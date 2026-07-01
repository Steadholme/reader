//! The SSO clipper surface: reading list, save form + bookmarklet landing, clip create, reader,
//! archive, delete.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Magpie is internal-only). The owner of a
//! clip is ALWAYS those headers — never a client-supplied field. State-changing POSTs (`/clip`,
//! `/archive`, `/delete`) carry a double-submit CSRF token. Every stored string — title, site,
//! excerpt, content, URL — is REMOTE/untrusted and is HTML-escaped on render, so a clipped page
//! can never execute as HTML.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{
    DEFAULT_PAGE, MAX_NOTE_CHARS, MAX_PAGE, MAX_QUOTE_CHARS, MAX_TAGS_INPUT_CHARS, MAX_TITLE_CHARS,
    MAX_URL_CHARS,
};
use crate::error::AppError;
use crate::extract;
use crate::fetch::parse_http_url;
use crate::handlers::{bookmarklet_href, esc, fmt_ts, userbox, APP_CSS, SHIELD_SVG};
use crate::model::{normalize_tags, Clip, Cursor, Filter, Highlight};
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random clip id (62-symbol alphabet => ~48 bits at 8 chars; the
/// `ON CONFLICT` insert retries on the astronomically rare collision).
const CLIP_ID_LEN: usize = 8;

/// Length of the short random highlight id (same alphabet/collision handling as the clip id).
const HIGHLIGHT_ID_LEN: usize = 12;

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const SAVE_HTML: &str = include_str!("../../templates/save.html");
const READER_HTML: &str = include_str!("../../templates/reader.html");
const SEARCH_HTML: &str = include_str!("../../templates/search.html");
const HIGHLIGHTS_HTML: &str = include_str!("../../templates/highlights.html");

// ---------------------------------------------------------------------------
// GET / — reading list
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub filter: String,
    /// Optional tag filter: `/?tag=rust` shows the owner's non-archived clips carrying that tag.
    #[serde(default)]
    pub tag: String,
}

/// `GET /` — render the reading list for the selected filter (or `?tag=`), the save form, and the
/// bookmarklet.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();

    // `?tag=` is a distinct view over the active list; otherwise the All/Unread/Archived filter.
    let tag = q.tag.trim();
    let (filter, tag_view, clips) = if !tag.is_empty() {
        let clips = state
            .store
            .list_by_tag(&who.subject, tag)
            .await
            .unwrap_or_default();
        (Filter::All, Some(tag.to_string()), clips)
    } else {
        let filter = Filter::parse(&q.filter);
        let clips = state
            .store
            .list(&who.subject, filter)
            .await
            .unwrap_or_default();
        (filter, None, clips)
    };

    let html = render_index(&state, &who, &csrf, filter, tag_view.as_deref(), &clips);
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// GET /search?q= — full-text search over title + extracted text (keyset-paginated)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    /// Keyset cursor (`{saved_at}_{id}`) — the last result of the previous page.
    #[serde(default)]
    pub before: String,
    /// Page size, clamped to `[1, MAX_PAGE]`.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /search?q=<terms>` — case-insensitive substring search over the owner's clip titles and
/// extracted text, newest-first, keyset-paginated via `?before=`.
pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(sq): Query<SearchQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let query = sq.q.trim().to_string();
    let limit = sq.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let before = Cursor::parse(&sq.before);

    let results = if query.is_empty() {
        Vec::new()
    } else {
        state
            .store
            .search(&who.subject, &query, before.as_ref(), limit)
            .await
            .unwrap_or_default()
    };

    let html = render_search(&who, &csrf, &query, &results, limit);
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// GET /clip?u= — bookmarklet landing (SSO confirm page that POSTs to /clip)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SaveQuery {
    #[serde(default)]
    pub u: String,
}

/// `GET /clip?u=<url>` — the bookmarklet opens this as a top-level GET (so the SameSite=Lax SSO
/// cookie is carried). It renders a same-origin confirm page that POSTs to `/clip` with a real
/// CSRF token, auto-submitting for a one-click save.
pub async fn clip_form(
    State(_state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SaveQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    // Validate up-front so a junk bookmark shows the branded error page rather than auto-POSTing
    // garbage. Use the normalized URL as the canonical value.
    let parsed = parse_http_url(q.u.trim())?;
    let url = parsed.to_string();

    let csrf = auth::new_csrf_token();
    let html = SAVE_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Save", Some(&who.email)))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{URL_ATTR}}", &esc(&url))
        .replace("{{URL_TEXT}}", &esc(&url));
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /clip — fetch + extract + save
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub url: String,
    /// Optional comma-separated tags typed on the save form (normalized before storage).
    #[serde(default)]
    pub tags: String,
}

/// `POST /clip` — validate + fetch the URL, extract the readable text, and store the clip, then
/// 302 to `/`. Re-clipping a URL already saved by this owner is de-duplicated (no duplicate row).
pub async fn clip_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }

    let who = auth::identity(&headers);
    let url = form.url.trim().to_string();
    if url.is_empty() {
        return Err(AppError::BadRequest("Enter a web address to save.".to_string()));
    }
    if url.chars().count() > MAX_URL_CHARS {
        return Err(AppError::BadRequest("That web address is too long.".to_string()));
    }
    // Owner-supplied tags: bound the raw input, then normalize (lowercase / trim / dedupe / cap).
    let tags_raw: String = form.tags.chars().take(MAX_TAGS_INPUT_CHARS).collect();
    let tags = normalize_tags(&tags_raw);

    // Fetch the page over HTTPS (SSRF-guarded, redirect-checked, size/time-capped).
    let fetched = state.fetcher.fetch(&url).await?;

    // Extract readable PLAIN TEXT. HTML pages go through the readability heuristic; text/plain is
    // taken as-is; anything else is refused (we only save readable web pages).
    let ct = fetched.content_type.as_str();
    let extracted = if ct.is_empty()
        || ct.starts_with("text/html")
        || ct.starts_with("application/xhtml")
    {
        extract::extract(&fetched.body, &fetched.final_url)
    } else if ct.starts_with("text/") {
        extract::extract_plaintext(&fetched.body, &fetched.final_url)
    } else {
        return Err(AppError::BadGateway(format!(
            "Magpie only saves readable web pages (this link is {ct})."
        )));
    };

    let now = now_secs();

    // De-dup on the FINAL (post-redirect) URL: if the owner already saved it, just make sure it
    // is in the active list and return — never a duplicate clip.
    if let Some(existing) = state
        .store
        .find_by_owner_url(&who.subject, &fetched.final_url)
        .await?
    {
        if existing.archived {
            state
                .store
                .set_archived(&existing.id, &who.subject, false)
                .await?;
        }
        // Re-clipping with tags updates the existing clip's tags rather than making a duplicate.
        if tags.is_some() {
            state
                .store
                .set_tags(&existing.id, &who.subject, tags)
                .await?;
        }
        return Ok(redirect_found("/"));
    }

    let mut clip = Clip {
        id: String::new(),
        owner_sub: who.subject.clone(),
        url: fetched.final_url.clone(),
        title: clamp_chars(&extracted.title, MAX_TITLE_CHARS),
        excerpt: extracted.excerpt,
        content_text: extracted.content_text,
        site: extracted.site,
        saved_at: now,
        read: false,
        archived: false,
        tags,
    };

    // Allocate a unique id: generate, try to insert, retry on the rare collision.
    let mut created = false;
    for _ in 0..6 {
        clip.id = random_alnum(CLIP_ID_LEN);
        if state.store.create(&clip).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique clip id".to_string(),
        ));
    }

    tracing::info!(id = clip.id, owner = who.subject, url = clip.url, "clip saved");
    Ok(redirect_found("/"))
}

// ---------------------------------------------------------------------------
// GET /r/{id} — reader view (marks read)
// ---------------------------------------------------------------------------

/// `GET /r/{id}` — render the clean reader view of the saved text and mark the clip read. A clip
/// is private to its owner; a non-owner (or missing id) gets a 404 (no existence leak).
pub async fn reader(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);

    let clip = match state.store.get(&id).await? {
        Some(c) if c.owner_sub == who.subject => c,
        _ => return Err(AppError::NotFound("No clip exists at that link.".to_string())),
    };

    // Marking read is the intended side effect of opening the reader (idempotent).
    let _ = state.store.mark_read(&id, &who.subject).await?;

    // The clip's own highlights, shown in a margin beside the article.
    let highlights = state
        .store
        .list_highlights(&who.subject, &id)
        .await
        .unwrap_or_default();

    let csrf = auth::new_csrf_token();
    let html = render_reader(&clip, &who, &csrf, &highlights);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /archive/{id} — toggle archived
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ActionForm {
    #[serde(default)]
    pub csrf_token: String,
    /// The reading-list filter to return to (so the action keeps the user in the same view).
    #[serde(default)]
    pub filter: String,
}

/// `POST /archive/{id}` — CSRF-checked, ownership-scoped toggle of the archived flag, then 302
/// back to the originating list view.
pub async fn archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    let clip = match state.store.get(&id).await? {
        Some(c) if c.owner_sub == who.subject => c,
        Some(_) => {
            return Err(AppError::Forbidden(
                "You can only manage your own clips.".to_string(),
            ))
        }
        None => return Err(AppError::NotFound("No clip exists at that link.".to_string())),
    };

    state
        .store
        .set_archived(&id, &who.subject, !clip.archived)
        .await?;
    Ok(redirect_found(&back_to(&form.filter)))
}

// ---------------------------------------------------------------------------
// POST /delete/{id} — delete your own clip
// ---------------------------------------------------------------------------

/// `POST /delete/{id}` — CSRF-checked, ownership-scoped delete, then 302 back to the list.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    if state.store.delete(&id, &who.subject).await? {
        tracing::info!(id, owner = who.subject, "clip deleted");
        return Ok(redirect_found(&back_to(&form.filter)));
    }
    // Nothing deleted: distinguish "not yours" from "does not exist" for a precise message.
    match state.store.get(&id).await? {
        Some(_) => Err(AppError::Forbidden(
            "You can only delete your own clips.".to_string(),
        )),
        None => Err(AppError::NotFound("No clip exists at that link.".to_string())),
    }
}

// ---------------------------------------------------------------------------
// POST /tags/{id} — edit the tags on your own clip
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TagsForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub tags: String,
}

/// `POST /tags/{id}` — CSRF-checked, ownership-scoped edit of a clip's tags, then 302 back to the
/// reader. The submitted string is normalized; an empty result clears the tags.
pub async fn edit_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<TagsForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    // Ownership check up-front so a non-owner gets 403/404 (never a silent no-op).
    match state.store.get(&id).await? {
        Some(c) if c.owner_sub == who.subject => {}
        Some(_) => {
            return Err(AppError::Forbidden(
                "You can only manage your own clips.".to_string(),
            ))
        }
        None => return Err(AppError::NotFound("No clip exists at that link.".to_string())),
    }

    let tags_raw: String = form.tags.chars().take(MAX_TAGS_INPUT_CHARS).collect();
    state
        .store
        .set_tags(&id, &who.subject, normalize_tags(&tags_raw))
        .await?;
    tracing::info!(id, owner = who.subject, "clip tags updated");
    Ok(redirect_found(&format!("/r/{id}")))
}

// ---------------------------------------------------------------------------
// POST /r/{id}/highlight — add a highlight (+ optional note) to your own clip
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HighlightForm {
    #[serde(default)]
    pub csrf_token: String,
    /// The passage being highlighted (copied from the article text).
    #[serde(default)]
    pub quote: String,
    /// An optional inline note attached to the highlight.
    #[serde(default)]
    pub note: String,
}

/// `POST /r/{id}/highlight` — CSRF-checked, ownership-scoped: add a highlight (a quote plus an
/// optional note) to a clip, then 302 back to the reader. Re-highlighting the SAME passage is
/// idempotent — it updates that highlight's note instead of inserting a duplicate.
pub async fn add_highlight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(clip_id): Path<String>,
    Form(form): Form<HighlightForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    // The clip must exist and be owned before we attach anything to it.
    match state.store.get(&clip_id).await? {
        Some(c) if c.owner_sub == who.subject => {}
        Some(_) => {
            return Err(AppError::Forbidden(
                "You can only highlight your own clips.".to_string(),
            ))
        }
        None => return Err(AppError::NotFound("No clip exists at that link.".to_string())),
    }

    let quote = clamp_chars(form.quote.trim(), MAX_QUOTE_CHARS);
    if quote.is_empty() {
        return Err(AppError::BadRequest(
            "Select some text to highlight.".to_string(),
        ));
    }
    let note = clamp_opt(form.note.trim(), MAX_NOTE_CHARS);

    // Idempotent on (owner, clip, quote): re-highlighting the same passage updates its note.
    if let Some(existing) = state
        .store
        .find_highlight_by_quote(&who.subject, &clip_id, &quote)
        .await?
    {
        state
            .store
            .set_highlight_note(&existing.id, &who.subject, note)
            .await?;
        tracing::info!(id = existing.id, owner = who.subject, clip = clip_id, "highlight note updated");
        return Ok(redirect_found(&format!("/r/{clip_id}")));
    }

    let mut highlight = Highlight {
        id: String::new(),
        clip_id: clip_id.clone(),
        owner_sub: who.subject.clone(),
        quote,
        note,
        created_at: now_secs(),
    };
    let mut created = false;
    for _ in 0..6 {
        highlight.id = random_alnum(HIGHLIGHT_ID_LEN);
        if state.store.add_highlight(&highlight).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique highlight id".to_string(),
        ));
    }
    tracing::info!(id = highlight.id, owner = who.subject, clip = clip_id, "highlight added");
    Ok(redirect_found(&format!("/r/{clip_id}")))
}

// ---------------------------------------------------------------------------
// POST /highlight/{hid}/delete — delete one of your own highlights
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HighlightDeleteForm {
    #[serde(default)]
    pub csrf_token: String,
    /// Where to return: `"list"` -> the "my highlights" page; anything else -> the clip reader.
    #[serde(default)]
    pub from: String,
}

/// `POST /highlight/{hid}/delete` — CSRF-checked, ownership-scoped delete of a single highlight,
/// then 302 back to the reader (or the aggregate page when `from=list`).
pub async fn delete_highlight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hid): Path<String>,
    Form(form): Form<HighlightDeleteForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    // Look up first so we can both enforce ownership and know which reader to return to.
    let highlight = match state.store.get_highlight(&hid).await? {
        Some(h) if h.owner_sub == who.subject => h,
        Some(_) => {
            return Err(AppError::Forbidden(
                "You can only delete your own highlights.".to_string(),
            ))
        }
        None => {
            return Err(AppError::NotFound(
                "No highlight exists at that link.".to_string(),
            ))
        }
    };

    state.store.delete_highlight(&hid, &who.subject).await?;
    tracing::info!(id = hid, owner = who.subject, "highlight deleted");

    let back = if form.from == "list" {
        "/highlights".to_string()
    } else {
        format!("/r/{}", highlight.clip_id)
    };
    Ok(redirect_found(&back))
}

// ---------------------------------------------------------------------------
// GET /highlights — the owner's highlights across every clip (aggregate page)
// ---------------------------------------------------------------------------

/// `GET /highlights` — every highlight the owner has made, newest-first, grouped by clip with the
/// clip title linking back to its reader.
pub async fn highlights(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();

    let items = state
        .store
        .list_all_highlights(&who.subject)
        .await
        .unwrap_or_default();

    let html = render_highlights_page(&state, &who, &csrf, &items).await;
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Truncate to at most `max` chars on a char boundary.
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

/// Truncate `s` to at most `max` chars, returning `None` when the (trimmed) result is empty — the
/// canonical "cleared" note value that maps to a NULL column.
fn clamp_opt(s: &str, max: usize) -> Option<String> {
    let clamped = clamp_chars(s, max);
    let trimmed = clamped.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Canonical list path for a (possibly junk) filter token.
fn back_to(filter: &str) -> String {
    format!("/?filter={}", Filter::parse(filter).as_str())
}

/// Wrap rendered HTML in a response that also (re)sets the CSRF cookie.
fn html_with_csrf(status: StatusCode, html: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

/// A `302 Found` redirect to `location` (the spec'd create/mutate response code).
fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

fn render_index(
    state: &AppState,
    who: &Identity,
    csrf: &str,
    filter: Filter,
    tag_view: Option<&str>,
    clips: &[Clip],
) -> String {
    // In a `?tag=` view the tabs are replaced by a "Tagged" banner with a clear-filter link.
    let tabs = match tag_view {
        Some(tag) => format!(
            "<div class=\"tag-banner\">Tagged <span class=\"tag-chip tag-chip--active\">{}</span>\
             <a class=\"tab\" href=\"/\">Clear</a></div>",
            esc(tag),
        ),
        None => render_tabs(filter),
    };
    INDEX_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Reading list", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace(
            "{{BOOKMARKLET_HREF}}",
            &esc(&bookmarklet_href(&state.config.public_base_url)),
        )
        .replace("{{TABS}}", &tabs)
        .replace("{{LIST}}", &render_list(clips, csrf, filter, tag_view))
}

/// The All / Unread / Archived filter tabs.
fn render_tabs(active: Filter) -> String {
    [(Filter::All, "All"), (Filter::Unread, "Unread"), (Filter::Archived, "Archived")]
        .iter()
        .map(|(f, label)| {
            let cls = if *f == active { "tab tab--active" } else { "tab" };
            format!(
                "<a class=\"{cls}\" href=\"/?filter={f}\">{label}</a>",
                f = f.as_str(),
                label = label,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// The reading-list items (already filtered/ordered by the store).
fn render_list(clips: &[Clip], csrf: &str, filter: Filter, tag_view: Option<&str>) -> String {
    if clips.is_empty() {
        let owned;
        let msg = match tag_view {
            Some(tag) => {
                owned = format!("No clips tagged \u{201c}{tag}\u{201d}.");
                owned.as_str()
            }
            None => match filter {
                Filter::All => "Your reading list is empty. Save a link to get started.",
                Filter::Unread => "Nothing unread — you're all caught up.",
                Filter::Archived => "No archived clips yet.",
            },
        };
        return format!("<li class=\"clip-item clip-item--empty\">{}</li>", esc(msg));
    }
    clips
        .iter()
        .map(|c| render_clip_item(c, csrf, filter))
        .collect::<Vec<_>>()
        .join("")
}

/// Render a clip's tags as small chips linking to their `/?tag=` view. Empty when the clip has
/// none. Each tag token is URL-encoded in the href and HTML-escaped in the label.
fn render_tag_chips(tags: &Option<String>) -> String {
    let Some(s) = tags else { return String::new() };
    let chips: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            format!(
                "<a class=\"tag-chip\" href=\"/?tag={href}\">{label}</a>",
                href = url_encode(t),
                label = esc(t),
            )
        })
        .collect();
    if chips.is_empty() {
        return String::new();
    }
    format!("<div class=\"clip-tags\">{}</div>", chips.join(""))
}

/// Minimal percent-encoding for a query-string value (RFC 3986 unreserved kept verbatim).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn render_clip_item(c: &Clip, csrf: &str, filter: Filter) -> String {
    let title = display_title(c);
    let status = if c.read {
        "<span class=\"badge badge--read\">Read</span>"
    } else {
        "<span class=\"badge badge--unread\">Unread</span>"
    };
    let site = if c.site.trim().is_empty() {
        String::new()
    } else {
        format!("<span class=\"clip-site\">{}</span>", esc(&c.site))
    };
    let excerpt = if c.excerpt.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"clip-excerpt\">{}</p>", esc(&c.excerpt))
    };
    let tags = render_tag_chips(&c.tags);
    let archive_label = if c.archived { "Unarchive" } else { "Archive" };

    format!(
        "<li class=\"clip-item\">\
           <div class=\"clip-main\">\
             <a class=\"clip-title\" href=\"/r/{id}\">{title}</a>\
             <div class=\"clip-meta\">{status}{site}<span class=\"clip-time\">Saved {saved}</span></div>\
             {excerpt}\
             {tags}\
           </div>\
           <div class=\"clip-actions\">\
             <a class=\"btn btn-ghost btn-sm\" href=\"{url_attr}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">Source</a>\
             <form class=\"inline-form\" method=\"post\" action=\"/archive/{id}\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"filter\" value=\"{filter}\">\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{archive_label}</button>\
             </form>\
             <form class=\"inline-form\" method=\"post\" action=\"/delete/{id}\" \
                   onsubmit=\"return confirm('Delete this clip? This cannot be undone.');\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"filter\" value=\"{filter}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
             </form>\
           </div>\
         </li>",
        id = esc(&c.id),
        title = esc(&title),
        status = status,
        site = site,
        saved = esc(&fmt_ts(c.saved_at)),
        excerpt = excerpt,
        tags = tags,
        url_attr = esc(&c.url),
        csrf = esc(csrf),
        filter = filter.as_str(),
        archive_label = archive_label,
    )
}

fn render_reader(clip: &Clip, who: &Identity, csrf: &str, highlights: &[Highlight]) -> String {
    let title = display_title(clip);
    let site = if clip.site.trim().is_empty() {
        "Saved page".to_string()
    } else {
        clip.site.clone()
    };
    let read_state = if clip.read { "Read" } else { "Unread" };
    let meta = format!("{site} · Saved {saved} · {read_state}", saved = fmt_ts(clip.saved_at));

    let archive_label = if clip.archived { "Unarchive" } else { "Archive" };
    let archive_form = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/archive/{id}\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{label}</button>\
         </form>",
        id = esc(&clip.id),
        csrf = esc(csrf),
        label = archive_label,
    );
    let delete_form = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/delete/{id}\" \
               onsubmit=\"return confirm('Delete this clip? This cannot be undone.');\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
         </form>",
        id = esc(&clip.id),
        csrf = esc(csrf),
    );

    READER_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Reader", Some(&who.email)))
        .replace("{{TITLE}}", &esc(&title))
        .replace("{{META}}", &esc(&meta))
        .replace("{{URL_ATTR}}", &esc(&clip.url))
        .replace("{{URL_TEXT}}", &esc(&clip.url))
        .replace("{{ARCHIVE}}", &archive_form)
        .replace("{{DELETE}}", &delete_form)
        .replace("{{TAGS}}", &render_tags_editor(clip, csrf))
        .replace("{{CONTENT}}", &render_content(&clip.content_text))
        .replace("{{HIGHLIGHTS}}", &render_highlights_margin(clip, csrf, highlights))
}

/// The reader's highlights margin: the add-a-highlight form (quote + optional note) followed by
/// the clip's existing highlights, each with a delete button. All stored text is escaped.
fn render_highlights_margin(clip: &Clip, csrf: &str, highlights: &[Highlight]) -> String {
    let add_form = format!(
        "<form class=\"highlight-form\" method=\"post\" action=\"/r/{id}/highlight\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <label class=\"field\">\
             <span class=\"field-label\">Highlight a passage</span>\
             <textarea class=\"highlight-quote\" name=\"quote\" rows=\"3\" \
                       placeholder=\"Paste or type the passage to highlight\" required></textarea>\
           </label>\
           <label class=\"field\">\
             <span class=\"field-label\">Note <span class=\"field-hint\">(optional)</span></span>\
             <textarea class=\"highlight-note\" name=\"note\" rows=\"2\" \
                       placeholder=\"Add a thought…\"></textarea>\
           </label>\
           <div class=\"actions\">\
             <button class=\"btn btn-primary btn-sm\" type=\"submit\">Add highlight</button>\
           </div>\
         </form>",
        id = esc(&clip.id),
        csrf = esc(csrf),
    );

    let list = if highlights.is_empty() {
        "<li class=\"highlight-item highlight-item--empty\">No highlights yet. Select a passage \
         above to save your first one.</li>"
            .to_string()
    } else {
        highlights
            .iter()
            .map(|h| render_highlight_item(h, csrf, false))
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        "<aside class=\"reader-margin\">\
           <div class=\"card\">\
             <div class=\"card__head\"><h2>Highlights</h2></div>\
             <div class=\"card__body\">{add_form}</div>\
           </div>\
           <ul class=\"highlight-list\">{list}</ul>\
         </aside>",
        add_form = add_form,
        list = list,
    )
}

/// One highlight: the quote (as a blockquote), the optional note, a creation timestamp, and a
/// CSRF-guarded delete form. `on_list` picks the return target for the delete redirect. On the
/// aggregate page the quote also links back to its clip's reader.
fn render_highlight_item(h: &Highlight, csrf: &str, on_list: bool) -> String {
    let note = match &h.note {
        Some(n) if !n.trim().is_empty() => {
            format!("<p class=\"highlight-note-text\">{}</p>", esc(n))
        }
        _ => String::new(),
    };
    let from = if on_list { "list" } else { "reader" };
    let open = if on_list {
        format!(
            "<a class=\"btn btn-ghost btn-sm\" href=\"/r/{id}\">Open</a>",
            id = esc(&h.clip_id),
        )
    } else {
        String::new()
    };
    format!(
        "<li class=\"highlight-item\">\
           <blockquote class=\"highlight-quote-text\">{quote}</blockquote>\
           {note}\
           <div class=\"highlight-meta\">\
             <span class=\"highlight-time\">Highlighted {when}</span>\
             {open}\
             <form class=\"inline-form\" method=\"post\" action=\"/highlight/{hid}/delete\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"from\" value=\"{from}\">\
               <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
             </form>\
           </div>\
         </li>",
        quote = esc(&h.quote),
        note = note,
        when = esc(&fmt_ts(h.created_at)),
        open = open,
        hid = esc(&h.id),
        csrf = esc(csrf),
        from = from,
    )
}

/// Render the "my highlights" aggregate page: every highlight grouped under its clip title.
async fn render_highlights_page(
    state: &AppState,
    who: &Identity,
    csrf: &str,
    items: &[Highlight],
) -> String {
    let body = if items.is_empty() {
        "<ul class=\"highlight-list\"><li class=\"highlight-item highlight-item--empty\">You have \
         not highlighted anything yet. Open a clip and highlight a passage to see it here.</li></ul>"
            .to_string()
    } else {
        // Group consecutive highlights by clip (the list is already ordered newest-first, so a
        // clip's highlights stay together). Fetch each clip's title once for the group header.
        let mut out = String::new();
        let mut current_clip: Option<String> = None;
        for h in items {
            if current_clip.as_deref() != Some(h.clip_id.as_str()) {
                if current_clip.is_some() {
                    out.push_str("</ul></section>");
                }
                let title = match state.store.get(&h.clip_id).await {
                    Ok(Some(c)) if c.owner_sub == who.subject => display_title(&c),
                    _ => "Saved clip".to_string(),
                };
                out.push_str(&format!(
                    "<section class=\"highlight-group\">\
                       <h2 class=\"highlight-group__title\">\
                         <a href=\"/r/{id}\">{title}</a>\
                       </h2><ul class=\"highlight-list\">",
                    id = esc(&h.clip_id),
                    title = esc(&title),
                ));
                current_clip = Some(h.clip_id.clone());
            }
            out.push_str(&render_highlight_item(h, csrf, true));
        }
        if current_clip.is_some() {
            out.push_str("</ul></section>");
        }
        out
    };

    HIGHLIGHTS_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Highlights", Some(&who.email)))
        .replace("{{BODY}}", &body)
}

/// The reader's tags row: the current tag chips plus an inline edit form (comma-separated). The
/// stored value is pre-filled so a save preserves what is not changed.
fn render_tags_editor(clip: &Clip, csrf: &str) -> String {
    let chips = render_tag_chips(&clip.tags);
    let current = clip.tags.as_deref().unwrap_or("");
    format!(
        "<div class=\"reader-tags\">\
           {chips}\
           <form class=\"tags-form\" method=\"post\" action=\"/tags/{id}\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <input class=\"tags-input\" type=\"text\" name=\"tags\" value=\"{value}\" \
                    placeholder=\"tags, comma, separated\" autocomplete=\"off\">\
             <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Save tags</button>\
           </form>\
         </div>",
        chips = chips,
        id = esc(&clip.id),
        csrf = esc(csrf),
        value = esc(current),
    )
}

/// Render the search results page: the query box, a result count, the matching clips, and a
/// keyset "Load more" link when the page came back full.
fn render_search(
    who: &Identity,
    csrf: &str,
    query: &str,
    results: &[Clip],
    limit: usize,
) -> String {
    let list = if query.is_empty() {
        "<li class=\"clip-item clip-item--empty\">Type a word or phrase to search your saved \
         clips.</li>"
            .to_string()
    } else if results.is_empty() {
        format!(
            "<li class=\"clip-item clip-item--empty\">No clips match \u{201c}{}\u{201d}.</li>",
            esc(query)
        )
    } else {
        results
            .iter()
            .map(|c| render_clip_item(c, csrf, Filter::All))
            .collect::<Vec<_>>()
            .join("")
    };

    // Keyset "next page": only when the page filled to `limit` (there may be more).
    let more = match results.last() {
        Some(last) if results.len() == limit => {
            let cur = Cursor {
                saved_at: last.saved_at,
                id: last.id.clone(),
            };
            format!(
                "<div class=\"search-more\"><a class=\"btn btn-ghost btn-sm\" \
                 href=\"/search?q={q}&before={before}\">Load more</a></div>",
                q = url_encode(query),
                before = url_encode(&cur.encode()),
            )
        }
        _ => String::new(),
    };

    SEARCH_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Search", Some(&who.email)))
        .replace("{{QUERY_ATTR}}", &esc(query))
        .replace("{{LIST}}", &list)
        .replace("{{MORE}}", &more)
}

/// Render the stored plain-text content as escaped paragraphs (one per source line). The remote
/// text is NEVER emitted as raw HTML — every line is escaped.
fn render_content(content_text: &str) -> String {
    let paragraphs: Vec<String> = content_text
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| format!("<p>{}</p>", esc(line)))
        .collect();
    if paragraphs.is_empty() {
        return "<p class=\"reader-empty\">No readable text could be extracted from this page. \
                Open the original to read it.</p>"
            .to_string();
    }
    paragraphs.join("")
}

/// The display title, falling back to "Untitled" when the page exposed none.
fn display_title(c: &Clip) -> String {
    if c.title.trim().is_empty() {
        "Untitled".to_string()
    } else {
        c.title.clone()
    }
}
