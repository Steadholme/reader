//! The SSO clipper surface: reading list, save form + bookmarklet landing, clip create, reader,
//! archive, delete.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Magpie is internal-only). The owner of a
//! clip is ALWAYS those headers — never a client-supplied field. State-changing POSTs (`/clip`,
//! `/archive`, `/delete`) carry a double-submit CSRF token. Every stored string — title, site,
//! excerpt, content, URL — is REMOTE/untrusted and is HTML-escaped on render, so a clipped page
//! can never execute as HTML.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{
    DEFAULT_PAGE, EXPORT_LIMIT, LIST_LIMIT, MAX_BULK_IDS, MAX_NOTE_CHARS, MAX_PAGE,
    MAX_QUOTE_CHARS, MAX_SAVED_VIEWS, MAX_TAGS_INPUT_CHARS, MAX_TITLE_CHARS, MAX_URL_CHARS,
    MAX_VIEW_NAME_CHARS,
};
use crate::error::AppError;
use crate::extract;
use crate::fetch::parse_http_url;
use crate::handlers::{
    bookmarklet_href, esc, fmt_ts, md_escape, page_shell, Shell, ICON_BOOKMARK, ICON_GLOBE,
    ICON_HIGHLIGHT, ICON_SEARCH,
};
use crate::model::{
    clamp_progress, normalize_tags, reading_minutes, word_count, Clip, ClipQuery, Cursor, Filter,
    Highlight, SavedView,
};
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random clip id (62-symbol alphabet => ~48 bits at 8 chars; the
/// `ON CONFLICT` insert retries on the astronomically rare collision).
const CLIP_ID_LEN: usize = 8;

/// Length of the short random highlight id (same alphabet/collision handling as the clip id).
const HIGHLIGHT_ID_LEN: usize = 12;

/// Length of the short random saved-view id.
const VIEW_ID_LEN: usize = 8;

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const SAVE_HTML: &str = include_str!("../../templates/save.html");
const READER_HTML: &str = include_str!("../../templates/reader.html");
const SEARCH_HTML: &str = include_str!("../../templates/search.html");
const HIGHLIGHTS_HTML: &str = include_str!("../../templates/highlights.html");
const SITES_HTML: &str = include_str!("../../templates/sites.html");

// ---------------------------------------------------------------------------
// GET / — reading list
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    /// Canonical view selector: `all` / `unread` / `favorites` / `archive`.
    #[serde(default)]
    pub view: String,
    /// Legacy alias for `view` (kept so old links/bookmarks keep working).
    #[serde(default)]
    pub filter: String,
    /// Optional tag filter: `/?tag=rust` shows the owner's non-archived clips carrying that tag.
    #[serde(default)]
    pub tag: String,
    /// Optional site/source filter, case-insensitive exact match.
    #[serde(default)]
    pub site: String,
    /// One-shot status marker used after failed saved-view actions.
    #[serde(default)]
    pub view_error: String,
}

impl IndexQuery {
    /// The effective view token, preferring `?view=` and falling back to the legacy `?filter=`.
    fn view_token(&self) -> &str {
        if !self.view.trim().is_empty() {
            self.view.trim()
        } else {
            self.filter.trim()
        }
    }
}

/// `GET /` — render the reading list for the selected view (or `?tag=`), the save form, the bulk
/// toolbar, and the bookmarklet.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();

    let clip_query = ClipQuery::from_params(q.view_token(), &q.tag, &q.site);
    let clips = state
        .store
        .list_filtered(&who.subject, &clip_query, LIST_LIMIT)
        .await
        .unwrap_or_default();
    let views = state
        .store
        .list_saved_views(&who.subject)
        .await
        .unwrap_or_default();

    let auto_archive = state
        .store
        .get_auto_archive(&who.subject)
        .await
        .unwrap_or(false);

    let html = render_index(
        &state,
        &who,
        &csrf,
        &clip_query,
        &views,
        q.view_error.trim(),
        &clips,
        auto_archive,
    );
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
    let main = SAVE_HTML
        .replace("{{ICON_BOOKMARK}}", ICON_BOOKMARK)
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{URL_ATTR}}", &esc(&url))
        .replace("{{URL_TEXT}}", &esc(&url))
        .replace("{{URL_HOST}}", &esc(parsed.host_str().unwrap_or("")));
    let html = page_shell(
        "Save to HOLDFAST · Magpie",
        "Save",
        Some(&who.email),
        None,
        false,
        Shell::Narrow,
        &main,
        None,
    );
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
        return Err(AppError::BadRequest(
            "Enter a web address to save.".to_string(),
        ));
    }
    if url.chars().count() > MAX_URL_CHARS {
        return Err(AppError::BadRequest(
            "That web address is too long.".to_string(),
        ));
    }
    // Owner-supplied tags: bound the raw input, then normalize (lowercase / trim / dedupe / cap).
    let tags_raw: String = form.tags.chars().take(MAX_TAGS_INPUT_CHARS).collect();
    let tags = normalize_tags(&tags_raw);

    // Fetch the page over HTTPS (SSRF-guarded, redirect-checked, size/time-capped).
    let fetched = state.fetcher.fetch(&url).await?;

    // Extract readable PLAIN TEXT. HTML pages go through the readability heuristic; text/plain is
    // taken as-is; anything else is refused (we only save readable web pages).
    let ct = fetched.content_type.as_str();
    let extracted =
        if ct.is_empty() || ct.starts_with("text/html") || ct.starts_with("application/xhtml") {
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
        favorite: false,
        progress: 0,
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

    tracing::info!(
        id = clip.id,
        owner = who.subject,
        url = clip.url,
        "clip saved"
    );
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

    let mut clip = match state.store.get(&id).await? {
        Some(c) if c.owner_sub == who.subject => c,
        _ => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
    };

    // Marking read is the intended side effect of opening the reader (idempotent).
    let _ = state.store.mark_read(&id, &who.subject).await?;
    clip.read = true;

    // Optional per-owner preference: opening the reader auto-archives the clip (default off).
    if !clip.archived
        && state
            .store
            .get_auto_archive(&who.subject)
            .await
            .unwrap_or(false)
    {
        let _ = state.store.set_archived(&id, &who.subject, true).await?;
        clip.archived = true;
        tracing::info!(id, owner = who.subject, "clip auto-archived on read");
    }

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
    /// The reading-list view to return to (so the action keeps the user in the same tab).
    #[serde(default)]
    pub view: String,
    /// Legacy alias for `view` (older forms/links posted `filter`).
    #[serde(default)]
    pub filter: String,
}

impl ActionForm {
    /// The effective return-view token, preferring `view` and falling back to legacy `filter`.
    fn view_token(&self) -> &str {
        if !self.view.trim().is_empty() {
            self.view.trim()
        } else {
            self.filter.trim()
        }
    }
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
    };

    state
        .store
        .set_archived(&id, &who.subject, !clip.archived)
        .await?;
    tracing::info!(
        id,
        owner = who.subject,
        archived = !clip.archived,
        "clip archive toggled"
    );
    Ok(redirect_found(&back_to(form.view_token())))
}

// ---------------------------------------------------------------------------
// POST /favorite/{id} — toggle the favorite (starred) flag
// ---------------------------------------------------------------------------

/// `POST /favorite/{id}` — CSRF-checked, ownership-scoped toggle of the favorite flag, then 302
/// back to the originating list view.
pub async fn favorite(
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
    };

    state
        .store
        .set_favorite(&id, &who.subject, !clip.favorite)
        .await?;
    tracing::info!(
        id,
        owner = who.subject,
        favorite = !clip.favorite,
        "clip favorite toggled"
    );
    Ok(redirect_found(&back_to(form.view_token())))
}

// ---------------------------------------------------------------------------
// JSON siblings of /archive/{id} and /favorite/{id} (progressive enhancement)
// ---------------------------------------------------------------------------
//
// Same double-submit CSRF, same ownership scope and audit log as the form routes above, but they
// return small JSON and DO NOT redirect. The form routes are untouched, so a no-JS browser still
// works; JS uses these for optimistic, no-reload archive/favorite toggles.

/// `POST /api/archive/{id}` — CSRF-checked, owner-scoped archive toggle. Returns
/// `{ "ok": true, "id": …, "archived": <new state> }`.
pub async fn api_archive(
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
    };
    let now = !clip.archived;
    state.store.set_archived(&id, &who.subject, now).await?;
    tracing::info!(
        id,
        owner = who.subject,
        archived = now,
        "clip archive toggled (json)"
    );
    Ok(axum::Json(serde_json::json!({ "ok": true, "id": id, "archived": now })).into_response())
}

/// `POST /api/favorite/{id}` — CSRF-checked, owner-scoped favorite toggle. Returns
/// `{ "ok": true, "id": …, "favorite": <new state> }`.
pub async fn api_favorite(
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
    };
    let now = !clip.favorite;
    state.store.set_favorite(&id, &who.subject, now).await?;
    tracing::info!(
        id,
        owner = who.subject,
        favorite = now,
        "clip favorite toggled (json)"
    );
    Ok(axum::Json(serde_json::json!({ "ok": true, "id": id, "favorite": now })).into_response())
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
        return Ok(redirect_found(&back_to(form.view_token())));
    }
    // Nothing deleted: distinguish "not yours" from "does not exist" for a precise message.
    match state.store.get(&id).await? {
        Some(_) => Err(AppError::Forbidden(
            "You can only delete your own clips.".to_string(),
        )),
        None => Err(AppError::NotFound(
            "No clip exists at that link.".to_string(),
        )),
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
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
        None => {
            return Err(AppError::NotFound(
                "No clip exists at that link.".to_string(),
            ))
        }
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
        tracing::info!(
            id = existing.id,
            owner = who.subject,
            clip = clip_id,
            "highlight note updated"
        );
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
    tracing::info!(
        id = highlight.id,
        owner = who.subject,
        clip = clip_id,
        "highlight added"
    );
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
// POST /views — save/delete filtered views
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SaveViewForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub view: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub site: String,
}

/// `POST /views` — CSRF-checked, owner-scoped creation of a named filtered view. The query is
/// rebuilt from structured fields and canonicalized before storage.
pub async fn save_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SaveViewForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let query = ClipQuery::from_params(&form.view, &form.tag, &form.site);
    let canonical = query.to_query_string();
    if query.is_default() {
        return Err(AppError::BadRequest(
            "Choose a filter before saving a view.".to_string(),
        ));
    }

    let name = clamp_chars(form.name.trim(), MAX_VIEW_NAME_CHARS);
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "Name this view before saving.".to_string(),
        ));
    }

    let views = state.store.list_saved_views(&who.subject).await?;
    if views.len() >= MAX_SAVED_VIEWS {
        return Ok(redirect_found(&view_limit_location(&canonical)));
    }

    let mut view = SavedView {
        id: String::new(),
        owner_sub: who.subject.clone(),
        name,
        query: canonical.clone(),
        created_at: now_secs(),
    };
    let mut created = false;
    for _ in 0..6 {
        view.id = random_alnum(VIEW_ID_LEN);
        if state.store.create_saved_view(&view).await? {
            created = true;
            break;
        }
    }
    if !created {
        return Err(AppError::Internal(
            "could not allocate a unique saved view id".to_string(),
        ));
    }
    tracing::info!(id = view.id, owner = who.subject, "saved view created");
    Ok(redirect_found(&index_location(&canonical)))
}

#[derive(Debug, Deserialize)]
pub struct DeleteViewForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /views/{id}/delete` — CSRF-checked, owner-scoped delete of a saved filtered view.
pub async fn delete_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<DeleteViewForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    if state.store.delete_saved_view(&id, &who.subject).await? {
        tracing::info!(id, owner = who.subject, "saved view deleted");
    }
    Ok(redirect_found("/"))
}

// ---------------------------------------------------------------------------
// GET /sites — source facet
// ---------------------------------------------------------------------------

/// `GET /sites` — aggregate the owner's saved clips by source/site and link each source into the
/// structured `?site=` filter.
pub async fn sites(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let clips = state
        .store
        .export_clips(&who.subject, EXPORT_LIMIT)
        .await
        .unwrap_or_default();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for clip in clips {
        let site = clip.site.trim();
        if site.is_empty() {
            continue;
        }
        *counts.entry(site.to_string()).or_insert(0) += 1;
    }
    let mut items: Vec<(String, usize)> = counts.into_iter().collect();
    items.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
            .then_with(|| a.0.cmp(&b.0))
    });
    let html = render_sites(&who, &items);
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// POST /bulk — act on many selected clips at once
// ---------------------------------------------------------------------------

/// `POST /bulk` — CSRF-checked, ownership-scoped batch action over the selected clip ids. The
/// body is `application/x-www-form-urlencoded` with a REPEATED `ids` field (one per checkbox),
/// which `serde_urlencoded` cannot decode into a `Vec`, so the body is parsed manually. Supported
/// actions: `archive`, `unarchive`, `favorite`, `unfavorite`, `delete`, `tag` (replaces tags with
/// the `tags` field). Every mutation is owner-scoped in the store, so a non-owned id is a no-op.
pub async fn bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let fields = parse_urlencoded(&body);
    let field = |key: &str| -> String {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    if !auth::verify_csrf(&headers, &field("csrf_token")) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    let action = field("action");
    let view_token = {
        let v = field("view");
        if v.trim().is_empty() {
            field("filter")
        } else {
            v
        }
    };

    // Collect the selected ids (deduplicated, bounded).
    let mut ids: Vec<String> = Vec::new();
    for (k, v) in &fields {
        if k == "ids" && !v.is_empty() && !ids.iter().any(|e| e == v) {
            ids.push(v.clone());
            if ids.len() >= MAX_BULK_IDS {
                break;
            }
        }
    }
    if ids.is_empty() {
        // Nothing selected — just return to the list rather than erroring.
        return Ok(redirect_found(&back_to(&view_token)));
    }

    // For the tag action, normalize the shared tag string once.
    let tags = if action == "tag" {
        let raw: String = field("tags").chars().take(MAX_TAGS_INPUT_CHARS).collect();
        Some(normalize_tags(&raw))
    } else {
        None
    };

    let mut changed = 0usize;
    for id in &ids {
        let ok = match action.as_str() {
            "archive" => state.store.set_archived(id, &who.subject, true).await?,
            "unarchive" => state.store.set_archived(id, &who.subject, false).await?,
            "favorite" => state.store.set_favorite(id, &who.subject, true).await?,
            "unfavorite" => state.store.set_favorite(id, &who.subject, false).await?,
            "delete" => state.store.delete(id, &who.subject).await?,
            "tag" => {
                state
                    .store
                    .set_tags(id, &who.subject, tags.clone().unwrap_or(None))
                    .await?
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "Unknown bulk action: {}",
                    other
                )))
            }
        };
        if ok {
            changed += 1;
        }
    }
    tracing::info!(
        owner = who.subject,
        action,
        selected = ids.len(),
        changed,
        "bulk action"
    );
    Ok(redirect_found(&back_to(&view_token)))
}

// ---------------------------------------------------------------------------
// GET /export — the owner's clips (+ highlights/notes) as Markdown or JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// `json` -> JSON; anything else (incl. `md` / `markdown` / missing) -> Markdown.
    #[serde(default)]
    pub format: String,
}

/// `GET /export?format=md|json` — a Readwise-style export of the owner's clips together with their
/// highlights and notes. Owner-scoped; served INERT (an `attachment` with `X-Content-Type-Options:
/// nosniff`) so a browser downloads it rather than rendering any embedded markup.
pub async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExportQuery>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);

    let clips = state.store.export_clips(&who.subject, EXPORT_LIMIT).await?;
    let highlights = state
        .store
        .export_highlights(&who.subject, EXPORT_LIMIT)
        .await?;

    let as_json = matches!(q.format.trim(), "json");
    let (body, content_type, filename) = if as_json {
        (
            export_json(&clips, &highlights),
            "application/json; charset=utf-8",
            "magpie-export.json",
        )
    } else {
        (
            export_markdown(&clips, &highlights),
            "text/markdown; charset=utf-8",
            "magpie-export.md",
        )
    };

    tracing::info!(
        owner = who.subject,
        json = as_json,
        clips = clips.len(),
        "export served"
    );
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /progress/{id} — persist reading progress (throttled AJAX from the reader)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ProgressForm {
    #[serde(default)]
    pub csrf_token: String,
    /// Raw client-reported percent; clamped to `[0, 100]` before storage.
    #[serde(default)]
    pub progress: i64,
}

/// `POST /progress/{id}` — CSRF-checked, ownership-scoped write of the reading-progress percent,
/// returning `204 No Content` (the reader posts this from JS, not a navigation). The value is
/// clamped to `[0, 100]`; a non-owned/missing id is a silent no-op (still 204) so the beacon never
/// surfaces a scary error mid-scroll.
pub async fn set_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ProgressForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let pct = clamp_progress(form.progress);
    let _ = state.store.set_progress(&id, &who.subject, pct).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// POST /settings — per-owner preferences (auto-archive on read)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    #[serde(default)]
    pub csrf_token: String,
    /// Present (any value) when the checkbox is ticked; absent when unticked.
    #[serde(default)]
    pub auto_archive: Option<String>,
    #[serde(default)]
    pub view: String,
}

/// `POST /settings` — CSRF-checked write of the owner's auto-archive-on-read preference, then 302
/// back to the reading list. An HTML checkbox only submits its field when ticked, so presence maps
/// to `true` and absence to `false`.
pub async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SettingsForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let on = form.auto_archive.is_some();
    state.store.set_auto_archive(&who.subject, on).await?;
    tracing::info!(owner = who.subject, auto_archive = on, "settings updated");
    Ok(redirect_found(&back_to(form.view.trim())))
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

/// Canonical list path for a (possibly junk) view token.
fn back_to(view: &str) -> String {
    format!("/?view={}", Filter::parse(view).as_str())
}

/// Parse an `application/x-www-form-urlencoded` body into ordered `(key, value)` pairs, preserving
/// REPEATED keys (needed for the bulk `ids` multi-select, which `serde_urlencoded` drops). `+` maps
/// to space and `%XX` is percent-decoded; malformed escapes are passed through literally.
fn parse_urlencoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (pct_decode(k), pct_decode(v)),
            None => (pct_decode(pair), String::new()),
        })
        .collect()
}

/// Percent-decode one form component (`+` -> space, `%XX` -> byte), lossily UTF-8 decoding the
/// result. A stray `%` not followed by two hex digits is kept verbatim.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                match (
                    bytes.get(i + 1).copied().and_then(hex_val),
                    bytes.get(i + 2).copied().and_then(hex_val),
                ) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of a single hex ASCII digit, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Build the JSON export of the owner's clips + highlights. Serialized via `serde_json`, which
/// escapes every string value, so remote/owner text can never break the document structure.
fn export_json(clips: &[Clip], highlights: &[Highlight]) -> String {
    use serde_json::{Map, Value};

    let items: Vec<Value> = clips
        .iter()
        .map(|c| {
            let hls: Vec<Value> = highlights
                .iter()
                .filter(|h| h.clip_id == c.id)
                .map(|h| {
                    let mut m = Map::new();
                    m.insert("quote".into(), Value::String(h.quote.clone()));
                    m.insert(
                        "note".into(),
                        match &h.note {
                            Some(n) => Value::String(n.clone()),
                            None => Value::Null,
                        },
                    );
                    m.insert("created_at".into(), Value::from(h.created_at));
                    Value::Object(m)
                })
                .collect();
            let mut m = Map::new();
            m.insert("id".into(), Value::String(c.id.clone()));
            m.insert("url".into(), Value::String(c.url.clone()));
            m.insert("title".into(), Value::String(c.title.clone()));
            m.insert("site".into(), Value::String(c.site.clone()));
            m.insert("excerpt".into(), Value::String(c.excerpt.clone()));
            m.insert("saved_at".into(), Value::from(c.saved_at));
            m.insert("read".into(), Value::Bool(c.read));
            m.insert("archived".into(), Value::Bool(c.archived));
            m.insert("favorite".into(), Value::Bool(c.favorite));
            m.insert("progress".into(), Value::from(c.progress));
            m.insert(
                "tags".into(),
                match &c.tags {
                    Some(t) => Value::String(t.clone()),
                    None => Value::Null,
                },
            );
            m.insert("highlights".into(), Value::Array(hls));
            Value::Object(m)
        })
        .collect();

    let mut root = Map::new();
    root.insert("version".into(), Value::from(1));
    root.insert("clips".into(), Value::Array(items));
    serde_json::to_string_pretty(&Value::Object(root)).unwrap_or_else(|_| "{}".to_string())
}

/// Build the Markdown export of the owner's clips + highlights. Every remote/owner string is run
/// through [`md_escape`], so no embedded HTML or Markdown control sequence survives — combined with
/// the `attachment`/`nosniff` response headers the file is inert wherever it is later opened.
fn export_markdown(clips: &[Clip], highlights: &[Highlight]) -> String {
    let mut out = String::from("# Magpie export\n\n");
    if clips.is_empty() {
        out.push_str("_No clips saved._\n");
        return out;
    }
    for c in clips {
        let title = if c.title.trim().is_empty() {
            "Untitled".to_string()
        } else {
            md_escape(&c.title)
        };
        out.push_str(&format!("## {title}\n\n"));
        // Plain escaped text (not a `<...>` autolink) so backslash-escaped chars render literally.
        out.push_str(&format!("- URL: {}\n", md_escape(&c.url)));
        if !c.site.trim().is_empty() {
            out.push_str(&format!("- Site: {}\n", md_escape(&c.site)));
        }
        out.push_str(&format!("- Saved: {}\n", fmt_ts(c.saved_at)));
        let status = if c.archived {
            "archived"
        } else if c.read {
            "read"
        } else {
            "unread"
        };
        out.push_str(&format!(
            "- Status: {status}{}\n",
            if c.favorite { " · favorite" } else { "" }
        ));
        if let Some(t) = &c.tags {
            out.push_str(&format!("- Tags: {}\n", md_escape(t)));
        }
        if !c.excerpt.trim().is_empty() {
            out.push_str(&format!("\n{}\n", md_escape(&c.excerpt)));
        }
        let hls: Vec<&Highlight> = highlights.iter().filter(|h| h.clip_id == c.id).collect();
        if !hls.is_empty() {
            out.push_str("\n### Highlights\n\n");
            for h in hls {
                out.push_str(&format!("> {}\n", md_escape(&h.quote)));
                if let Some(n) = &h.note {
                    if !n.trim().is_empty() {
                        out.push_str(&format!(">\n> Note: {}\n", md_escape(n)));
                    }
                }
                out.push('\n');
            }
        }
        out.push_str("\n---\n\n");
    }
    out
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

fn index_location(query: &str) -> String {
    if query.is_empty() {
        "/".to_string()
    } else {
        format!("/?{query}")
    }
}

fn view_limit_location(query: &str) -> String {
    if query.is_empty() {
        "/?view_error=limit".to_string()
    } else {
        format!("/?{query}&view_error=limit")
    }
}

#[allow(clippy::too_many_arguments)]
fn render_index(
    state: &AppState,
    who: &Identity,
    csrf: &str,
    query: &ClipQuery,
    views: &[SavedView],
    view_error: &str,
    clips: &[Clip],
    auto_archive: bool,
) -> String {
    // The return-view token used by the bulk/settings forms so an action keeps the current tab.
    let view = query.filter.as_str();
    let main = INDEX_HTML
        .replace("{{ICON_BOOKMARK}}", ICON_BOOKMARK)
        .replace("{{ICON_SEARCH}}", ICON_SEARCH)
        .replace(
            "{{VIEWS}}",
            &render_views_bar(views, query, csrf, view_error),
        )
        .replace("{{TOOLBAR}}", &render_toolbar(csrf, view, auto_archive))
        .replace("{{LIST}}", &render_list(clips, csrf, query));
    let rail = format!(
        "<section class=\"card mg-railsave\">\
          <div class=\"card__head\"><span class=\"mg-railsave__ico\" aria-hidden=\"true\">{icon}</span><h2>Save a link</h2></div>\
          <div class=\"card__body\">\
            <form method=\"post\" action=\"/clip\" class=\"save-form\">\
              <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
              <div class=\"field\">\
                <label for=\"url\">Page URL</label>\
                <input type=\"url\" id=\"url\" name=\"url\" inputmode=\"url\" autocomplete=\"off\"\
                       placeholder=\"https://example.com/article\" required>\
              </div>\
              <div class=\"field\">\
                <label for=\"tags\">Tags <span class=\"field-hint\">(optional, comma-separated)</span></label>\
                <input type=\"text\" id=\"tags\" name=\"tags\" autocomplete=\"off\"\
                       placeholder=\"rust, reading, later\">\
              </div>\
              <div class=\"actions\">\
                <button class=\"btn btn-primary\" type=\"submit\">Save to reading list</button>\
              </div>\
            </form>\
          </div>\
        </section>\
        <section class=\"card\">\
          <div class=\"card__head\"><h2>One-click bookmarklet</h2></div>\
          <div class=\"card__body\">\
            <p class=\"hint\">Drag this button to your bookmarks bar. Click it on any page to save it to HOLDFAST.</p>\
            <p class=\"bookmarklet-wrap\">\
              <a class=\"btn btn-secondary bookmarklet\" href=\"{bookmarklet}\"\
                 onclick=\"return false;\" draggable=\"true\">Save to HOLDFAST</a>\
            </p>\
            <p class=\"hint hint--muted\">It opens a small tab that saves the current page through your single sign-on session.</p>\
          </div>\
        </section>",
        icon = ICON_BOOKMARK,
        csrf = esc(csrf),
        bookmarklet = esc(&bookmarklet_href(&state.config.public_base_url)),
    );
    page_shell(
        "Reading list · Magpie · HOLDFAST",
        "Reading list",
        Some(&who.email),
        Some(query.filter.as_str()),
        true,
        Shell::Default,
        &main,
        Some(&rail),
    )
}

fn render_views_bar(
    views: &[SavedView],
    query: &ClipQuery,
    csrf: &str,
    view_error: &str,
) -> String {
    let mut saved = String::new();

    if view_error == "limit" {
        saved.push_str(
            "<div class=\"saved-views__notice\" role=\"status\">Saved view limit reached. Delete a view before adding another.</div>",
        );
    }

    if !views.is_empty() {
        saved.push_str("<div class=\"saved-views__pins\">");
        for view in views {
            let href = index_location(&view.query);
            saved.push_str(&format!(
                "<span class=\"saved-view\"><a class=\"saved-view__link\" href=\"{href}\">{name}</a>\
                   <form class=\"saved-view__del\" method=\"post\" action=\"/views/{id}/delete\">\
                     <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                     <button class=\"saved-view__remove\" type=\"submit\" aria-label=\"Delete view {name}\">×</button>\
                   </form></span>",
                href = esc(&href),
                name = esc(&view.name),
                id = esc(&view.id),
                csrf = esc(csrf),
            ));
        }
        saved.push_str("</div>");
    }

    let mut chips = String::new();
    if let Some(tag) = &query.tag {
        let mut without = query.clone();
        without.tag = None;
        let href = index_location(&without.to_query_string());
        chips.push_str(&format!(
            "<span class=\"filter-chip filter-chip--tag\">tag: {tag}<a class=\"filter-chip__remove\" href=\"{href}\" aria-label=\"Clear tag\">×</a></span>",
            tag = esc(tag),
            href = esc(&href),
        ));
    }
    if let Some(site) = &query.site {
        let mut without = query.clone();
        without.site = None;
        let href = index_location(&without.to_query_string());
        chips.push_str(&format!(
            "<span class=\"filter-chip filter-chip--site\">site: {site}<a class=\"filter-chip__remove\" href=\"{href}\" aria-label=\"Clear site\">×</a></span>",
            site = esc(site),
            href = esc(&href),
        ));
    }
    let chips = if chips.is_empty() {
        String::new()
    } else {
        format!("<div class=\"filter-chips\">{chips}</div>")
    };

    let form = if !query.is_default() {
        format!(
            "<form class=\"save-view-form\" method=\"post\" action=\"/views\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"view\" value=\"{view}\">\
               <input type=\"hidden\" name=\"tag\" value=\"{tag}\">\
               <input type=\"hidden\" name=\"site\" value=\"{site}\">\
               <input class=\"save-view-form__name\" type=\"text\" name=\"name\" maxlength=\"60\" placeholder=\"Name this view\" autocomplete=\"off\" required>\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Save view</button>\
             </form>",
            csrf = esc(csrf),
            view = esc(query.filter.as_str()),
            tag = esc(query.tag.as_deref().unwrap_or("")),
            site = esc(query.site.as_deref().unwrap_or("")),
        )
    } else {
        String::new()
    };

    let saved_block = format!("<div class=\"saved-views\" data-saved-views>{saved}</div>");
    if saved.is_empty() && chips.is_empty() && form.is_empty() {
        saved_block
    } else {
        format!("<div class=\"mg-refinebar\">{saved_block}{chips}{form}</div>")
    }
}

/// The list toolbar: the bulk-action form (whose submit buttons act on the checkboxes rendered in
/// each clip via `form="bulkForm"`), the export links, and the per-owner auto-archive toggle. The
/// bulk form is a SIBLING of the per-item forms (checkboxes are associated by id, never nested).
fn render_toolbar(csrf: &str, view: &str, auto_archive: bool) -> String {
    let checked = if auto_archive { " checked" } else { "" };
    format!(
        "<div class=\"listbar\">\
           <form id=\"bulkForm\" class=\"bulkbar\" method=\"post\" action=\"/bulk\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <input type=\"hidden\" name=\"view\" value=\"{view}\">\
             <label class=\"check\"><input type=\"checkbox\" id=\"bulkSelectAll\" aria-label=\"Select all clips\"><span>Select all</span></label>\
             <span class=\"bulkbar__count\" data-bulk-count hidden aria-live=\"polite\">0 selected</span>\
             <input class=\"bulk-tags\" type=\"text\" name=\"tags\" placeholder=\"tags for Tag\" autocomplete=\"off\">\
             <button class=\"btn btn-ghost btn-sm\" type=\"submit\" name=\"action\" value=\"archive\" data-bulk-btn>Archive</button>\
             <button class=\"btn btn-ghost btn-sm\" type=\"submit\" name=\"action\" value=\"favorite\" data-bulk-btn>Favorite</button>\
             <button class=\"btn btn-ghost btn-sm\" type=\"submit\" name=\"action\" value=\"tag\" data-bulk-btn>Tag</button>\
             <button class=\"btn btn-danger btn-sm\" type=\"submit\" name=\"action\" value=\"delete\" data-bulk-btn \
                     onclick=\"return confirm('Delete the selected clips? This cannot be undone.');\">Delete</button>\
           </form>\
           <div class=\"listbar__right\">\
             <form class=\"settingbar\" method=\"post\" action=\"/settings\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input type=\"hidden\" name=\"view\" value=\"{view}\">\
               <label class=\"switch\"><input type=\"checkbox\" name=\"auto_archive\"{checked}><i></i></label>\
               <span class=\"settingbar__label\">Archive on open</span>\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Save</button>\
             </form>\
             <a class=\"btn btn-ghost btn-sm\" href=\"/export?format=md\">Export .md</a>\
             <a class=\"btn btn-ghost btn-sm\" href=\"/export?format=json\">Export .json</a>\
           </div>\
         </div>\
         <div class=\"toast-host\" data-toast-host aria-live=\"polite\" aria-atomic=\"true\"></div>\
         <script>\
         (function(){{\
           function cookie(n){{var p=document.cookie?document.cookie.split('; '):[];for(var i=0;i<p.length;i++){{var e=p[i].indexOf('=');if(e>-1&&p[i].slice(0,e)===n)return decodeURIComponent(p[i].slice(e+1));}}return '';}}\
           var CSRF=cookie('__Host-csrf');\
           var host=document.querySelector('[data-toast-host]');\
           function toast(msg,ok,href){{if(!host)return;var t=document.createElement('div');t.className='toast '+(ok?'toast--ok':'toast--err');t.setAttribute('role','status');t.textContent=msg;if(href){{var a=document.createElement('a');a.className='mg-toast-read';a.href=href;a.textContent='Read now';t.appendChild(a);}}host.appendChild(t);setTimeout(function(){{t.classList.add('is-leaving');setTimeout(function(){{if(t.parentNode)t.parentNode.removeChild(t);}},200);}},2400);}}\
           function post(url,params){{var b=Object.keys(params).map(function(k){{return encodeURIComponent(k)+'='+encodeURIComponent(params[k]);}}).join('&');return fetch(url,{{method:'POST',credentials:'same-origin',headers:{{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'}},body:b}}).then(function(r){{if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}});}}\
           /* --- bulk-select count + sticky + disabled state --- */\
           var all=document.getElementById('bulkSelectAll');\
           var bar=document.getElementById('bulkForm');\
           var badge=document.querySelector('[data-bulk-count]');\
           var actions=Array.prototype.slice.call(document.querySelectorAll('[data-bulk-btn]'));\
           function checks(){{return Array.prototype.slice.call(document.querySelectorAll('input.bulk-check'));}}\
           function sync(){{var cs=checks();var n=cs.filter(function(c){{return c.checked;}}).length;\
             if(badge){{badge.textContent=n+' selected';if(n>0)badge.removeAttribute('hidden');else badge.setAttribute('hidden','');}}\
             if(bar){{if(n>0)bar.classList.add('is-active');else bar.classList.remove('is-active');}}\
             actions.forEach(function(b){{b.disabled=(n===0);}});\
             if(all){{all.checked=(n>0&&n===cs.length);all.indeterminate=(n>0&&n<cs.length);}}}}\
           if(all)all.addEventListener('change',function(){{checks().forEach(function(c){{c.checked=all.checked;}});sync();}});\
           document.addEventListener('change',function(e){{if(e.target&&e.target.classList&&e.target.classList.contains('bulk-check'))sync();}});\
           sync();\
           /* --- display density + bookmarklet save bridge --- */\
           var list=document.querySelector('.clip-list');var densityBtns=Array.prototype.slice.call(document.querySelectorAll('[data-density]'));\
           function setDensity(mode){{mode=mode==='compact'?'compact':'comfortable';try{{localStorage.setItem('magpie:density',mode);}}catch(e){{}}if(list)list.classList.toggle('clip-list--compact',mode==='compact');densityBtns.forEach(function(b){{b.classList.toggle('is-active',b.getAttribute('data-density')===mode);}});}}\
           var savedMode='comfortable';try{{savedMode=localStorage.getItem('magpie:density')||'comfortable';}}catch(e){{}}setDensity(savedMode);\
           densityBtns.forEach(function(b){{b.addEventListener('click',function(){{setDensity(b.getAttribute('data-density'));}});}});\
           try{{var saved=sessionStorage.getItem('magpie:saved');if(saved){{sessionStorage.removeItem('magpie:saved');var first=document.querySelector('.clip-title');toast('Saved to your reading list',true,first?first.getAttribute('href'):null);}}}}catch(e){{}}\
           /* --- optimistic per-card favorite / archive --- */\
           var VIEW='{view}';\
           function idOf(form){{var m=(form.getAttribute('action')||'').match(/\\/(favorite|archive)\\/([^\\/]+)$/);return m?decodeURIComponent(m[2]):'';}}\
           function toggleFav(form){{var id=idOf(form);if(!id||!CSRF){{form.submit();return;}}var li=form.closest('.clip-item');var btn=form.querySelector('button');if(btn)btn.setAttribute('aria-busy','true');\
             post('/api/favorite/'+encodeURIComponent(id),{{csrf_token:CSRF,view:VIEW}}).then(function(d){{var on=!!d.favorite;if(btn){{btn.removeAttribute('aria-busy');btn.textContent=on?'Unfavorite':'Favorite';}}\
               if(li){{var meta=li.querySelector('[data-clip-meta]');var ex=li.querySelector('.badge--fav');if(on&&!ex&&meta){{var b=document.createElement('span');b.className='badge badge--fav';b.textContent='\\u2605 Favorite';var read=meta.querySelector('.badge--read,.badge--unread');if(read&&read.nextSibling)meta.insertBefore(b,read.nextSibling);else meta.insertBefore(b,meta.firstChild);}}else if(!on&&ex){{ex.parentNode.removeChild(ex);}}}}\
               if(!on&&VIEW==='favorites'&&li){{li.classList.add('is-removing');setTimeout(function(){{if(li.parentNode)li.parentNode.removeChild(li);}},160);}}\
               toast(on?'Added to favorites':'Removed from favorites',true);}}).catch(function(){{if(btn)btn.removeAttribute('aria-busy');toast('Could not update — try again',false);}});}}\
           function toggleArchive(form){{var id=idOf(form);if(!id||!CSRF){{form.submit();return;}}var li=form.closest('.clip-item');var btn=form.querySelector('button');if(btn)btn.setAttribute('aria-busy','true');\
             post('/api/archive/'+encodeURIComponent(id),{{csrf_token:CSRF,view:VIEW}}).then(function(d){{var on=!!d.archived;if(btn){{btn.removeAttribute('aria-busy');btn.textContent=on?'Unarchive':'Archive';}}\
               var gone=(on&&(VIEW==='all'||VIEW==='unread'||VIEW==='favorites'))||(!on&&VIEW==='archive');\
               if(gone&&li){{li.classList.add('is-removing');setTimeout(function(){{if(li.parentNode)li.parentNode.removeChild(li);}},160);}}\
               toast(on?'Archived':'Moved to reading list',true);}}).catch(function(){{if(btn)btn.removeAttribute('aria-busy');toast('Could not update — try again',false);}});}}\
           document.addEventListener('submit',function(e){{var f=e.target;if(!(f instanceof HTMLFormElement)||!CSRF)return;\
             if(f.hasAttribute('data-fav-form')){{e.preventDefault();toggleFav(f);}}\
             else if(f.hasAttribute('data-archive-form')){{e.preventDefault();toggleArchive(f);}}}});\
         }})();\
         </script>",
        csrf = esc(csrf),
        view = esc(view),
        checked = checked,
    )
}

/// The reading-list items (already filtered/ordered by the store).
fn render_list(clips: &[Clip], csrf: &str, query: &ClipQuery) -> String {
    if clips.is_empty() {
        let owned;
        let msg = match (query.tag.as_deref(), query.site.as_deref()) {
            (Some(tag), None) => {
                owned = format!("No clips tagged \u{201c}{tag}\u{201d}.");
                owned.as_str()
            }
            (None, Some(site)) => {
                owned = format!("No clips from \u{201c}{site}\u{201d}.");
                owned.as_str()
            }
            (Some(_), Some(_)) => "No clips match these filters.",
            (None, None) => match query.filter {
                Filter::All => "Your reading list is empty. Save a link to get started.",
                Filter::Unread => "Nothing unread — you're all caught up.",
                Filter::Favorites => "No favorites yet. Star a clip to keep it here.",
                Filter::Archived => "No archived clips yet.",
            },
        };
        return format!(
            "<li class=\"clip-item clip-item--empty\"><div class=\"empty\"><div class=\"empty__ico\" aria-hidden=\"true\">{icon}</div><h3>{headline}</h3><p>{msg}</p></div></li>",
            icon = ICON_BOOKMARK,
            headline = match query.filter {
                Filter::All => "No clips",
                Filter::Unread => "All caught up",
                Filter::Favorites => "No favorites",
                Filter::Archived => "No archived clips",
            },
            msg = esc(msg),
        );
    }
    clips
        .iter()
        .map(|c| render_clip_item(c, csrf, query.filter, true, None))
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

/// Render one reading-list card. `selectable` adds the bulk-select checkbox (associated to
/// `#bulkForm` by id) — the reading list sets it, the search results do not.
fn render_clip_item(
    c: &Clip,
    csrf: &str,
    filter: Filter,
    selectable: bool,
    snippet: Option<&str>,
) -> String {
    let title = display_title(c);
    let initial = thumb_initial(c);
    let tone = thumb_tone(&c.site);
    let read_cls = if c.read { " clip-item--read" } else { "" };
    let read_badge = if c.read {
        "<span class=\"badge badge--read\">Read</span>"
    } else {
        "<span class=\"badge badge--unread\">Unread</span>"
    };
    let fav_badge = if c.favorite {
        "<span class=\"badge badge--fav\">★ Favorite</span>"
    } else {
        ""
    };
    let site = if c.site.trim().is_empty() {
        String::new()
    } else {
        format!("<span class=\"clip-site\">{}</span>", esc(&c.site))
    };
    // Reading-time estimate from the extracted text (word count / WPM).
    let minutes = reading_minutes(word_count(&c.content_text));
    let readtime = if minutes > 0 {
        format!("<span class=\"clip-readtime\">{minutes} min read</span>")
    } else {
        String::new()
    };
    let excerpt = if c.excerpt.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"clip-excerpt\">{}</p>", esc(&c.excerpt))
    };
    let excerpt = match snippet {
        Some(s) => format!("<p class=\"mg-snippet\">{s}</p>"),
        None => excerpt,
    };
    let tags = render_tag_chips(&c.tags);
    let progress = render_card_progress(c);
    let archive_label = if c.archived { "Unarchive" } else { "Archive" };
    let fav_label = if c.favorite { "Unfavorite" } else { "Favorite" };
    let view = filter.as_str();
    // The bulk-select checkbox is a control associated with `#bulkForm` by the `form` attribute, so
    // it is NEVER nested inside the per-item forms below.
    let check = if selectable {
        format!(
            "<label class=\"clip-select\"><input class=\"bulk-check\" type=\"checkbox\" \
             form=\"bulkForm\" name=\"ids\" value=\"{id}\"></label>",
            id = esc(&c.id),
        )
    } else {
        String::new()
    };

    format!(
        "<li class=\"clip-item{read_cls}\" data-clip-id=\"{id}\">\
           {check}\
           <span class=\"mg-thumb mg-thumb--t{tone}\" aria-hidden=\"true\">{initial}</span>\
           <div class=\"clip-main\">\
             <a class=\"clip-title\" href=\"/r/{id}\">{title}</a>\
             <div class=\"clip-meta\" data-clip-meta>{read_badge}{fav_badge}{site}{readtime}<span class=\"clip-time\">Saved {saved}</span></div>\
             {excerpt}\
             {progress}\
             {tags}\
             <div class=\"clip-actions\">\
               <a class=\"btn btn-ghost btn-sm\" href=\"{url_attr}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">Source</a>\
               <form class=\"inline-form\" method=\"post\" action=\"/favorite/{id}\" data-fav-form>\
                 <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"view\" value=\"{view}\">\
                 <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{fav_label}</button>\
               </form>\
               <form class=\"inline-form\" method=\"post\" action=\"/archive/{id}\" data-archive-form>\
                 <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"view\" value=\"{view}\">\
                 <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{archive_label}</button>\
               </form>\
               <form class=\"inline-form\" method=\"post\" action=\"/delete/{id}\" \
                     onsubmit=\"return confirm('Delete this clip? This cannot be undone.');\">\
                 <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"view\" value=\"{view}\">\
                 <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
               </form>\
             </div>\
           </div>\
         </li>",
        check = check,
        read_cls = read_cls,
        id = esc(&c.id),
        tone = tone,
        initial = esc(&initial),
        title = esc(&title),
        read_badge = read_badge,
        fav_badge = fav_badge,
        site = site,
        readtime = readtime,
        saved = esc(&fmt_ts(c.saved_at)),
        excerpt = excerpt,
        progress = progress,
        tags = tags,
        url_attr = esc(&c.url),
        csrf = esc(csrf),
        view = esc(view),
        fav_label = fav_label,
        archive_label = archive_label,
    )
}

/// Render the card's reading-progress affordance: a slim meter plus a "Continue reading" link when
/// the owner is partway through (progress in `1..=99`); nothing at 0 and a "Finished" pill at 100.
fn render_card_progress(c: &Clip) -> String {
    let p = c.progress.clamp(0, 100);
    if p <= 0 {
        String::new()
    } else if p >= 100 {
        "<div class=\"clip-progress\"><span class=\"badge badge--read\">Finished</span></div>"
            .to_string()
    } else {
        format!(
            "<div class=\"clip-progress\">\
               <span class=\"progress-meter\"><span class=\"progress-meter__fill\" style=\"width:{p}%\"></span></span>\
               <a class=\"progress-continue\" href=\"/r/{id}\">Continue reading · {p}%</a>\
             </div>",
            p = p,
            id = esc(&c.id),
        )
    }
}

fn render_reader(clip: &Clip, who: &Identity, csrf: &str, highlights: &[Highlight]) -> String {
    let title = display_title(clip);
    let site = if clip.site.trim().is_empty() {
        "<span>Saved page</span>".to_string()
    } else {
        format!(
            "<a class=\"mg-read__site\" href=\"/?site={href}\">{site}</a>",
            href = url_encode(&clip.site),
            site = esc(&clip.site),
        )
    };
    let read_state = if clip.read {
        "<span class=\"pill pill--muted\">Read</span>"
    } else {
        "<span class=\"pill mg-pill--unread\">Unread</span>"
    };
    let minutes = reading_minutes(word_count(&clip.content_text));
    let readtime = if minutes > 0 {
        format!("<span class=\"mg-read__readtime\">{minutes} min read</span>")
    } else {
        String::new()
    };
    let meta = format!(
        "{site}<span>Saved {saved}</span>{readtime}{read_state}",
        saved = fmt_ts(clip.saved_at),
    );

    let favorite_label = if clip.favorite {
        "Unfavorite"
    } else {
        "Favorite"
    };
    let favorite_form = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/favorite/{id}\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{label}</button>\
         </form>",
        id = esc(&clip.id),
        csrf = esc(csrf),
        label = favorite_label,
    );
    let archive_label = if clip.archived {
        "Unarchive"
    } else {
        "Archive"
    };
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

    let main = READER_HTML
        .replace("{{TITLE}}", &esc(&title))
        .replace("{{META}}", &meta)
        .replace("{{URL_ATTR}}", &esc(&clip.url))
        .replace("{{URL_TEXT}}", &esc(&clip.url))
        .replace("{{FAVORITE}}", &favorite_form)
        .replace("{{ARCHIVE}}", &archive_form)
        .replace("{{DELETE}}", &delete_form)
        .replace("{{TAGS}}", &render_tags_editor(clip, csrf))
        .replace("{{CONTENT}}", &render_content(&clip.content_text))
        .replace(
            "{{HIGHLIGHTS}}",
            &render_highlights_margin(clip, csrf, highlights),
        )
        .replace("{{PROGRESS}}", &render_reader_progress(clip, csrf));
    page_shell(
        &format!("{title} · Magpie · HOLDFAST"),
        "Reader",
        Some(&who.email),
        None,
        false,
        Shell::Reader,
        &main,
        None,
    )
}

/// The reader's progress plumbing: a data holder carrying the clip id, CSRF token and saved percent
/// plus the throttled scroll reporter. On load it best-effort resumes near the saved fraction; while
/// scrolling it POSTs the clamped percent to `/progress/{id}`. All dynamic values are escaped into
/// `data-*` attributes; the script reads them via `dataset`, never interpolating remote text.
fn render_reader_progress(clip: &Clip, csrf: &str) -> String {
    format!(
        "<div id=\"readerProgress\" data-id=\"{id}\" data-csrf=\"{csrf}\" data-progress=\"{progress}\"></div>\
         <script>\
         (function(){{\
           var el=document.getElementById('readerProgress');if(!el)return;\
           var id=el.dataset.id,csrf=el.dataset.csrf;\
           var fill=document.getElementById('readerBarFill');var paintPending=false;\
           var start=parseInt(el.dataset.progress,10)||0;var last=start;var pending=false;\
           function docPct(){{var h=document.documentElement.scrollHeight-window.innerHeight;\
             if(h<=0)return 0;var p=Math.round(window.scrollY/h*100);return p<0?0:(p>100?100:p);}}\
           function paint(){{paintPending=false;if(fill)fill.style.width=docPct()+'%';}}\
           function schedulePaint(){{if(paintPending)return;paintPending=true;requestAnimationFrame(paint);}}\
           if(fill)fill.style.width=start+'%';\
           if(start>0&&start<100){{window.addEventListener('load',function(){{\
             var h=document.documentElement.scrollHeight-window.innerHeight;\
             if(h>0)window.scrollTo(0,Math.round(h*start/100));schedulePaint();}});}}\
           function report(){{pending=false;var p=docPct();if(Math.abs(p-last)<2)return;last=p;\
             var body='csrf_token='+encodeURIComponent(csrf)+'&progress='+p;\
             fetch('/progress/'+encodeURIComponent(id),{{method:'POST',credentials:'same-origin',\
               keepalive:true,headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:body}});}}\
           window.addEventListener('scroll',function(){{if(pending)return;pending=true;\
             setTimeout(report,1500);}},{{passive:true}});\
           window.addEventListener('scroll',schedulePaint,{{passive:true}});\
           window.addEventListener('load',schedulePaint);\
         }})();\
         </script>",
        id = esc(&clip.id),
        csrf = esc(csrf),
        progress = clip.progress.clamp(0, 100),
    )
}

/// The reader's highlights margin: the add-a-highlight form (quote + optional note) followed by
/// the clip's existing highlights, each with a delete button. All stored text is escaped.
fn render_highlights_margin(clip: &Clip, csrf: &str, highlights: &[Highlight]) -> String {
    let add_form = format!(
        "<form class=\"highlight-form mg-hlform\" method=\"post\" action=\"/r/{id}/highlight\">\
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
           <span class=\"mg-hlform__hint\">Passage captured — add a note?</span>\
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
        "<aside class=\"reader-margin mg-rail\">\
           <div class=\"card\">\
             <div class=\"card__head\"><h2>Highlights</h2><span class=\"pill\">{count}</span></div>\
             <div class=\"card__body\">{add_form}</div>\
           </div>\
           <ul class=\"highlight-list\">{list}</ul>\
           <button class=\"mg-hlchip\" type=\"button\" hidden>Highlight</button>\
           <script>\
           (function(){{\
             var prose=document.querySelector('.mg-prose');var form=document.querySelector('.mg-hlform');var chip=document.querySelector('.mg-hlchip');\
             if(!prose||!form||!chip)return;var quote=form.querySelector('textarea[name=quote]');var note=form.querySelector('textarea[name=note]');\
             function inProse(sel){{return sel&&sel.anchorNode&&sel.focusNode&&prose.contains(sel.anchorNode)&&prose.contains(sel.focusNode);}}\
             function arm(){{var sel=window.getSelection();if(!inProse(sel)||sel.isCollapsed)return;var text=sel.toString().trim();if(!text)return;\
               if(quote)quote.value=text;form.classList.add('is-armed');var r=sel.getRangeAt(0).getBoundingClientRect();\
               chip.style.left=Math.max(12,Math.min(window.innerWidth-120,r.left))+'px';chip.style.top=Math.max(12,r.top+window.scrollY-42)+'px';chip.hidden=false;}}\
             document.addEventListener('mouseup',function(){{setTimeout(arm,0);}});\
             document.addEventListener('selectionchange',function(){{if(window.getSelection()&&window.getSelection().isCollapsed)chip.hidden=true;}});\
             chip.addEventListener('click',function(){{form.scrollIntoView({{block:'center'}});if(note)note.focus();chip.hidden=true;}});\
           }})();\
           </script>\
         </aside>",
        add_form = add_form,
        list = list,
        count = highlights.len(),
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
             <div class=\"mg-hl__actions\">\
               {open}\
               <form class=\"inline-form\" method=\"post\" action=\"/highlight/{hid}/delete\">\
                 <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"from\" value=\"{from}\">\
                 <button class=\"btn btn-subtle btn-sm mg-hl__del\" type=\"submit\">Delete</button>\
               </form>\
             </div>\
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
        format!(
            "<div class=\"empty\"><div class=\"empty__ico\" aria-hidden=\"true\">{icon}</div><h2>Your commonplace book is empty</h2><p>You have not highlighted anything yet. Open a clip and highlight a passage to see it here.</p><a class=\"btn btn-primary\" href=\"/\">Reading list</a></div>",
            icon = ICON_HIGHLIGHT,
        )
            .to_string()
    } else {
        let mut groups: Vec<(String, Vec<&Highlight>)> = Vec::new();
        for h in items {
            if let Some((_, bucket)) = groups.iter_mut().find(|(id, _)| id == &h.clip_id) {
                bucket.push(h);
            } else {
                groups.push((h.clip_id.clone(), vec![h]));
            }
        }
        let mut out = String::new();
        out.push_str(&format!(
            "<p class=\"mg-hl-stats\"><b>{}</b> highlights across <b>{}</b> articles</p>",
            items.len(),
            groups.len(),
        ));
        for (clip_id, hs) in groups {
            let (title, tile, meta, tile_cls) = match state.store.get(&clip_id).await {
                Ok(Some(c)) if c.owner_sub == who.subject => {
                    let title = display_title(&c);
                    let saved = fmt_ts(c.saved_at);
                    let date = saved.get(..10).unwrap_or(&saved);
                    let minutes = reading_minutes(word_count(&c.content_text));
                    let readtime = if minutes > 0 {
                        format!(" · {minutes} min read")
                    } else {
                        String::new()
                    };
                    let site = if c.site.trim().is_empty() {
                        "Saved page".to_string()
                    } else {
                        c.site.clone()
                    };
                    (
                        title,
                        thumb_initial(&c),
                        format!(
                            "{} · Saved {} · {} {}{}",
                            esc(&site),
                            esc(date),
                            hs.len(),
                            if hs.len() == 1 {
                                "highlight"
                            } else {
                                "highlights"
                            },
                            readtime,
                        ),
                        "",
                    )
                }
                _ => (
                    "Saved clip".to_string(),
                    "S".to_string(),
                    format!(
                        "{} {}",
                        hs.len(),
                        if hs.len() == 1 {
                            "highlight"
                        } else {
                            "highlights"
                        },
                    ),
                    " mg-hlgroup__tile--fallback",
                ),
            };
            out.push_str(&format!(
                "<section class=\"highlight-group\">\
                   <header class=\"mg-hlgroup__head\">\
                     <span class=\"mg-hlgroup__tile{tile_cls}\" aria-hidden=\"true\">{tile}</span>\
                     <div class=\"mg-hlgroup__id\">\
                       <h2 class=\"highlight-group__title\"><a href=\"/r/{id}\">{title}</a></h2>\
                       <p class=\"mg-hlgroup__meta\">{meta}</p>\
                     </div>\
                     <a class=\"btn btn-ghost btn-sm mg-hlgroup__open\" href=\"/r/{id}\">Open reader</a>\
                   </header>\
                   <ul class=\"highlight-list\">",
                id = esc(&clip_id),
                title = esc(&title),
                tile = esc(&tile),
                tile_cls = tile_cls,
                meta = meta,
            ));
            for h in hs {
                out.push_str(&render_highlight_item(h, csrf, true));
            }
            out.push_str("</ul></section>");
        }
        out
    };

    let main = HIGHLIGHTS_HTML
        .replace("{{ICON_HIGHLIGHT}}", ICON_HIGHLIGHT)
        .replace("{{BODY}}", &body);
    page_shell(
        "Highlights · Magpie · HOLDFAST",
        "Highlights",
        Some(&who.email),
        Some("highlights"),
        false,
        Shell::Solo,
        &main,
        None,
    )
}

fn render_sites(who: &Identity, sites: &[(String, usize)]) -> String {
    let body = if sites.is_empty() {
        "<ul class=\"source-list\"><li class=\"source-row source-row--empty\">No sources yet.</li></ul>"
            .to_string()
    } else {
        let max = sites
            .iter()
            .map(|(_, count)| *count)
            .max()
            .unwrap_or(1)
            .max(1);
        let rows = sites
            .iter()
            .map(|(site, count)| {
                let initial = site
                    .chars()
                    .find(|c| !c.is_whitespace())
                    .map(|c| c.to_uppercase().to_string())
                    .unwrap_or_else(|| "S".to_string());
                let pct = (*count * 100) / max;
                format!(
                    "<li class=\"source-row\"><span class=\"mg-source__glyph\" aria-hidden=\"true\">{initial}</span><a class=\"source-row__link\" href=\"/?site={href}\">{site}</a><span class=\"source-row__count badge\">{count}</span><span class=\"mg-source__bar\" aria-hidden=\"true\"><i style=\"--w:{pct}%\"></i></span></li>",
                    initial = esc(&initial),
                    href = url_encode(site),
                    site = esc(site),
                    count = count,
                    pct = pct,
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!("<ul class=\"source-list\">{rows}</ul>")
    };

    let main = SITES_HTML
        .replace("{{ICON_GLOBE}}", ICON_GLOBE)
        .replace("{{BODY}}", &body);
    page_shell(
        "Sources · Magpie · HOLDFAST",
        "Sources",
        Some(&who.email),
        Some("sites"),
        false,
        Shell::Solo,
        &main,
        None,
    )
}

/// The reader's tags row: the current tag chips plus an inline edit form (comma-separated). The
/// stored value is pre-filled so a save preserves what is not changed.
fn render_tags_editor(clip: &Clip, csrf: &str) -> String {
    let chips = render_tag_chips(&clip.tags);
    let current = clip.tags.as_deref().unwrap_or("");
    format!(
        "<details class=\"mg-tagedit\"><summary>Edit tags</summary>\
           <div class=\"reader-tags\">\
             {chips}\
             <form class=\"tags-form\" method=\"post\" action=\"/tags/{id}\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <input class=\"tags-input\" type=\"text\" name=\"tags\" value=\"{value}\" \
                      placeholder=\"tags, comma, separated\" autocomplete=\"off\">\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Save tags</button>\
             </form>\
           </div>\
         </details>",
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
        format!(
            "<li class=\"clip-item clip-item--empty\"><div class=\"empty\"><div class=\"empty__ico\" aria-hidden=\"true\">{icon}</div><h3>Search your library</h3><p>Type a word or phrase to search your saved clips.</p></div></li>",
            icon = ICON_SEARCH,
        )
    } else if results.is_empty() {
        format!(
            "<li class=\"clip-item clip-item--empty\"><div class=\"empty\"><div class=\"empty__ico\" aria-hidden=\"true\">{icon}</div><h3>No results</h3><p>No clips match \u{201c}{query}\u{201d}.</p></div></li>",
            icon = ICON_SEARCH,
            query = esc(query),
        )
    } else {
        results
            .iter()
            .map(|c| {
                let snippet = matched_snippet(c, query);
                render_clip_item(c, csrf, Filter::All, false, snippet.as_deref())
            })
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

    let result_meta = if query.is_empty() {
        String::new()
    } else if results.len() == limit && !results.is_empty() {
        format!(
            "<p class=\"mg-resultmeta\">Showing first <b>{}</b> — load more below</p>",
            results.len()
        )
    } else {
        format!(
            "<p class=\"mg-resultmeta\"><b>{}</b> results for \u{201c}{}\u{201d}</p>",
            results.len(),
            esc(query),
        )
    };

    let main = SEARCH_HTML
        .replace("{{ICON_SEARCH}}", ICON_SEARCH)
        .replace("{{QUERY_ATTR}}", &esc(query))
        .replace("{{RESULTMETA}}", &result_meta)
        .replace("{{LIST}}", &list)
        .replace("{{MORE}}", &more);
    page_shell(
        "Search · Magpie · HOLDFAST",
        "Search",
        Some(&who.email),
        None,
        false,
        Shell::Solo,
        &main,
        None,
    )
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

fn matched_snippet(c: &Clip, query: &str) -> Option<String> {
    let q = query.trim();
    if q.is_empty() {
        return None;
    }
    snippet_window(&c.title, q).or_else(|| snippet_window(&c.content_text, q))
}

fn snippet_window(text: &str, query: &str) -> Option<String> {
    if text.trim().is_empty() {
        return None;
    }
    let lower = text.to_lowercase();
    let needle = query.to_lowercase();
    let pos = lower.find(&needle)?;
    let mut hit_start = pos.min(text.len());
    while hit_start > 0 && !text.is_char_boundary(hit_start) {
        hit_start -= 1;
    }
    let mut hit_end = (pos + query.len()).min(text.len());
    while hit_end < text.len() && !text.is_char_boundary(hit_end) {
        hit_end += 1;
    }
    if hit_end < hit_start {
        return None;
    }
    let prefix_start = text[..hit_start]
        .char_indices()
        .rev()
        .nth(119)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let suffix_end = text[hit_end..]
        .char_indices()
        .nth(120)
        .map(|(idx, _)| hit_end + idx)
        .unwrap_or(text.len());
    let prefix_ellipsis = if prefix_start > 0 { "…" } else { "" };
    let suffix_ellipsis = if suffix_end < text.len() { "…" } else { "" };
    Some(format!(
        "{}{}<mark class=\"mg-hit\">{}</mark>{}{}",
        prefix_ellipsis,
        esc(&text[prefix_start..hit_start]),
        esc(&text[hit_start..hit_end]),
        esc(&text[hit_end..suffix_end]),
        suffix_ellipsis,
    ))
}

/// The display title, falling back to "Untitled" when the page exposed none.
fn display_title(c: &Clip) -> String {
    if c.title.trim().is_empty() {
        "Untitled".to_string()
    } else {
        c.title.clone()
    }
}

fn thumb_initial(c: &Clip) -> String {
    c.site
        .trim()
        .chars()
        .find(|ch| !ch.is_whitespace())
        .or_else(|| c.title.trim().chars().find(|ch| !ch.is_whitespace()))
        .map(|ch| ch.to_uppercase().to_string())
        .unwrap_or_else(|| "•".to_string())
}

fn thumb_tone(site: &str) -> usize {
    site.bytes().map(usize::from).sum::<usize>() % 5 + 1
}
