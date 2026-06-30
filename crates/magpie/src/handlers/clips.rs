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
use crate::config::{MAX_URL_CHARS, MAX_TITLE_CHARS};
use crate::error::AppError;
use crate::extract;
use crate::fetch::parse_http_url;
use crate::handlers::{bookmarklet_href, esc, fmt_ts, userbox, APP_CSS, SHIELD_SVG};
use crate::model::{Clip, Filter};
use crate::{now_secs, random_alnum, AppState};

/// Length of the short random clip id (62-symbol alphabet => ~48 bits at 8 chars; the
/// `ON CONFLICT` insert retries on the astronomically rare collision).
const CLIP_ID_LEN: usize = 8;

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const SAVE_HTML: &str = include_str!("../../templates/save.html");
const READER_HTML: &str = include_str!("../../templates/reader.html");

// ---------------------------------------------------------------------------
// GET / — reading list
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    #[serde(default)]
    pub filter: String,
}

/// `GET /` — render the reading list for the selected filter, the save form, and the bookmarklet.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IndexQuery>,
) -> Response {
    let who = auth::identity(&headers);
    let filter = Filter::parse(&q.filter);
    let csrf = auth::new_csrf_token();
    let clips = state
        .store
        .list(&who.subject, filter)
        .await
        .unwrap_or_default();

    let html = render_index(&state, &who, &csrf, filter, &clips);
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

    let csrf = auth::new_csrf_token();
    let html = render_reader(&clip, &who, &csrf);
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
// Rendering helpers
// ---------------------------------------------------------------------------

/// Truncate to at most `max` chars on a char boundary.
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
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
    clips: &[Clip],
) -> String {
    INDEX_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Reading list", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace(
            "{{BOOKMARKLET_HREF}}",
            &esc(&bookmarklet_href(&state.config.public_base_url)),
        )
        .replace("{{TABS}}", &render_tabs(filter))
        .replace("{{LIST}}", &render_list(clips, csrf, filter))
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
fn render_list(clips: &[Clip], csrf: &str, filter: Filter) -> String {
    if clips.is_empty() {
        let msg = match filter {
            Filter::All => "Your reading list is empty. Save a link to get started.",
            Filter::Unread => "Nothing unread — you're all caught up.",
            Filter::Archived => "No archived clips yet.",
        };
        return format!("<li class=\"clip-item clip-item--empty\">{}</li>", esc(msg));
    }
    clips
        .iter()
        .map(|c| render_clip_item(c, csrf, filter))
        .collect::<Vec<_>>()
        .join("")
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
    let archive_label = if c.archived { "Unarchive" } else { "Archive" };

    format!(
        "<li class=\"clip-item\">\
           <div class=\"clip-main\">\
             <a class=\"clip-title\" href=\"/r/{id}\">{title}</a>\
             <div class=\"clip-meta\">{status}{site}<span class=\"clip-time\">Saved {saved}</span></div>\
             {excerpt}\
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
        url_attr = esc(&c.url),
        csrf = esc(csrf),
        filter = filter.as_str(),
        archive_label = archive_label,
    )
}

fn render_reader(clip: &Clip, who: &Identity, csrf: &str) -> String {
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
        .replace("{{CONTENT}}", &render_content(&clip.content_text))
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
