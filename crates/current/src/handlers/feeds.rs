//! Feed management: list, add by URL, remove.
//!
//! Behind the SSO route: the owner is the gateway-injected `X-Auth-Subject` (never client-
//! supplied). Add/remove POSTs are CSRF-checked. Adding a feed inserts it immediately (title =
//! the URL) and kicks off a one-off background fetch so its items + real title appear without
//! waiting for the next poll; a failing fetch is logged, never surfaced as an error.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{MAX_FEEDS_PER_OWNER, MAX_URL_CHARS};
use crate::error::AppError;
use crate::feed::{fetch_and_store, new_feed_id, parse_opml_urls, safe_link};
use crate::handlers::{esc, fmt_rel, html_with_csrf, redirect_see_other, userbox, APP_CSS, SHIELD_SVG};
use crate::model::Feed;
use crate::{now_secs, AppState};

const FEEDS_HTML: &str = include_str!("../../templates/feeds.html");

// ---------------------------------------------------------------------------
// GET /feeds
// ---------------------------------------------------------------------------

/// `GET /feeds` — the add-feed form + the owner's current subscriptions.
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let feeds = state.store.list_feeds(&who.subject).await?;
    let html = render_feeds(&feeds, &who, &csrf, None);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /feeds — add by URL
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub url: String,
}

/// `POST /feeds` — validate + subscribe to a feed URL, then 303 to `/feeds`. Validation errors
/// re-render the page (preserving nothing sensitive) with an inline message.
pub async fn add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AddForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let now = now_secs();

    // Normalize + validate the URL (http/https only, bounded length).
    let url = form.url.trim();
    if url.is_empty() || url.chars().count() > MAX_URL_CHARS {
        return Ok(rerender(&state, &who, "Enter a feed URL (up to 2048 characters).").await);
    }
    let Some(url) = safe_link(url) else {
        return Ok(rerender(
            &state,
            &who,
            "Feed URL must start with http:// or https://.",
        )
        .await);
    };

    // Friendly cap so the per-owner river join stays cheap.
    let existing = state.store.list_feeds(&who.subject).await?;
    if existing.len() >= MAX_FEEDS_PER_OWNER {
        return Ok(rerender(
            &state,
            &who,
            "You've reached the maximum number of feeds.",
        )
        .await);
    }

    // Shared insert + best-effort initial fetch (the same path the OPML import reuses).
    if !subscribe(&state, &who.subject, url, now).await? {
        return Ok(rerender(&state, &who, "You're already subscribed to that feed.").await);
    }

    Ok(redirect_see_other("/feeds"))
}

// ---------------------------------------------------------------------------
// POST /feeds/{id}/delete — unsubscribe
// ---------------------------------------------------------------------------

/// `POST /feeds/{id}/delete` — CSRF-checked, owner-scoped removal (cascades the feed's items),
/// then 303 to `/feeds`.
pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<crate::handlers::river::CsrfForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    state.store.remove_feed(&id, &who.subject).await?;
    tracing::info!(owner = who.subject, feed = id, "feed removed");
    Ok(redirect_see_other("/feeds"))
}

// ---------------------------------------------------------------------------
// GET /opml — export all subscriptions as OPML
// ---------------------------------------------------------------------------

/// `GET /opml` — download the owner's subscriptions as an OPML 2.0 document (one `<outline>` per
/// feed). Owner-scoped; feed titles + URLs are XML-attribute-escaped.
pub async fn export_opml(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let feeds = state.store.list_feeds(&who.subject).await?;
    let xml = render_opml(&feeds);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/x-opml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"current-subscriptions.opml\"",
            ),
        ],
        xml,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /opml — import subscriptions from a pasted OPML document
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ImportForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub opml: String,
}

/// `POST /opml` — CSRF-checked import: parse each `<outline xmlUrl=…>`, subscribe every valid
/// http(s) URL (reusing the add-feed path so dedup + the initial fetch are identical), and 303 to
/// `/feeds`. Duplicates (already-subscribed URLs, repeats within the file) are silently skipped;
/// the per-owner cap still applies.
pub async fn import_opml(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ImportForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let now = now_secs();

    let urls = parse_opml_urls(&form.opml);
    if urls.is_empty() {
        return Ok(rerender(
            &state,
            &who,
            "No feeds found in that OPML. Paste the contents of an exported OPML file and try again.",
        )
        .await);
    }

    // Existing count seeds the per-owner cap; each successful (deduped) insert bumps it.
    let mut count = state.store.list_feeds(&who.subject).await?.len();
    let mut added = 0usize;
    for raw in urls {
        if count >= MAX_FEEDS_PER_OWNER {
            break;
        }
        let url = raw.trim();
        if url.is_empty() || url.chars().count() > MAX_URL_CHARS {
            continue;
        }
        let Some(url) = safe_link(url) else { continue };
        if subscribe(&state, &who.subject, url, now).await? {
            added += 1;
            count += 1;
        }
    }
    tracing::info!(owner = who.subject, added, "opml import complete");

    Ok(redirect_see_other("/feeds"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Insert a subscription for `owner` to an already scheme-validated `url`, then kick off the
/// best-effort initial fetch. Returns `Ok(true)` when newly inserted, `Ok(false)` on an
/// `(owner, url)` conflict (dedup). Shared by the single add form and the OPML import.
async fn subscribe(
    state: &AppState,
    owner: &str,
    url: String,
    now: i64,
) -> Result<bool, AppError> {
    let feed = Feed {
        id: new_feed_id(),
        owner_sub: owner.to_string(),
        url: url.clone(),
        title: url.clone(), // placeholder until the first fetch learns the real <title>
        last_fetched: None,
        created_at: now,
    };
    if !state.store.add_feed(&feed).await? {
        return Ok(false);
    }
    tracing::info!(owner = owner, url = feed.url, "feed added");
    // Kick off a one-off fetch so items + the real title appear promptly (best effort).
    spawn_initial_fetch(state.clone(), feed);
    Ok(true)
}

/// Render the owner's feeds as an OPML 2.0 document (subscription export).
fn render_opml(feeds: &[Feed]) -> String {
    let mut body = String::new();
    for f in feeds {
        // Only export a feed whose URL is a safe http(s) link (matches what import will accept).
        let Some(url) = safe_link(&f.url) else { continue };
        let title = if f.title.trim().is_empty() {
            f.url.clone()
        } else {
            f.title.clone()
        };
        body.push_str(&format!(
            "    <outline type=\"rss\" text=\"{title}\" title=\"{title}\" xmlUrl=\"{url}\"/>\n",
            title = esc(&title),
            url = esc(&url),
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <opml version=\"2.0\">\n\
         \x20 <head><title>Current subscriptions</title></head>\n\
         \x20 <body>\n\
         {body}\
         \x20 </body>\n\
         </opml>\n",
        body = body,
    )
}

/// Spawn a detached best-effort initial fetch for a freshly-added feed.
fn spawn_initial_fetch(state: AppState, feed: Feed) {
    tokio::spawn(async move {
        match fetch_and_store(&state.http, state.store.as_ref(), &feed, now_secs()).await {
            Ok(n) => tracing::info!(url = feed.url, new = n, "initial fetch complete"),
            Err(e) => tracing::warn!(url = feed.url, error = %e, "initial fetch failed (skipped)"),
        }
    });
}

/// Re-render the feeds page with an inline error (a fresh CSRF token + the current list).
async fn rerender(state: &AppState, who: &Identity, message: &str) -> Response {
    let csrf = auth::new_csrf_token();
    let feeds = state.store.list_feeds(&who.subject).await.unwrap_or_default();
    let html = render_feeds(&feeds, who, &csrf, Some(message));
    html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf)
}

fn render_feeds(feeds: &[Feed], who: &Identity, csrf: &str, error: Option<&str>) -> String {
    let now = now_secs();
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };

    let list = if feeds.is_empty() {
        "<li class=\"feed-item feed-item--empty\">No feeds yet. Add one above to start your river.</li>"
            .to_string()
    } else {
        feeds
            .iter()
            .map(|f| render_feed_row(f, csrf, now))
            .collect::<Vec<_>>()
            .join("")
    };

    FEEDS_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("feeds", Some(&who.email)))
        .replace("{{ERROR}}", &error_block)
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{FEEDS}}", &list)
}

fn render_feed_row(feed: &Feed, csrf: &str, now: i64) -> String {
    let title = if feed.title.trim().is_empty() {
        feed.url.clone()
    } else {
        feed.title.clone()
    };
    let fetched = match feed.last_fetched {
        Some(ts) => format!("updated {}", fmt_rel(ts, now)),
        None => "not fetched yet".to_string(),
    };
    // The title links to the feed's own site only when the URL is a safe http(s) link.
    let title_html = match safe_link(&feed.url) {
        Some(url) => format!(
            "<a class=\"feed-item__title\" href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">{title}</a>",
            href = esc(&url),
            title = esc(&title),
        ),
        None => format!("<span class=\"feed-item__title\">{}</span>", esc(&title)),
    };

    format!(
        "<li class=\"feed-item\">\
           <div class=\"feed-item__main\">\
             {title_html}\
             <span class=\"feed-item__meta\"><span class=\"feed-item__url\">{url}</span><span>{fetched}</span></span>\
           </div>\
           <form class=\"inline-form\" method=\"post\" action=\"/feeds/{id}/delete\" \
             onsubmit=\"return confirm('Remove this feed and its items?');\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <button class=\"btn btn-danger btn-sm\" type=\"submit\">Remove</button>\
           </form>\
         </li>",
        title_html = title_html,
        url = esc(&feed.url),
        fetched = esc(&fetched),
        id = esc(&feed.id),
        csrf = esc(csrf),
    )
}
