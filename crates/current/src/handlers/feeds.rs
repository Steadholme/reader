//! Feed management: list, add by URL, remove.
//!
//! Behind the SSO route: the owner is the gateway-injected `X-Auth-Subject` (never client-
//! supplied). Add/remove POSTs are CSRF-checked. Adding a feed inserts it immediately (title =
//! the URL) and kicks off a one-off background fetch so its items + real title appear without
//! waiting for the next poll; a failing fetch is logged, never surfaced as an error.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::config::{MAX_FEEDS_PER_OWNER, MAX_URL_CHARS};
use crate::error::AppError;
use crate::feed::{fetch_and_store, new_feed_id, safe_link};
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

    let feed = Feed {
        id: new_feed_id(),
        owner_sub: who.subject.clone(),
        url: url.clone(),
        title: url.clone(), // placeholder until the first fetch learns the real <title>
        last_fetched: None,
        created_at: now,
    };

    if !state.store.add_feed(&feed).await? {
        return Ok(rerender(&state, &who, "You're already subscribed to that feed.").await);
    }
    tracing::info!(owner = who.subject, url = feed.url, "feed added");

    // Kick off a one-off fetch so items + the real title appear promptly (best effort).
    spawn_initial_fetch(state.clone(), feed);

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
// Helpers
// ---------------------------------------------------------------------------

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
