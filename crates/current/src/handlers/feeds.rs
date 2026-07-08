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

use std::collections::HashMap;

use crate::auth::{self, Identity};
use crate::config::{MAX_FEEDS_PER_OWNER, MAX_URL_CHARS};
use crate::error::AppError;
use crate::feed::{fetch_and_store, new_feed_id, parse_opml_urls, safe_link};
use crate::handlers::{
    esc, fmt_rel, html_with_csrf, page_shell, redirect_see_other, theme_of, tile_initial,
    tile_tint, SHIELD_SVG,
};
use crate::model::{Category, Feed};
use crate::{now_secs, random_alnum, AppState, FEED_ID_LEN};

/// Hard cap on a category name, in characters.
const MAX_CATEGORY_NAME_CHARS: usize = 120;
/// Friendly cap on how many categories one owner may create.
const MAX_CATEGORIES_PER_OWNER: usize = 200;

const FEEDS_HTML: &str = include_str!("../../templates/feeds.html");

// ---------------------------------------------------------------------------
// GET /feeds
// ---------------------------------------------------------------------------

/// `GET /feeds` — the add-feed form, category management, and subscriptions grouped by category.
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let feeds = state.store.list_feeds(&who.subject).await?;
    let categories = state.store.list_categories(&who.subject).await?;
    let unread = state.store.feed_unread_counts(&who.subject).await?;
    let theme = theme_of(&headers);
    let html = render_feeds(&feeds, &categories, &unread, &who, &csrf, None, theme);
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
        return Ok(rerender(&state, &who, "Enter a feed URL (up to 2048 characters).", &headers).await);
    }
    let Some(url) = safe_link(url) else {
        return Ok(rerender(
            &state,
            &who,
            "Feed URL must start with http:// or https://.",
            &headers,
        )
        .await);
    };

    // Friendly cap so the per-owner river join stays cheap.
    let existing = state.store.list_feeds(&who.subject).await?;
    if existing.len() >= MAX_FEEDS_PER_OWNER {
        return Ok(rerender(&state, &who, "You've reached the maximum number of feeds.", &headers).await);
    }

    // Shared insert + best-effort initial fetch (the same path the OPML import reuses).
    if !subscribe(&state, &who.subject, url, now).await? {
        return Ok(rerender(&state, &who, "You're already subscribed to that feed.", &headers).await);
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
// POST /feeds/{id}/refresh — force a fetch now
// ---------------------------------------------------------------------------

/// `POST /feeds/{id}/refresh` — CSRF-checked, owner-scoped forced fetch, then 303 to `/feeds`.
pub async fn refresh(
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
    let Some(feed) = state.store.get_feed(&id).await? else {
        return Err(AppError::NotFound("Feed not found.".to_string()));
    };
    if feed.owner_sub != who.subject {
        return Err(AppError::NotFound("Feed not found.".to_string()));
    }

    let now = now_secs();
    match fetch_and_store(&state.http, state.store.as_ref(), &feed, now).await {
        Ok(n) => tracing::info!(owner = %who.subject, feed = %id, new = n, "feed refreshed"),
        Err(e) => {
            tracing::warn!(owner = %who.subject, feed = %id, error = %e, "feed refresh failed");
            if let Err(store_err) = state.store.record_fetch_failure(&id, now_secs(), &e).await {
                tracing::warn!(
                    feed = %id,
                    error = %store_err,
                    "could not record refresh failure"
                );
            }
        }
    }

    Ok(redirect_see_other("/feeds"))
}

// ---------------------------------------------------------------------------
// Categories: create / rename / delete / reorder + per-feed assignment
// ---------------------------------------------------------------------------

/// Create-category form: CSRF token + the new name.
#[derive(Debug, Deserialize)]
pub struct CategoryForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

/// `POST /categories` — create a category (owner-scoped), then 303 to `/feeds`.
pub async fn create_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CategoryForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_CATEGORY_NAME_CHARS {
        return Ok(rerender(
            &state,
            &who,
            "Enter a category name (up to 120 characters).",
            &headers,
        )
        .await);
    }
    let existing = state.store.list_categories(&who.subject).await?;
    if existing.len() >= MAX_CATEGORIES_PER_OWNER {
        return Ok(rerender(
            &state,
            &who,
            "You've reached the maximum number of categories.",
            &headers,
        )
        .await);
    }
    let category = Category {
        id: random_alnum(FEED_ID_LEN),
        owner_sub: who.subject.clone(),
        name: name.to_string(),
        position: existing.len() as i64,
    };
    if !state.store.add_category(&category).await? {
        return Ok(rerender(&state, &who, "A category with that name already exists.", &headers).await);
    }
    tracing::info!(
        owner = who.subject,
        category = category.id,
        "category created"
    );
    Ok(redirect_see_other("/feeds"))
}

/// `POST /categories/{id}/rename` — rename a category (owner-scoped), then 303 to `/feeds`.
pub async fn rename_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CategoryForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > MAX_CATEGORY_NAME_CHARS {
        return Ok(rerender(
            &state,
            &who,
            "Enter a category name (up to 120 characters).",
            &headers,
        )
        .await);
    }
    state.store.rename_category(&id, &who.subject, name).await?;
    Ok(redirect_see_other("/feeds"))
}

/// `POST /categories/{id}/delete` — delete a category (owner-scoped); its feeds become
/// uncategorized. Then 303 to `/feeds`.
pub async fn delete_category(
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
    state.store.delete_category(&id, &who.subject).await?;
    tracing::info!(owner = who.subject, category = id, "category deleted");
    Ok(redirect_see_other("/feeds"))
}

/// Move-category form: CSRF token + a direction (`up` / `down`).
#[derive(Debug, Deserialize)]
pub struct MoveForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub dir: String,
}

/// `POST /categories/{id}/move` — reorder a category up or down (owner-scoped), then 303 to
/// `/feeds`. Positions are renumbered to the sorted order and the target swapped with its neighbor.
pub async fn move_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MoveForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let mut cats = state.store.list_categories(&who.subject).await?;
    if let Some(idx) = cats.iter().position(|c| c.id == id) {
        let target = match form.dir.as_str() {
            "up" if idx > 0 => Some(idx - 1),
            "down" if idx + 1 < cats.len() => Some(idx + 1),
            _ => None,
        };
        if let Some(t) = target {
            cats.swap(idx, t);
            for (i, c) in cats.iter().enumerate() {
                state
                    .store
                    .set_category_position(&c.id, &who.subject, i as i64)
                    .await?;
            }
        }
    }
    Ok(redirect_see_other("/feeds"))
}

/// Assign-category form: CSRF token + the target category id (empty = uncategorized).
#[derive(Debug, Deserialize)]
pub struct AssignForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub category_id: String,
}

/// `POST /feeds/{id}/category` — assign a feed to a category (or clear it), then 303 to `/feeds`.
pub async fn assign_category(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<AssignForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let category_id = form.category_id.trim();
    let target = if category_id.is_empty() {
        None
    } else {
        Some(category_id)
    };
    state
        .store
        .assign_feed_category(&id, &who.subject, target)
        .await?;
    Ok(redirect_see_other("/feeds"))
}

/// Full-content toggle form: CSRF token + the desired on state (`1` = on, else off).
#[derive(Debug, Deserialize)]
pub struct FullContentForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub on: String,
}

/// `POST /feeds/{id}/full-content` — set the per-feed "fetch full content" toggle, then 303 to
/// `/feeds`.
pub async fn toggle_full_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<FullContentForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let on = form.on.trim() == "1";
    state
        .store
        .set_feed_full_content(&id, &who.subject, on)
        .await?;
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
            &headers,
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
async fn subscribe(state: &AppState, owner: &str, url: String, now: i64) -> Result<bool, AppError> {
    let feed = Feed {
        id: new_feed_id(),
        owner_sub: owner.to_string(),
        url: url.clone(),
        title: url.clone(), // placeholder until the first fetch learns the real <title>
        last_fetched: None,
        last_error: None,
        last_error_at: None,
        consecutive_failures: 0,
        created_at: now,
        category_id: None,
        full_content: false,
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
        let Some(url) = safe_link(&f.url) else {
            continue;
        };
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
            Err(e) => {
                tracing::warn!(url = feed.url, error = %e, "initial fetch failed (skipped)");
                if let Err(store_err) = state
                    .store
                    .record_fetch_failure(&feed.id, now_secs(), &e)
                    .await
                {
                    tracing::warn!(
                        feed = %feed.id,
                        error = %store_err,
                        "could not record initial fetch failure"
                    );
                }
            }
        }
    });
}

/// Re-render the feeds page with an inline error (a fresh CSRF token + the current list).
async fn rerender(
    state: &AppState,
    who: &Identity,
    message: &str,
    headers: &HeaderMap,
) -> Response {
    let csrf = auth::new_csrf_token();
    let feeds = state
        .store
        .list_feeds(&who.subject)
        .await
        .unwrap_or_default();
    let categories = state
        .store
        .list_categories(&who.subject)
        .await
        .unwrap_or_default();
    let unread = state
        .store
        .feed_unread_counts(&who.subject)
        .await
        .unwrap_or_default();
    let theme = theme_of(headers);
    let html = render_feeds(&feeds, &categories, &unread, who, &csrf, Some(message), theme);
    html_with_csrf(StatusCode::BAD_REQUEST, html, &csrf)
}

#[allow(clippy::too_many_arguments)]
fn render_feeds(
    feeds: &[Feed],
    categories: &[Category],
    unread: &[(String, i64)],
    who: &Identity,
    csrf: &str,
    error: Option<&str>,
    theme: &str,
) -> String {
    let now = now_secs();
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };
    let unread_by_feed: HashMap<&str, i64> =
        unread.iter().map(|(id, n)| (id.as_str(), *n)).collect();
    let unread_total: i64 = unread.iter().map(|(_, n)| *n).sum();
    let stats = format!(
        "<strong>{}</strong> feeds · <strong>{}</strong> categories · <strong>{}</strong> unread",
        feeds.len(),
        categories.len(),
        unread_total,
    );
    let cats_open = if categories.is_empty() { "" } else { " open" };

    let categories_html = render_category_manager(categories, csrf);
    let list = render_grouped_feeds(feeds, categories, &unread_by_feed, csrf, now);

    let main = FEEDS_HTML
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{STATS}}", &stats)
        .replace("{{CATS_OPEN}}", cats_open)
        .replace("{{ERROR}}", &error_block)
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{CATEGORIES}}", &categories_html)
        .replace("{{FEEDS}}", &list);
    page_shell(
        "Feeds",
        "feeds",
        Some("feeds"),
        "",
        " cur-shell",
        Some(&who.email),
        theme,
        &main,
        "",
    )
}

/// The category management block: a create form + one row per category (rename / move / delete).
fn render_category_manager(categories: &[Category], csrf: &str) -> String {
    let rows = if categories.is_empty() {
        "<li class=\"list__meta\">No categories yet. Create one to group your feeds.</li>"
            .to_string()
    } else {
        let last = categories.len() - 1;
        categories
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let up = if i > 0 {
                    format!(
                        "<form class=\"inline-form\" method=\"post\" action=\"/categories/{id}/move\">\
                           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                           <input type=\"hidden\" name=\"dir\" value=\"up\">\
                           <button class=\"btn btn-ghost btn-sm\" type=\"submit\" aria-label=\"Move up\">↑</button>\
                         </form>",
                        id = esc(&c.id),
                        csrf = esc(csrf),
                    )
                } else {
                    String::new()
                };
                let down = if i < last {
                    format!(
                        "<form class=\"inline-form\" method=\"post\" action=\"/categories/{id}/move\">\
                           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                           <input type=\"hidden\" name=\"dir\" value=\"down\">\
                           <button class=\"btn btn-ghost btn-sm\" type=\"submit\" aria-label=\"Move down\">↓</button>\
                         </form>",
                        id = esc(&c.id),
                        csrf = esc(csrf),
                    )
                } else {
                    String::new()
                };
                format!(
                    "<li class=\"cur-cat\">\
                       <form class=\"inline-form\" method=\"post\" action=\"/categories/{id}/rename\">\
                         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                         <input class=\"input\" type=\"text\" name=\"name\" value=\"{name}\" maxlength=\"120\" aria-label=\"Category name\">\
                         <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Rename</button>\
                       </form>\
                       <span class=\"feed-item__actions\">{up}{down}\
                         <form class=\"inline-form\" method=\"post\" action=\"/categories/{id}/delete\" \
                           onsubmit=\"return confirm('Delete this category? Its feeds become uncategorized.');\">\
                           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                           <button class=\"btn btn-danger btn-sm\" type=\"submit\">Delete</button>\
                         </form>\
                       </span>\
                     </li>",
                    id = esc(&c.id),
                    csrf = esc(csrf),
                    name = esc(&c.name),
                    up = up,
                    down = down,
                )
            })
            .collect::<String>()
    };

    format!(
        "<form method=\"post\" action=\"/categories\" class=\"add-feed\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"text\" name=\"name\" class=\"add-feed__url\" maxlength=\"120\" \
             placeholder=\"New category name\" required>\
           <button class=\"btn btn-primary\" type=\"submit\">Add category</button>\
         </form>\
         <ul class=\"feed-list\">{rows}</ul>",
        csrf = esc(csrf),
        rows = rows,
    )
}

/// Render the subscriptions grouped by category (each category in order, then Uncategorized last),
/// with a per-group unread subtotal.
fn render_grouped_feeds(
    feeds: &[Feed],
    categories: &[Category],
    unread_by_feed: &HashMap<&str, i64>,
    csrf: &str,
    now: i64,
) -> String {
    if feeds.is_empty() {
        return "<div class=\"empty\"><p class=\"empty__title\">No feeds yet. Add one above to start your river.</p></div>".to_string();
    }

    let mut out = String::new();
    // Named categories in their configured order.
    for cat in categories {
        let group: Vec<&Feed> = feeds
            .iter()
            .filter(|f| f.category_id.as_deref() == Some(cat.id.as_str()))
            .collect();
        out.push_str(&render_group(
            &esc(&cat.name),
            &group,
            categories,
            unread_by_feed,
            csrf,
            now,
        ));
    }
    // Uncategorized: no category, OR a dangling category id (its category was deleted elsewhere).
    let known: std::collections::HashSet<&str> = categories.iter().map(|c| c.id.as_str()).collect();
    let uncategorized: Vec<&Feed> = feeds
        .iter()
        .filter(|f| match f.category_id.as_deref() {
            Some(id) => !known.contains(id),
            None => true,
        })
        .collect();
    if !uncategorized.is_empty() {
        out.push_str(&render_group(
            "Uncategorized",
            &uncategorized,
            categories,
            unread_by_feed,
            csrf,
            now,
        ));
    }
    out
}

/// One category group: a header with the name + unread subtotal, then the feed rows.
fn render_group(
    name_html: &str,
    group: &[&Feed],
    categories: &[Category],
    unread_by_feed: &HashMap<&str, i64>,
    csrf: &str,
    now: i64,
) -> String {
    if group.is_empty() {
        return format!(
            "<section class=\"cur-group\">\
             <div class=\"cur-group__head\">\
               <h3>{name}</h3><span class=\"count-pill\">0 unread</span>\
             </div>\
             <ul class=\"feed-list\"><li class=\"feed-item feed-item--empty\">No feeds in this category.</li></ul>\
             </section>",
            name = name_html,
        );
    }
    let subtotal: i64 = group
        .iter()
        .map(|f| *unread_by_feed.get(f.id.as_str()).unwrap_or(&0))
        .sum();
    let rows = group
        .iter()
        .map(|f| {
            let n = *unread_by_feed.get(f.id.as_str()).unwrap_or(&0);
            render_feed_row(f, categories, n, csrf, now)
        })
        .collect::<String>();
    format!(
        "<section class=\"cur-group\">\
         <div class=\"cur-group__head\">\
           <h3>{name}</h3><span class=\"count-pill\">{subtotal} unread</span>\
         </div>\
         <ul class=\"feed-list\">{rows}</ul>\
         </section>",
        name = name_html,
        subtotal = subtotal,
        rows = rows,
    )
}

fn render_feed_row(
    feed: &Feed,
    categories: &[Category],
    unread: i64,
    csrf: &str,
    now: i64,
) -> String {
    let title = if feed.title.trim().is_empty() {
        feed.url.clone()
    } else {
        feed.title.clone()
    };
    let fetched = match feed.last_fetched {
        Some(ts) => format!("updated {}", fmt_rel(ts, now)),
        None => "not fetched yet".to_string(),
    };
    let (dot_cls, dot_title, down_cls) = if feed.consecutive_failures > 0 {
        ("down", "failing", " cur-row--down")
    } else if feed.last_fetched.is_none() {
        ("warn", "not fetched yet", "")
    } else {
        ("ok", "healthy", "")
    };
    let (health_badge, health_error) = if feed.consecutive_failures > 0 {
        let last_error = feed.last_error.as_deref().unwrap_or("unknown error");
        let last_error_at = feed
            .last_error_at
            .map(|ts| fmt_rel(ts, now))
            .unwrap_or_else(|| "unknown time".to_string());
        (
            format!(
                "<span class=\"badge pill-down\" title=\"{error}\">failing &middot; {failures}&times;</span>",
                error = esc(last_error),
                failures = feed.consecutive_failures,
            ),
            format!(
                "<span class=\"cur-row__error\">last error {when}: {error}</span>",
                when = esc(&last_error_at),
                error = esc(last_error),
            ),
        )
    } else {
        (String::new(), String::new())
    };
    let tile = tile_initial(&title);
    let tint = tile_tint(&title);
    let delete = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/feeds/{id}/delete\" \
           onsubmit=\"return confirm('Remove this feed and its items?');\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-danger btn-sm\" type=\"submit\">Remove</button>\
         </form>",
        id = esc(&feed.id),
        csrf = esc(csrf),
    );
    // The title links to the feed's own site only when the URL is a safe http(s) link.
    let title_html = match safe_link(&feed.url) {
        Some(url) => format!(
            "<a class=\"feed-item__title\" href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">{title}</a>",
            href = esc(&url),
            title = esc(&title),
        ),
        None => format!("<span class=\"feed-item__title\">{}</span>", esc(&title)),
    };
    let unread_pill = if unread > 0 {
        format!("<span class=\"count-pill\">{unread} unread</span>")
    } else {
        String::new()
    };

    // Category assignment <select> (Uncategorized + each category), submitting on change.
    let mut options = String::from("<option value=\"\">Uncategorized</option>");
    for c in categories {
        let selected = if feed.category_id.as_deref() == Some(c.id.as_str()) {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            "<option value=\"{id}\"{selected}>{name}</option>",
            id = esc(&c.id),
            selected = selected,
            name = esc(&c.name),
        ));
    }
    let assign = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/feeds/{id}/category\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <select class=\"input\" name=\"category_id\" aria-label=\"Category\" onchange=\"this.form.submit()\">{options}</select>\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Set</button>\
         </form>",
        id = esc(&feed.id),
        csrf = esc(csrf),
        options = options,
    );

    // Full-content toggle: a single form flipping the flag to the opposite of its current state.
    let (fc_next, fc_label) = if feed.full_content {
        ("0", "Full content: on")
    } else {
        ("1", "Full content: off")
    };
    let full_content = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/feeds/{id}/full-content\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"on\" value=\"{fc_next}\">\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{fc_label}</button>\
         </form>",
        id = esc(&feed.id),
        csrf = esc(csrf),
        fc_next = fc_next,
        fc_label = fc_label,
    );
    let refresh = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/feeds/{id}/refresh\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Refresh</button>\
         </form>",
        id = esc(&feed.id),
        csrf = esc(csrf),
    );

    format!(
        "<li class=\"feed-item cur-row{down_cls}\">\
           <span class=\"cur-dot cur-dot--{dot_cls}\" title=\"{dot_title}\"></span>\
           <span class=\"cur-tile cur-tile--lg cur-tile--t{tint}\" aria-hidden=\"true\">{tile}</span>\
           <div class=\"feed-item__main\">\
             {title_html} {health_badge}\
             <span class=\"feed-item__meta\"><span class=\"feed-item__url\">{url}</span><span>{fetched}</span></span>\
           </div>\
           {health_error}\
           <span class=\"cur-row__end\">\
             {unread_pill}\
             {refresh}\
             <details class=\"cur-menu\">\
               <summary aria-label=\"Feed options\">⋯</summary>\
               <div class=\"cur-menu__pop\">\
                 {assign}\
                 {full_content}\
                 <div class=\"cur-menu__sep\"></div>\
                 {delete}\
               </div>\
             </details>\
           </span>\
         </li>",
        down_cls = down_cls,
        dot_cls = dot_cls,
        dot_title = dot_title,
        tint = tint,
        tile = tile,
        title_html = title_html,
        health_badge = health_badge,
        unread_pill = unread_pill,
        url = esc(&feed.url),
        fetched = esc(&fetched),
        health_error = health_error,
        assign = assign,
        refresh = refresh,
        full_content = full_content,
        delete = delete,
    )
}
