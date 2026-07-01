//! The unified reading river + item open / mark-read / mark-all-read.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the user and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Current is internal-only). The owner is
//! ALWAYS those headers — never a client-supplied field. State-changing POSTs carry a double-
//! submit CSRF token. Every feed/item string (remote, untrusted) is HTML-escaped on render.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

use crate::auth;
use crate::config::{RIVER_LIMIT, SUMMARY_SENTENCES};
use crate::error::AppError;
use crate::feed::safe_link;
use crate::handlers::{
    esc, fmt_rel, fmt_ts, html_with_csrf, redirect_found, redirect_see_other, userbox, APP_CSS,
    SHIELD_SVG,
};
use crate::model::RiverEntry;
use crate::nlp::{self, Cluster};
use crate::{now_secs, AppState};

const RIVER_HTML: &str = include_str!("../../templates/river.html");

/// Shared form shape for the CSRF-only POSTs (mark read, mark all).
#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// GET / — the river
// ---------------------------------------------------------------------------

/// `GET /` — newest unread items across all of the owner's feeds.
pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let now = now_secs();
    let csrf = auth::new_csrf_token();
    let entries = state.store.river(&who.subject, RIVER_LIMIT).await?;

    let html = render_river(&entries, &who.email, &csrf, now);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /read-all — mark everything read
// ---------------------------------------------------------------------------

/// `POST /read-all` — CSRF-checked; mark every unread item read, then 303 to `/`.
pub async fn mark_all(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    let n = state.store.mark_all_read(&who.subject).await?;
    tracing::info!(owner = who.subject, count = n, "marked all read");
    Ok(redirect_see_other("/"))
}

// ---------------------------------------------------------------------------
// POST /i/{id}/read — mark a single item read (stay in the river)
// ---------------------------------------------------------------------------

/// `POST /i/{id}/read` — CSRF-checked, owner-scoped; mark one item read, then 303 to `/`.
pub async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    state.store.mark_item_read(&id, &who.subject).await?;
    Ok(redirect_see_other("/"))
}

// ---------------------------------------------------------------------------
// GET /i/{id} — open: mark read, then link out to the original article
// ---------------------------------------------------------------------------

/// `GET /i/{id}` — mark the item read (owner-scoped) and 302 to its external link. A foreign /
/// missing item is a 404; an item with no usable link falls back to the river.
pub async fn open(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let entry = match state.store.get_item_owned(&id, &who.subject).await? {
        Some(e) => e,
        None => return Err(AppError::NotFound("No such item in your feeds.".to_string())),
    };
    // Marking read is the whole point of "opening" — do it before we leave.
    state.store.mark_item_read(&id, &who.subject).await?;

    match safe_link(&entry.item.link) {
        Some(url) => Ok(redirect_found(&url)),
        None => Ok(redirect_see_other("/")),
    }
}

// ---------------------------------------------------------------------------
// GET /api/item/{id}/summary — extractive 1–2 sentence summary (JSON)
// ---------------------------------------------------------------------------

/// `GET /api/item/{id}/summary` — owner-scoped extractive summary of one item, computed locally
/// (top sentences of the item's stored content by term frequency — no external model). A
/// foreign/missing item is a 404; the summary itself is always derivable, so this never 500s on
/// the content. Read-only (no mark-read side effect, unlike `/i/{id}`).
pub async fn item_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let entry = match state.store.get_item_owned(&id, &who.subject).await? {
        Some(e) => e,
        None => return Err(AppError::NotFound("No such item in your feeds.".to_string())),
    };
    let sentences =
        nlp::extractive_sentences(&entry.item.title, &entry.item.summary, SUMMARY_SENTENCES);
    let summary = sentences.join(" ");
    Ok(Json(serde_json::json!({
        "id": entry.item.id,
        "title": entry.item.title,
        "summary": summary,
        "sentences": sentences,
        "source": "extractive",
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_river(entries: &[RiverEntry], email: &str, csrf: &str, now: i64) -> String {
    let count = entries.len();
    let unread_label = if count >= RIVER_LIMIT as usize {
        format!("{}+ unread", RIVER_LIMIT)
    } else if count == 1 {
        "1 unread".to_string()
    } else {
        format!("{count} unread")
    };

    let list = if entries.is_empty() {
        "<div class=\"empty\">\
           <p class=\"empty__title\">You're all caught up.</p>\
           <p class=\"empty__sub\">New items appear here as your feeds update. \
             <a href=\"/feeds\">Manage feeds</a>.</p>\
         </div>"
            .to_string()
    } else {
        // Collapse the same story carried by multiple feeds into one entry (non-destructive:
        // every unread item still lives in the store; this only folds the view). A cluster of
        // one renders byte-for-byte as before.
        nlp::cluster_river(entries)
            .iter()
            .map(|c| {
                let also = if c.others.is_empty() {
                    String::new()
                } else {
                    render_also(c)
                };
                render_entry(&c.head, csrf, now, &also)
            })
            .collect::<Vec<_>>()
            .join("")
    };

    RIVER_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("river", Some(email)))
        .replace("{{UNREAD}}", &esc(&unread_label))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{ENTRIES}}", &list)
}

/// Render one river entry. `also` is the optional "also in N feeds" block injected for a cluster
/// head (empty for a standalone item). When `also` is empty AND the item has no condensable
/// content, the output is identical to the pre-dedup/-summary markup (additive-only).
fn render_entry(entry: &RiverEntry, csrf: &str, now: i64, also: &str) -> String {
    let item = &entry.item;
    let title = if item.title.trim().is_empty() {
        "(untitled)".to_string()
    } else {
        item.title.clone()
    };
    let when = match item.published_at {
        Some(ts) => format!(
            "<time class=\"entry__time\" title=\"{abs}\">{rel}</time>",
            abs = esc(&fmt_ts(ts)),
            rel = esc(&fmt_rel(ts, now)),
        ),
        None => String::new(),
    };
    // Inline TL;DR: a locally-computed extractive 1–2 sentence condensation, shown only when the
    // stored summary actually has something to condense (more sentences than the TL;DR keeps),
    // so short items render exactly as before.
    let tldr = render_tldr(item);
    // The title links to /i/{id} (mark-read + redirect out). Items with no usable link still
    // open the internal handler, which falls back to the river.
    let summary = if item.summary.trim().is_empty() {
        String::new()
    } else {
        format!("<p class=\"entry__summary\">{}</p>", esc(&item.summary))
    };

    format!(
        "<article class=\"entry\">\
           <div class=\"entry__head\">\
             <span class=\"feed-badge\">{feed}</span>\
             {when}\
           </div>\
           <h2 class=\"entry__title\"><a href=\"/i/{id}\">{title}</a></h2>\
           {tldr}{summary}{also}\
           <div class=\"entry__actions\">\
             <a class=\"btn btn-secondary btn-sm\" href=\"/read/{id}\">Read</a>\
             <a class=\"btn btn-ghost btn-sm\" href=\"/i/{id}\">Open &#8599;</a>\
             <form class=\"inline-form\" method=\"post\" action=\"/i/{id}/read\">\
               <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
               <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Mark read</button>\
             </form>\
           </div>\
         </article>",
        feed = esc(&entry.feed_title),
        when = when,
        id = esc(&item.id),
        title = esc(&title),
        tldr = tldr,
        summary = summary,
        also = also,
        csrf = esc(csrf),
    )
}

/// The inline TL;DR element for an item, or `""` when there is nothing to condense (so the entry
/// renders unchanged). Genuinely condenses only when the summary has more sentences than the
/// TL;DR keeps.
fn render_tldr(item: &crate::model::Item) -> String {
    let total = nlp::split_sentences(&item.summary).len();
    if total <= SUMMARY_SENTENCES {
        return String::new();
    }
    let tldr = nlp::extractive_summary(&item.title, &item.summary, SUMMARY_SENTENCES);
    if tldr.trim().is_empty() {
        return String::new();
    }
    format!(
        "<p class=\"entry__tldr\"><span class=\"tldr-tag\">TL;DR</span> {}</p>",
        esc(&tldr)
    )
}

/// The "also in N feeds" disclosure for a cluster head: a collapsible list of the other sources
/// carrying the same story, each linking to its own `/i/{id}` (open + mark-read). Only called
/// when the cluster has other entries.
fn render_also(cluster: &Cluster) -> String {
    let extra = cluster.extra_feed_count();
    // Distinct other feeds, else fall back to the raw other-source count.
    let n = if extra > 0 { extra } else { cluster.others.len() };
    let noun = if n == 1 { "feed" } else { "feeds" };
    let sources = cluster
        .others
        .iter()
        .map(|e| {
            let title = if e.item.title.trim().is_empty() {
                "(untitled)".to_string()
            } else {
                e.item.title.clone()
            };
            format!(
                "<li class=\"entry__also-src\">\
                   <a href=\"/i/{id}\">\
                     <span class=\"feed-badge feed-badge--sm\">{feed}</span>\
                     <span class=\"entry__also-title\">{title}</span>\
                   </a>\
                 </li>",
                id = esc(&e.item.id),
                feed = esc(&e.feed_title),
                title = esc(&title),
            )
        })
        .collect::<String>();
    format!(
        "<details class=\"entry__also\">\
           <summary class=\"also-tag\">Also in {n} {noun}</summary>\
           <ul class=\"entry__also-list\">{sources}</ul>\
         </details>",
        n = n,
        noun = noun,
        sources = sources,
    )
}
