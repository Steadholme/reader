//! In-app full-article reading: `GET /read/{id}`.
//!
//! Behind the SSO route (owner = gateway-injected `X-Auth-Subject`, never client input). When the
//! stored item already has a cached `full_text`, it is rendered straight from the store. Otherwise,
//! when the item's summary is missing/short, the handler FETCHES the item's `link` — SSRF-guarded
//! exactly like the sibling Magpie clipper ([`crate::article`]) — extracts the readable main text,
//! caches it on the item (idempotent), and renders it. A failed/blocked fetch falls back to the
//! feed summary, so the page ALWAYS renders. Opening a reader view marks the item read (like the
//! `/i/{id}` open path). Every line of remote text is HTML-escaped on render.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::article;
use crate::auth;
use crate::config::READER_SHORT_CONTENT_CHARS;
use crate::error::AppError;
use crate::feed::safe_link;
use crate::handlers::{esc, fmt_rel, fmt_ts, html_with_csrf, page_shell, tile_initial, tile_tint};
use crate::model::RiverEntry;
use crate::{now_secs, AppState};

const READER_HTML: &str = include_str!("../../templates/reader.html");

/// Where the rendered readable text came from (drives the small provenance label).
#[derive(Clone, Copy)]
enum Source {
    /// Served from the previously-cached `full_text`.
    Cached,
    /// Freshly fetched + extracted from the item link on this request.
    Fetched,
    /// The feed summary (item already had enough content, or the fetch failed/was blocked).
    Summary,
}

impl Source {
    fn label(&self) -> &'static str {
        match self {
            Source::Cached => "Full article",
            Source::Fetched => "Full article",
            Source::Summary => "Feed summary",
        }
    }
}

/// `GET /read/{id}` — render the clean in-app reader page for one owned item.
pub async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let entry = match state.store.get_item_owned(&id, &who.subject).await? {
        Some(e) => e,
        None => {
            return Err(AppError::NotFound(
                "No such item in your feeds.".to_string(),
            ))
        }
    };

    let (paragraphs, source) = resolve_content(&state, &who.subject, &entry).await;

    // Reading an item in-app marks it read, matching the `/i/{id}` open path (best-effort).
    let _ = state.store.mark_item_read(&id, &who.subject).await;

    let csrf = auth::new_csrf_token();
    let html = render_reader(&entry, &paragraphs, source, &who.email, now_secs(), &csrf);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

/// Decide what readable text to show: cached full text, a fresh fetch+extract (cached on success),
/// or the feed summary. Never errors — a fetch failure degrades to the summary.
///
/// When the owning feed has the per-feed "fetch full content" toggle set, the readability extractor
/// runs on EVERY open (even a long summary) and the body is cached in the `entry_content` table.
/// Otherwise the pre-existing behavior holds: extract only when the summary is short, caching to the
/// item's `full_text` column.
async fn resolve_content(
    state: &AppState,
    owner_sub: &str,
    entry: &RiverEntry,
) -> (Vec<String>, Source) {
    let item = &entry.item;

    // 1) Already cached on the item -> render straight from the store (pre-existing cache).
    if let Some(cached) = item.full_text.as_deref() {
        let paras = article::cache_to_paragraphs(cached);
        if !paras.is_empty() {
            return (paras, Source::Cached);
        }
    }

    // 2) Per-entry full-content cache (populated by the full-content toggle path) -> render it.
    if let Ok(Some(cached)) = state.store.get_entry_content(&item.id, owner_sub).await {
        let paras = article::cache_to_paragraphs(&cached);
        if !paras.is_empty() {
            return (paras, Source::Cached);
        }
    }

    // The owning feed's toggle: when on, always attempt the full-content fetch.
    let full_content = match state.store.get_feed(&item.feed_id).await {
        Ok(Some(f)) => f.owner_sub == owner_sub && f.full_content,
        _ => false,
    };

    // 3) Decide whether to fetch: the toggle forces it; otherwise only a short summary triggers it.
    //    Either way we need a usable link.
    let short = item.summary.chars().count() <= READER_SHORT_CONTENT_CHARS;
    let link = safe_link(&item.link);
    if !(full_content || short) || link.is_none() {
        return (summary_paragraphs(&item.summary), Source::Summary);
    }
    let link = link.expect("checked is_some above");

    // 4) Fetch + extract, caching on success. Any failure falls back to the summary. The full-content
    //    toggle caches into `entry_content`; the legacy short-summary path caches into `full_text`.
    match article::fetch_article(&link).await {
        Ok(body) => {
            let paras = article::extract_readable(&body);
            if paras.is_empty() {
                tracing::info!(item = item.id, "reader: extraction empty, using summary");
                (summary_paragraphs(&item.summary), Source::Summary)
            } else {
                let cache = article::paragraphs_to_cache(&paras);
                let write = if full_content {
                    state
                        .store
                        .set_entry_content(&item.id, owner_sub, &cache)
                        .await
                } else {
                    state
                        .store
                        .set_item_full_text(&item.id, owner_sub, &cache)
                        .await
                };
                if let Err(e) = write {
                    tracing::warn!(item = item.id, error = %e, "reader: cache write failed");
                }
                (paras, Source::Fetched)
            }
        }
        Err(e) => {
            tracing::info!(item = item.id, url = link, error = %e, "reader: fetch failed, using summary");
            (summary_paragraphs(&item.summary), Source::Summary)
        }
    }
}

/// The feed summary as a (possibly empty) single-paragraph list.
fn summary_paragraphs(summary: &str) -> Vec<String> {
    let s = summary.trim();
    if s.is_empty() {
        Vec::new()
    } else {
        vec![s.to_string()]
    }
}

fn render_reader(
    entry: &RiverEntry,
    paragraphs: &[String],
    source: Source,
    email: &str,
    now: i64,
    csrf: &str,
) -> String {
    let item = &entry.item;
    let title = if item.title.trim().is_empty() {
        "(untitled)".to_string()
    } else {
        item.title.clone()
    };
    let when = match item.published_at {
        Some(ts) => format!(
            "<time class=\"cur-read__time\" title=\"{abs}\">{rel}</time>",
            abs = esc(&fmt_ts(ts)),
            rel = esc(&fmt_rel(ts, now)),
        ),
        None => String::new(),
    };
    let safe_url = safe_link(&item.link);
    // Link out to the original article only when it is a safe http(s) URL.
    let source_link = match safe_url.as_deref() {
        Some(url) => format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">Open original &#8599;</a>",
            href = esc(url),
        ),
        None => String::new(),
    };
    let foot_link = match safe_url.as_deref() {
        Some(url) => format!(
            "<a class=\"btn btn-primary\" href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">Open original &#8599;</a>",
            href = esc(url),
        ),
        None => String::new(),
    };
    let domain_row = match safe_url.as_deref() {
        Some(url) => reqwest::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_string))
            .map(|host| {
                format!(
                    "<p class=\"cur-read__domain\"><a href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">{host}</a></p>",
                    href = esc(url),
                    host = esc(&host),
                )
            })
            .unwrap_or_default(),
        None => String::new(),
    };
    let star_label = if item.starred {
        "★ Unstar"
    } else {
        "☆ Star"
    };
    let star = format!(
        "<form class=\"inline-form\" method=\"post\" action=\"/i/{id}/star\">\
           <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"filter\" value=\"unread\">\
           <button class=\"btn btn-ghost btn-sm\" type=\"submit\">{star_label}</button>\
         </form>",
        id = esc(&item.id),
        csrf = esc(csrf),
        star_label = star_label,
    );
    let readtime = if paragraphs.is_empty() {
        String::new()
    } else {
        let words = paragraphs
            .iter()
            .map(|p| p.split_whitespace().count())
            .sum::<usize>();
        let minutes = usize::max(1, words / 220);
        format!(
            "<span class=\"cur-read__readtime\">{} min read</span>",
            esc(&minutes.to_string())
        )
    };
    let source_cls = if matches!(source, Source::Summary) {
        " cur-provchip--summary"
    } else {
        ""
    };

    let content = if paragraphs.is_empty() {
        "<p class=\"cur-read__empty\">No readable content was found for this item. Try opening the original article.</p>".to_string()
    } else {
        paragraphs
            .iter()
            .map(|p| format!("<p>{}</p>", esc(p)))
            .collect::<String>()
    };
    let tint = tile_tint(&entry.feed_title).to_string();

    let main = READER_HTML
        .replace("{{TINT}}", &esc(&tint))
        .replace("{{TILE}}", &tile_initial(&entry.feed_title))
        .replace("{{FEED}}", &esc(&entry.feed_title))
        .replace("{{WHEN}}", &when)
        .replace("{{READTIME}}", &readtime)
        .replace("{{SOURCE_CLS}}", source_cls)
        .replace("{{SOURCE}}", &esc(source.label()))
        .replace("{{SOURCELINK}}", &source_link)
        .replace("{{STAR}}", &star)
        .replace("{{DOMAINROW}}", &domain_row)
        .replace("{{FOOTLINK}}", &foot_link)
        .replace("{{TITLE}}", &esc(&title))
        .replace("{{CONTENT}}", &content);
    page_shell(
        &title,
        "river",
        None,
        "",
        " console--narrow",
        Some(email),
        &main,
        "",
    )
}
