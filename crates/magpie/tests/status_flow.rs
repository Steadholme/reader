//! End-to-end flow tests for clip STATUS (favorite / archive), the `?view=` tabs, the auto-archive
//! preference, reading-progress writes and the reading-time estimate — all against the in-memory
//! store + a STUB fetcher (NO database, NO network). Drives the real `Router` via `tower::oneshot`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use magpie::config::Config;
use magpie::fetch::{FetchError, Fetched, Fetcher};
use magpie::store::InMemoryStore;
use magpie::{app, AppState};
use tower::ServiceExt;

#[derive(Default)]
struct StubFetcher {
    pages: HashMap<String, (String, String)>,
}

impl StubFetcher {
    fn with(mut self, url: &str, content_type: &str, body: &str) -> Self {
        self.pages
            .insert(url.to_string(), (content_type.to_string(), body.to_string()));
        self
    }
}

#[async_trait]
impl Fetcher for StubFetcher {
    async fn fetch(&self, url: &str) -> Result<Fetched, FetchError> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(FetchError::InvalidUrl(format!("bad scheme: {url}")));
        }
        match self.pages.get(url) {
            Some((ct, body)) => Ok(Fetched {
                final_url: url.to_string(),
                content_type: ct.clone(),
                body: body.clone(),
            }),
            None => Err(FetchError::Network("stub: no such page".into())),
        }
    }
}

fn state_with(fetcher: StubFetcher) -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        fetcher: Arc::new(fetcher),
    }
}

fn article(title: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head>\
           <meta property=\"og:title\" content=\"{title}\">\
           <meta property=\"og:site_name\" content=\"Example News\">\
         </head><body><article>\
           <p>This is the first readable paragraph of the article about widgets and gadgets.</p>\
           <p>Second paragraph continues the discussion with more words to read here.</p>\
         </article></body></html>"
    )
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    fn csrf_cookie(&self) -> Option<String> {
        for hv in self.headers.get_all(header::SET_COOKIE).iter() {
            let raw = hv.to_str().ok()?;
            if let Some(rest) = raw.strip_prefix("__Host-csrf=") {
                return Some(rest.split(';').next().unwrap_or("").to_string());
            }
        }
        None
    }
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(s) = subject {
        b = b.header("x-auth-subject", s).header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

fn post_form(path: &str, fields: &[(&str, &str)], cookie: &str, subject: Option<&str>) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"));
    if let Some(s) = subject {
        b = b.header("x-auth-subject", s).header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::from(body)).unwrap()
}

/// Extract a clip's id from a reading-list body by its (unique, plain) title. Robust against
/// same-second `saved_at` ties (the list breaks ties by id, not save order).
fn id_of(body: &str, title: &str) -> String {
    let anchor = format!("\">{title}</a>");
    let end = body.find(&anchor).expect("clip title present in list");
    let before = &body[..end];
    let start = before.rfind("/r/").expect("reader link before title") + 3;
    before[start..].to_string()
}

/// Save `url` (whose extracted title is `title`) as `subject` and return the new clip id.
async fn save_clip(app: &axum::Router, url: &str, title: &str, subject: &str) -> String {
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().unwrap();
    let saved = send(
        app,
        post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some(subject)),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);
    let list = send(app, get("/", Some(subject))).await;
    id_of(&list.body, title)
}

#[tokio::test]
async fn favorite_toggle_shows_in_favorites_view() {
    let url = "https://example.com/a";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", &article("Fav Article"))));
    let id = save_clip(&app, url, "Fav Article", "alice").await;

    // Not a favorite yet -> the favorites view is empty.
    let favs0 = send(&app, get("/?view=favorites", Some("alice"))).await;
    assert!(favs0.body.contains("No favorites yet"));

    // Star it via POST /favorite/{id}.
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let fav = send(
        &app,
        post_form(&format!("/favorite/{id}"), &[("csrf_token", &csrf), ("view", "all")], &csrf, Some("alice")),
    )
    .await;
    assert_eq!(fav.status, StatusCode::FOUND);
    assert_eq!(fav.location(), "/?view=all");

    // Now it shows in the favorites view, with the favorite badge on the card.
    let favs1 = send(&app, get("/?view=favorites", Some("alice"))).await;
    assert!(favs1.body.contains("Fav Article"));
    assert!(favs1.body.contains("Favorite</span>"));

    // Un-favorite -> favorites view empties again.
    let csrf2 = favs1.csrf_cookie().unwrap();
    let unfav = send(
        &app,
        post_form(&format!("/favorite/{id}"), &[("csrf_token", &csrf2), ("view", "favorites")], &csrf2, Some("alice")),
    )
    .await;
    assert_eq!(unfav.status, StatusCode::FOUND);
    let favs2 = send(&app, get("/?view=favorites", Some("alice"))).await;
    assert!(favs2.body.contains("No favorites yet"));
}

#[tokio::test]
async fn views_partition_by_status() {
    let ua = "https://example.com/unread";
    let ra = "https://example.com/read";
    let app = app(state_with(
        StubFetcher::default()
            .with(ua, "text/html", &article("Unread One"))
            .with(ra, "text/html", &article("Read One")),
    ));
    let unread_id = save_clip(&app, ua, "Unread One", "alice").await;
    let read_id = save_clip(&app, ra, "Read One", "alice").await;

    // Open the second clip -> marks it read.
    send(&app, get(&format!("/r/{read_id}"), Some("alice"))).await;

    // All: both (non-archived). Unread: only the untouched one.
    let all = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(all.body.contains("Unread One") && all.body.contains("Read One"));
    let unread = send(&app, get("/?view=unread", Some("alice"))).await;
    assert!(unread.body.contains("Unread One"));
    assert!(!unread.body.contains("Read One"));

    // Archive the unread one -> leaves All, appears under Archive; legacy ?filter= still resolves.
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    send(
        &app,
        post_form(&format!("/archive/{unread_id}"), &[("csrf_token", &csrf), ("view", "all")], &csrf, Some("alice")),
    )
    .await;
    let archive = send(&app, get("/?view=archive", Some("alice"))).await;
    assert!(archive.body.contains("Unread One"));
    let archive_legacy = send(&app, get("/?filter=archived", Some("alice"))).await;
    assert!(archive_legacy.body.contains("Unread One"));
    let all2 = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(!all2.body.contains("Unread One"));
    let _ = read_id;
}

#[tokio::test]
async fn auto_archive_on_read_is_opt_in() {
    let a = "https://example.com/a";
    let b = "https://example.com/b";
    let app = app(state_with(
        StubFetcher::default()
            .with(a, "text/html", &article("Alpha"))
            .with(b, "text/html", &article("Beta")),
    ));
    let id_a = save_clip(&app, a, "Alpha", "alice").await;

    // Default off: opening the reader leaves the clip in the active list.
    send(&app, get(&format!("/r/{id_a}"), Some("alice"))).await;
    let all = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(all.body.contains("Alpha"));

    // Enable auto-archive via POST /settings.
    let csrf = all.csrf_cookie().unwrap();
    let set = send(
        &app,
        post_form("/settings", &[("csrf_token", &csrf), ("auto_archive", "on"), ("view", "all")], &csrf, Some("alice")),
    )
    .await;
    assert_eq!(set.status, StatusCode::FOUND);

    // Save + open a fresh clip -> it is auto-archived on read.
    let id_b = save_clip(&app, b, "Beta", "alice").await;
    send(&app, get(&format!("/r/{id_b}"), Some("alice"))).await;
    let all2 = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(!all2.body.contains("Beta"));
    let arch = send(&app, get("/?view=archive", Some("alice"))).await;
    assert!(arch.body.contains("Beta"));
}

#[tokio::test]
async fn reading_time_estimate_on_card() {
    let url = "https://example.com/a";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", &article("Timed"))));
    save_clip(&app, url, "Timed", "alice").await;
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("min read"));
}

#[tokio::test]
async fn progress_is_clamped_persisted_and_owner_scoped() {
    let url = "https://example.com/a";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", &article("Progress"))));
    let id = save_clip(&app, url, "Progress", "alice").await;

    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();

    // A mid-scroll write -> 204, and the card offers "Continue reading · 60%".
    let p = send(
        &app,
        post_form(&format!("/progress/{id}"), &[("csrf_token", &csrf), ("progress", "60")], &csrf, Some("alice")),
    )
    .await;
    assert_eq!(p.status, StatusCode::NO_CONTENT);
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("Continue reading · 60%"));

    // Over-range clamps to 100 -> the card shows "Finished".
    send(
        &app,
        post_form(&format!("/progress/{id}"), &[("csrf_token", &csrf), ("progress", "250")], &csrf, Some("alice")),
    )
    .await;
    let list2 = send(&app, get("/", Some("alice"))).await;
    assert!(list2.body.contains("Finished"));
    assert!(!list2.body.contains("Continue reading"));

    // Negative clamps to 0 -> no progress affordance.
    send(
        &app,
        post_form(&format!("/progress/{id}"), &[("csrf_token", &csrf), ("progress", "-10")], &csrf, Some("alice")),
    )
    .await;
    let list3 = send(&app, get("/", Some("alice"))).await;
    assert!(!list3.body.contains("Continue reading"));
    assert!(!list3.body.contains("Finished"));

    // Owner scoping: bob's write to alice's clip is a silent no-op (204, no effect).
    let bob_home = send(&app, get("/", Some("bob"))).await;
    let bob_csrf = bob_home.csrf_cookie().unwrap();
    let bob = send(
        &app,
        post_form(&format!("/progress/{id}"), &[("csrf_token", &bob_csrf), ("progress", "90")], &bob_csrf, Some("bob")),
    )
    .await;
    assert_eq!(bob.status, StatusCode::NO_CONTENT);
    let list4 = send(&app, get("/", Some("alice"))).await;
    assert!(!list4.body.contains("Continue reading · 90%"));

    // CSRF is required.
    let bad = send(
        &app,
        post_form(&format!("/progress/{id}"), &[("csrf_token", "wrong"), ("progress", "10")], "cookie", Some("alice")),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}
