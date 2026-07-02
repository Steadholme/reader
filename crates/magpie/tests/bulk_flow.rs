//! End-to-end flow tests for BULK actions (multi-select archive / delete / tag / favorite) against
//! the in-memory store + a STUB fetcher (NO database, NO network). Verifies the CSRF guard, the
//! repeated-`ids` parsing, and owner scoping. Drives the real `Router` via `tower::oneshot`.

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
        "<!DOCTYPE html><html><head><meta property=\"og:title\" content=\"{title}\"></head>\
         <body><article><p>Body text for {title} with several readable words here.</p></article></body></html>"
    )
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
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

/// Build a form POST whose body preserves REPEATED keys (needed for multi-select `ids`).
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
async fn bulk_archive_then_delete_many() {
    let a = "https://example.com/a";
    let b = "https://example.com/b";
    let app = app(state_with(
        StubFetcher::default()
            .with(a, "text/html", &article("Alpha"))
            .with(b, "text/html", &article("Beta")),
    ));
    let id_a = save_clip(&app, a, "Alpha", "alice").await;
    let id_b = save_clip(&app, b, "Beta", "alice").await;

    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    // Archive both in one POST (repeated ids).
    let arch = send(
        &app,
        post_form(
            "/bulk",
            &[("csrf_token", &csrf), ("view", "all"), ("action", "archive"), ("ids", &id_a), ("ids", &id_b)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(arch.status, StatusCode::FOUND);
    let all = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(!all.body.contains("Alpha") && !all.body.contains("Beta"));
    let archive = send(&app, get("/?view=archive", Some("alice"))).await;
    assert!(archive.body.contains("Alpha") && archive.body.contains("Beta"));

    // Delete both in one POST.
    let csrf2 = archive.csrf_cookie().unwrap();
    let del = send(
        &app,
        post_form(
            "/bulk",
            &[("csrf_token", &csrf2), ("view", "archive"), ("action", "delete"), ("ids", &id_a), ("ids", &id_b)],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    let gone = send(&app, get("/?view=archive", Some("alice"))).await;
    assert!(!gone.body.contains("Alpha") && !gone.body.contains("Beta"));
}

#[tokio::test]
async fn bulk_tag_applies_to_all_selected() {
    let a = "https://example.com/a";
    let b = "https://example.com/b";
    let app = app(state_with(
        StubFetcher::default()
            .with(a, "text/html", &article("Alpha"))
            .with(b, "text/html", &article("Beta")),
    ));
    let id_a = save_clip(&app, a, "Alpha", "alice").await;
    let id_b = save_clip(&app, b, "Beta", "alice").await;
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    let tagged = send(
        &app,
        post_form(
            "/bulk",
            &[
                ("csrf_token", &csrf),
                ("view", "all"),
                ("action", "tag"),
                ("tags", "Rust, Reading"),
                ("ids", &id_a),
                ("ids", &id_b),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(tagged.status, StatusCode::FOUND);
    let view = send(&app, get("/?tag=rust", Some("alice"))).await;
    assert!(view.body.contains("Alpha") && view.body.contains("Beta"));
}

#[tokio::test]
async fn bulk_is_owner_scoped() {
    let url = "https://example.com/a";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", &article("Alice Only"))));
    let id = save_clip(&app, url, "Alice Only", "alice").await;

    // Bob's bulk delete of alice's id passes CSRF (his own cookie==token) but changes nothing.
    let bob = send(
        &app,
        post_form(
            "/bulk",
            &[("csrf_token", "x"), ("view", "all"), ("action", "delete"), ("ids", &id)],
            "x",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(bob.status, StatusCode::FOUND);
    let alice = send(&app, get("/?view=all", Some("alice"))).await;
    assert!(alice.body.contains("Alice Only"), "alice's clip survives a foreign bulk delete");
}

#[tokio::test]
async fn bulk_requires_csrf() {
    let url = "https://example.com/a";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", &article("Alpha"))));
    let id = save_clip(&app, url, "Alpha", "alice").await;
    let bad = send(
        &app,
        post_form(
            "/bulk",
            &[("csrf_token", "wrong"), ("action", "archive"), ("ids", &id)],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}
