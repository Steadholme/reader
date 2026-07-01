//! End-to-end flow tests for clip highlights + inline notes against the in-memory store + a STUB
//! fetcher (NO database, NO network).
//!
//! Drives the real `Router` in-process via `tower::oneshot`: save a clip, add a highlight with a
//! note, verify the reader margin + the "my highlights" aggregate page, the idempotent re-highlight
//! (note update, no duplicate), remote/owner XSS escaping, the double-submit CSRF guard, ownership
//! scoping, and delete.

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

const ARTICLE: &str = r#"<!DOCTYPE html><html><head>
  <meta property="og:title" content="Real Article Title">
  <meta property="og:site_name" content="Example News">
</head><body><article>
  <p>This is the first readable paragraph of the article.</p>
</article></body></html>"#;

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

/// Save a clip as `subject` and return its id.
async fn save_clip(app: &axum::Router, url: &str, subject: &str) -> String {
    let home = send(app, get("/", Some(subject))).await;
    let csrf = home.csrf_cookie().unwrap();
    let saved = send(
        app,
        post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some(subject)),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);
    let list = send(app, get("/", Some(subject))).await;
    let i = list.body.find("/r/").unwrap() + 3;
    let rest = &list.body[i..];
    rest[..rest.find('"').unwrap()].to_string()
}

/// Pull the first highlight id out of a reader/aggregate body (`/highlight/{hid}/delete`).
fn first_highlight_id(body: &str) -> String {
    let marker = "/highlight/";
    let i = body.find(marker).expect("a highlight delete form is present") + marker.len();
    let rest = &body[i..];
    rest[..rest.find('/').unwrap()].to_string()
}

#[tokio::test]
async fn add_list_and_delete_highlight_lifecycle() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;

    // Reader shows the empty highlights state + the add form.
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert_eq!(reader.status, StatusCode::OK);
    assert!(reader.body.contains("No highlights yet"));
    assert!(reader.body.contains(&format!("action=\"/r/{id}/highlight\"")));
    let csrf = reader.csrf_cookie().unwrap();

    // Add a highlight with a note -> 302 back to the reader.
    let added = send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "a striking passage"), ("note", "why it matters")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(added.status, StatusCode::FOUND);
    assert_eq!(added.location(), format!("/r/{id}"));

    // The margin now shows the quote + note.
    let reader2 = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert!(reader2.body.contains("a striking passage"));
    assert!(reader2.body.contains("why it matters"));
    assert!(!reader2.body.contains("No highlights yet"));
    let hid = first_highlight_id(&reader2.body);

    // The aggregate page groups it under the clip title, linking back to the reader.
    let agg = send(&app, get("/highlights", Some("alice"))).await;
    assert_eq!(agg.status, StatusCode::OK);
    assert!(agg.body.contains("a striking passage"));
    assert!(agg.body.contains("Real Article Title"));
    assert!(agg.body.contains(&format!("href=\"/r/{id}\"")));

    // Delete it -> 302 back to the reader; the margin returns to the empty state.
    let csrf2 = reader2.csrf_cookie().unwrap();
    let del = send(
        &app,
        post_form(
            &format!("/highlight/{hid}/delete"),
            &[("csrf_token", &csrf2), ("from", "reader")],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), format!("/r/{id}"));
    let reader3 = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert!(reader3.body.contains("No highlights yet"));
}

#[tokio::test]
async fn re_highlighting_same_passage_updates_note_without_duplicate() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();

    // First highlight.
    send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "same passage"), ("note", "first note")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    // Re-highlight the identical passage with a different note.
    let again = send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "same passage"), ("note", "second note")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(again.status, StatusCode::FOUND);

    // Idempotent: exactly one highlight, and the note was updated.
    let reader2 = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert_eq!(reader2.body.matches("same passage").count(), 1, "no duplicate highlight");
    assert!(reader2.body.contains("second note"));
    assert!(!reader2.body.contains("first note"));
}

#[tokio::test]
async fn highlight_quote_and_note_are_escaped() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();

    send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[
                ("csrf_token", &csrf),
                ("quote", "<script>alert(1)</script>"),
                ("note", "<img src=x onerror=alert(2)>"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;

    let reader2 = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert!(reader2.body.contains("&lt;script&gt;"));
    assert!(!reader2.body.contains("<script>alert(1)"));
    assert!(reader2.body.contains("&lt;img src=x"));
    assert!(!reader2.body.contains("<img src=x onerror"));
}

#[tokio::test]
async fn empty_quote_is_rejected() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();

    let r = send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "   "), ("note", "n")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn csrf_is_required_to_add_highlight() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;

    let bad = send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", "wrong"), ("quote", "x")],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn highlights_are_owner_scoped() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let id = save_clip(&app, url, "alice").await;

    // Bob cannot highlight alice's clip: CSRF cookie "x" == token "x" passes double-submit, then
    // the ownership check rejects with 403.
    let bob_add = send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", "x"), ("quote", "sneaky")],
            "x",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(bob_add.status, StatusCode::FORBIDDEN);

    // Alice adds one; bob cannot delete it (403) and never sees it on his aggregate page.
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();
    send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "alice only")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    let reader2 = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let hid = first_highlight_id(&reader2.body);

    let bob_del = send(
        &app,
        post_form(
            &format!("/highlight/{hid}/delete"),
            &[("csrf_token", "x"), ("from", "reader")],
            "x",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(bob_del.status, StatusCode::FORBIDDEN);

    let bob_agg = send(&app, get("/highlights", Some("bob"))).await;
    assert!(bob_agg.body.contains("not highlighted anything yet"));
    assert!(!bob_agg.body.contains("alice only"));
}
