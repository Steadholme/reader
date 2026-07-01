//! End-to-end flow tests against the in-memory store + a STUB fetcher (NO database, NO network).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising the full save -> list ->
//! read -> archive -> delete lifecycle, the double-submit CSRF guard, readable extraction, remote
//! XSS escaping, de-dup, and ownership scoping. This is the default `cargo test` suite and stays
//! offline.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use magpie::fetch::{FetchError, Fetched, Fetcher};
use magpie::store::InMemoryStore;
use magpie::{app, AppState};
use magpie::config::Config;
use tower::ServiceExt;

/// A deterministic fetcher: maps a URL to canned `(content_type, body)`; unknown http(s) URLs
/// 502 (`Network`), non-http(s) URLs are `InvalidUrl`.
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
  <title>tag title</title>
  <meta property="og:title" content="Real Article Title">
  <meta property="og:site_name" content="Example News">
  <script>alert('evil-script-body')</script>
  <style>.x{color:red}</style>
</head><body>
  <nav><p>nav junk</p></nav>
  <article>
    <p>This is the first readable paragraph of the article.</p>
    <p>Second paragraph mentions a dangerous &lt;script&gt; sequence inline.</p>
  </article>
</body></html>"#;

// ---- request helpers ------------------------------------------------------

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

// ---- tests ----------------------------------------------------------------

#[tokio::test]
async fn save_list_read_archive_delete_lifecycle() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html; charset=utf-8", ARTICLE)));

    // GET / mints a CSRF cookie and shows the empty-state + bookmarklet.
    let home = send(&app, get("/", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.body.contains("Read later"));
    assert!(home.body.contains("Your reading list is empty"));
    assert!(home.body.contains("Save to HOLDFAST")); // bookmarklet
    assert!(home.body.contains("javascript:")); // draggable bookmarklet href
    let csrf = home.csrf_cookie().expect("csrf cookie on GET /");

    // POST /clip saves it -> 302 /.
    let saved = send(
        &app,
        post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some("alice")),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);
    assert_eq!(saved.location(), "/");

    // The list now shows the EXTRACTED title (og:title), site, excerpt, and an Unread badge.
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("Real Article Title"));
    assert!(list.body.contains("Example News"));
    assert!(list.body.contains("first readable paragraph"));
    assert!(list.body.contains("Unread"));
    // Script/style content never leaks into the saved text.
    assert!(!list.body.contains("evil-script-body"));
    assert!(!list.body.contains("color:red"));

    // Find the clip id from the reader link.
    let id = {
        let marker = "/r/";
        let i = list.body.find(marker).expect("reader link present") + marker.len();
        let rest = &list.body[i..];
        rest[..rest.find('"').unwrap()].to_string()
    };

    // GET /r/{id} renders the reader and marks it read.
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert_eq!(reader.status, StatusCode::OK);
    assert!(reader.body.contains("first readable paragraph"));
    // Inline-decoded "<script>" from the page text is re-escaped, never raw.
    assert!(reader.body.contains("&lt;script&gt;"));
    assert!(!reader.body.contains("dangerous <script> sequence"));

    // It now reads as Read in the list; the Unread filter excludes it.
    let after_read = send(&app, get("/", Some("alice"))).await;
    assert!(after_read.body.contains("Read</span>"));
    let unread = send(&app, get("/?filter=unread", Some("alice"))).await;
    assert!(unread.body.contains("all caught up"));

    // Archive it -> leaves the active list, appears under Archived.
    let csrf2 = after_read.csrf_cookie().unwrap();
    let arch = send(
        &app,
        post_form(&format!("/archive/{id}"), &[("csrf_token", &csrf2), ("filter", "all")], &csrf2, Some("alice")),
    )
    .await;
    assert_eq!(arch.status, StatusCode::FOUND);
    let active = send(&app, get("/", Some("alice"))).await;
    assert!(active.body.contains("Your reading list is empty"));
    let archived = send(&app, get("/?filter=archived", Some("alice"))).await;
    assert!(archived.body.contains("Real Article Title"));

    // Delete it -> gone everywhere.
    let csrf3 = archived.csrf_cookie().unwrap();
    let del = send(
        &app,
        post_form(&format!("/delete/{id}"), &[("csrf_token", &csrf3), ("filter", "archived")], &csrf3, Some("alice")),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    let gone = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn title_xss_is_escaped() {
    let url = "https://evil.test/x";
    let page = r#"<html><head><meta property="og:title" content="Pwn<script>alert(1)</script>"></head>
        <body><article><p>body text</p></article></body></html>"#;
    let app = app(state_with(StubFetcher::default().with(url, "text/html", page)));
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    send(&app, post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some("alice"))).await;

    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("Pwn&lt;script&gt;"));
    assert!(!list.body.contains("Pwn<script>"));
}

#[tokio::test]
async fn duplicate_url_is_not_saved_twice() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();

    for _ in 0..3 {
        let r = send(&app, post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some("alice"))).await;
        assert_eq!(r.status, StatusCode::FOUND);
    }
    let list = send(&app, get("/", Some("alice"))).await;
    assert_eq!(list.body.matches("Real Article Title").count(), 1, "only one clip despite re-saving");
}

#[tokio::test]
async fn csrf_is_required_on_clip() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    // Wrong token vs cookie -> rejected before any fetch.
    let bad = send(
        &app,
        post_form("/clip", &[("csrf_token", "wrong"), ("url", url)], "the-cookie", Some("alice")),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bookmarklet_landing_rejects_bad_scheme() {
    let app = app(state_with(StubFetcher::default()));
    let bad = send(&app, get("/clip?u=file:///etc/passwd", Some("alice"))).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // A valid URL renders the auto-submitting confirm page.
    let ok = send(&app, get("/clip?u=https%3A%2F%2Fexample.com%2Fa", Some("alice"))).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert!(ok.body.contains("Save this page?"));
    assert!(ok.body.contains("https://example.com/a"));
    assert!(ok.body.contains("saveForm")); // auto-submit form present
}

#[tokio::test]
async fn unfetchable_url_returns_bad_gateway() {
    let app = app(state_with(StubFetcher::default()));
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let r = send(
        &app,
        post_form("/clip", &[("csrf_token", &csrf), ("url", "https://nope.test/x")], &csrf, Some("alice")),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn tags_on_save_filter_search_and_edit() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));

    // Save WITH tags on the create form.
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let saved = send(
        &app,
        post_form(
            "/clip",
            &[("csrf_token", &csrf), ("url", url), ("tags", "Rust, Reading")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);

    // The list shows the tag chips (normalized to lowercase), each linking to its /?tag= view.
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("href=\"/?tag=rust\""));
    assert!(list.body.contains("href=\"/?tag=reading\""));

    // The tag view returns the clip; a non-matching tag returns the empty state.
    let tagged = send(&app, get("/?tag=rust", Some("alice"))).await;
    assert!(tagged.body.contains("Real Article Title"));
    let empty_tag = send(&app, get("/?tag=nope", Some("alice"))).await;
    assert!(empty_tag.body.contains("No clips tagged"));
    // whole-token: "rus" must not match the "rust" tag.
    let partial = send(&app, get("/?tag=rus", Some("alice"))).await;
    assert!(partial.body.contains("No clips tagged"));

    // Full-text search over the extracted body text finds it (case-insensitive).
    let found = send(&app, get("/search?q=READABLE", Some("alice"))).await;
    assert_eq!(found.status, StatusCode::OK);
    assert!(found.body.contains("Real Article Title"));
    // A non-matching query shows the no-results state.
    let miss = send(&app, get("/search?q=zzznotpresent", Some("alice"))).await;
    assert!(miss.body.contains("No clips match"));
    // Search is owner-scoped: bob sees nothing.
    let bob_search = send(&app, get("/search?q=readable", Some("bob"))).await;
    assert!(!bob_search.body.contains("Real Article Title"));

    // Find the clip id from the reader link.
    let id = {
        let i = list.body.find("/r/").unwrap() + 3;
        let rest = &list.body[i..];
        rest[..rest.find('"').unwrap()].to_string()
    };

    // Edit the tags via POST /tags/{id} (CSRF-checked, ownership-scoped).
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf2 = reader.csrf_cookie().unwrap();
    let edited = send(
        &app,
        post_form(
            &format!("/tags/{id}"),
            &[("csrf_token", &csrf2), ("tags", "gardening")],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(edited.status, StatusCode::FOUND);
    assert_eq!(edited.location(), format!("/r/{id}"));

    // The old tag view is now empty; the new one has the clip.
    let old_view = send(&app, get("/?tag=rust", Some("alice"))).await;
    assert!(old_view.body.contains("No clips tagged"));
    let new_view = send(&app, get("/?tag=gardening", Some("alice"))).await;
    assert!(new_view.body.contains("Real Article Title"));

    // A non-owner cannot edit tags: CSRF cookie "x" == token "x" passes double-submit, then the
    // ownership check rejects with 403 (same as the archive/delete handlers).
    let bob_edit = send(
        &app,
        post_form(
            &format!("/tags/{id}"),
            &[("csrf_token", "x"), ("tags", "hacked")],
            "x",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(bob_edit.status, StatusCode::FORBIDDEN);
    // And alice's tags are unchanged.
    assert!(send(&app, get("/?tag=gardening", Some("alice"))).await.body.contains("Real Article Title"));
}

#[tokio::test]
async fn clips_are_private_to_owner() {
    let url = "https://example.com/article";
    let app = app(state_with(StubFetcher::default().with(url, "text/html", ARTICLE)));
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    send(&app, post_form("/clip", &[("csrf_token", &csrf), ("url", url)], &csrf, Some("alice"))).await;
    let list = send(&app, get("/", Some("alice"))).await;
    let id = {
        let i = list.body.find("/r/").unwrap() + 3;
        let rest = &list.body[i..];
        rest[..rest.find('"').unwrap()].to_string()
    };

    // Bob cannot read Alice's clip (404, no existence leak) and his own list is empty.
    let bob_view = send(&app, get(&format!("/r/{id}"), Some("bob"))).await;
    assert_eq!(bob_view.status, StatusCode::NOT_FOUND);
    let bob_list = send(&app, get("/", Some("bob"))).await;
    assert!(bob_list.body.contains("Your reading list is empty"));
}
