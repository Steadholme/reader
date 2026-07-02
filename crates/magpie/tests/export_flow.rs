//! End-to-end flow tests for EXPORT (`GET /export`): Markdown + JSON, escaping of remote/owner
//! text, the inert response headers (attachment + nosniff), and owner scoping. Against the in-memory
//! store + a STUB fetcher (NO database, NO network); drives the real `Router` via `tower::oneshot`.

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

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn header(&self, name: header::HeaderName) -> String {
        self.headers
            .get(name)
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

// og:title carries HTML + Markdown metacharacters (single-quoted attribute so the inner double
// quotes survive HTML parsing).
const MD_PAGE: &str = "<!DOCTYPE html><html><head>\
   <meta property='og:title' content='Pwn <script> *danger*'>\
   <meta property='og:site_name' content='Example News'>\
   </head><body><article><p>Readable body text here for the export.</p></article></body></html>";

const JSON_PAGE: &str = "<!DOCTYPE html><html><head>\
   <meta property='og:title' content='He said \"hi\" and <tag>'>\
   </head><body><article><p>Readable body text for JSON export.</p></article></body></html>";

#[tokio::test]
async fn export_markdown_escapes_and_is_inert_and_owner_scoped() {
    let url = "https://example.com/a";
    let bob_url = "https://example.com/bob";
    let app = app(state_with(
        StubFetcher::default()
            .with(url, "text/html", MD_PAGE)
            .with(bob_url, "text/html", "<html><head><meta property='og:title' content='Bob Secret'></head><body><article><p>bob body</p></article></body></html>"),
    ));
    let id = save_clip(&app, url, "alice").await;
    save_clip(&app, bob_url, "bob").await;

    // Add a highlight (+ note) with Markdown metacharacters.
    let reader = send(&app, get(&format!("/r/{id}"), Some("alice"))).await;
    let csrf = reader.csrf_cookie().unwrap();
    send(
        &app,
        post_form(
            &format!("/r/{id}/highlight"),
            &[("csrf_token", &csrf), ("quote", "quote with *stars* and `code`"), ("note", "a [link] note")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;

    let md = send(&app, get("/export?format=md", Some("alice"))).await;
    assert_eq!(md.status, StatusCode::OK);
    // Inert delivery: markdown content type, download attachment, nosniff.
    assert!(md.header(header::CONTENT_TYPE).starts_with("text/markdown"));
    assert!(md.header(header::CONTENT_DISPOSITION).contains("attachment"));
    assert_eq!(md.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");

    // Raw HTML angle brackets are entity-escaped; no live tag survives.
    assert!(md.body.contains("Pwn &lt;script&gt;"));
    assert!(!md.body.contains("Pwn <script>"));
    // Markdown metacharacters in title + highlight are backslash-escaped.
    assert!(md.body.contains("\\*danger\\*"));
    assert!(md.body.contains("\\*stars\\*"));
    assert!(md.body.contains("\\`code\\`"));
    assert!(md.body.contains("\\[link\\] note"));

    // Owner scoping: bob's clip never appears in alice's export.
    assert!(!md.body.contains("Bob Secret"));
}

#[tokio::test]
async fn export_json_escapes_and_is_inert_and_owner_scoped() {
    let url = "https://example.com/a";
    let bob_url = "https://example.com/bob";
    let app = app(state_with(
        StubFetcher::default()
            .with(url, "text/html", JSON_PAGE)
            .with(bob_url, "text/html", "<html><head><meta property='og:title' content='Bob Secret'></head><body><article><p>bob body</p></article></body></html>"),
    ));
    save_clip(&app, url, "alice").await;
    save_clip(&app, bob_url, "bob").await;

    let js = send(&app, get("/export?format=json", Some("alice"))).await;
    assert_eq!(js.status, StatusCode::OK);
    assert!(js.header(header::CONTENT_TYPE).starts_with("application/json"));
    assert!(js.header(header::CONTENT_DISPOSITION).contains("attachment"));
    assert_eq!(js.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");

    // The embedded double quotes are JSON-escaped (structure preserved), and the doc has the shape.
    assert!(js.body.contains("\\\"hi\\\""));
    assert!(js.body.contains("\"clips\""));
    assert!(js.body.contains("\"highlights\""));
    // Owner scoping.
    assert!(!js.body.contains("Bob Secret"));
}
