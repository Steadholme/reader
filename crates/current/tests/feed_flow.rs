//! DB-free end-to-end flow over the in-memory store (the default test suite — no database,
//! no network needed). Drives the real `app` Router in-process via `tower::oneshot`, seeding
//! state through the public `Store` trait so the HTTP surface is exercised exactly as Sluice
//! would call it (with the injected `X-Auth-*` headers + the double-submit CSRF cookie).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use current::model::{Feed, Item};
use current::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const OWNER: &str = "u_test";
const EMAIL: &str = "test@holdfast.local";

fn feed(id: &str, owner: &str, url: &str) -> Feed {
    Feed {
        id: id.into(),
        owner_sub: owner.into(),
        url: url.into(),
        title: "Test Feed".into(),
        last_fetched: None,
        created_at: now_secs(),
    }
}

fn item(id: &str, feed_id: &str, guid: &str, title: &str, summary: &str, link: &str) -> Item {
    Item {
        id: id.into(),
        feed_id: feed_id.into(),
        guid: guid.into(),
        title: title.into(),
        link: link.into(),
        summary: summary.into(),
        published_at: Some(now_secs()),
        read: false,
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes, headers)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::empty())
        .unwrap()
}

fn post(uri: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=tok")
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn healthz_is_public_ok() {
    let state = build_dev_state();
    let (status, body, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body, b"ok");
}

#[tokio::test]
async fn empty_river_renders_caught_up() {
    let state = build_dev_state();
    let (status, body, _) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Your river"));
    assert!(html.contains("caught up"));
}

#[tokio::test]
async fn river_shows_unread_and_escapes_remote_content() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    // A hostile remote title/summary must be neutralized on render.
    state
        .store
        .upsert_item(&item(
            "i1",
            "f1",
            "g1",
            "<script>alert(1)</script>Hello",
            "Body <b>remote</b> text",
            "https://ex.com/1",
        ))
        .await
        .unwrap();

    let (status, body, _) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Hello"));
    assert!(html.contains("Test Feed"));
    // The raw script tag must NOT survive into the page.
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn open_item_marks_read_and_redirects_out() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state
        .store
        .upsert_item(&item("i1", "f1", "g1", "Story", "summary", "https://ex.com/article"))
        .await
        .unwrap();

    // Open -> 302 to the external article link.
    let (status, _, headers) = call(&state, get("/i/i1")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        headers.get(header::LOCATION).unwrap().to_str().unwrap(),
        "https://ex.com/article"
    );

    // ...and it is now read, so the river no longer shows it.
    let (_, body, _) = call(&state, get("/")).await;
    assert!(!String::from_utf8_lossy(&body).contains("Story"));
}

#[tokio::test]
async fn open_foreign_item_is_not_found() {
    let state = build_dev_state();
    // Feed owned by someone else.
    state.store.add_feed(&feed("f1", "other", "https://ex.com/rss")).await.unwrap();
    state
        .store
        .upsert_item(&item("i1", "f1", "g1", "Secret", "s", "https://ex.com/x"))
        .await
        .unwrap();

    let (status, _, _) = call(&state, get("/i/i1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mark_all_read_clears_the_river() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "g1", "A", "a", "https://ex.com/1")).await.unwrap();
    state.store.upsert_item(&item("i2", "f1", "g2", "B", "b", "https://ex.com/2")).await.unwrap();

    let (status, _, _) = call(&state, post("/read-all", "csrf_token=tok")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, body, _) = call(&state, get("/")).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("caught up"));
}

#[tokio::test]
async fn mark_one_read_via_post() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "g1", "Keep", "k", "https://ex.com/1")).await.unwrap();
    state.store.upsert_item(&item("i2", "f1", "g2", "Gone", "g", "https://ex.com/2")).await.unwrap();

    let (status, _, _) = call(&state, post("/i/i2/read", "csrf_token=tok")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (_, body, _) = call(&state, get("/")).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Keep"));
    assert!(!html.contains("Gone"));
}

#[tokio::test]
async fn add_feed_requires_csrf() {
    let state = build_dev_state();
    // No CSRF cookie -> rejected with 400.
    let req = Request::builder()
        .method("POST")
        .uri("/feeds")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::from("csrf_token=tok&url=https://ex.com/rss"))
        .unwrap();
    let (status, _, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_feed_rejects_non_http_scheme() {
    let state = build_dev_state();
    let (status, body, _) =
        call(&state, post("/feeds", "csrf_token=tok&url=javascript:alert(1)")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("http"));
}

#[tokio::test]
async fn add_and_list_feed_via_http() {
    let state = build_dev_state();
    // A non-resolving host so the spawned initial fetch fails fast and harmlessly.
    let (status, _, _) = call(
        &state,
        post("/feeds", "csrf_token=tok&url=https://invalid.invalid/feed.xml"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, body, _) = call(&state, get("/feeds")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("invalid.invalid"));

    // The feed is now owned by us; remove it via the CSRF-checked delete.
    let feeds = state.store.list_feeds(OWNER).await.unwrap();
    assert_eq!(feeds.len(), 1);
    let id = &feeds[0].id;
    let (status, _, _) = call(&state, post_owned(&format!("/feeds/{id}/delete"), "csrf_token=tok")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state.store.list_feeds(OWNER).await.unwrap().is_empty());
}

/// `post` variant that accepts an owned uri (the `{id}` path is dynamic).
fn post_owned(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, "__Host-csrf=tok")
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Minimal `application/x-www-form-urlencoded` value encoder (enough for the OPML test bodies).
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn opml_export_downloads_subscriptions() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state.store.add_feed(&feed("f2", OWNER, "https://other.com/atom")).await.unwrap();
    // A feed owned by someone else must NOT appear in our export.
    state.store.add_feed(&feed("f3", "intruder", "https://secret.com/rss")).await.unwrap();

    let (status, body, headers) = call(&state, get("/opml")).await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(ct.contains("opml"), "content-type was {ct}");
    let cd = headers.get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
    assert!(cd.contains("attachment"), "content-disposition was {cd}");

    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<opml"));
    assert!(xml.contains("xmlUrl=\"https://ex.com/rss\""));
    assert!(xml.contains("xmlUrl=\"https://other.com/atom\""));
    assert!(!xml.contains("secret.com"));
}

#[tokio::test]
async fn opml_import_subscribes_and_dedups() {
    let state = build_dev_state();
    // Pre-existing subscription to dedup against (use .invalid so the initial fetch fails fast).
    state.store.add_feed(&feed("f1", OWNER, "https://a.invalid/feed.xml")).await.unwrap();

    let opml = r#"<?xml version="1.0"?><opml version="2.0"><body>
      <outline type="rss" text="A" xmlUrl="https://a.invalid/feed.xml"/>
      <outline type="rss" text="B" xmlUrl="https://b.invalid/rss"/>
      <outline type="rss" text="Bad scheme" xmlUrl="javascript:alert(1)"/>
      <outline text="grouping only, no url"/>
    </body></opml>"#;
    let body = format!("csrf_token=tok&opml={}", urlencode(opml));

    let (status, _, _) = call(&state, post_owned("/opml", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let feeds = state.store.list_feeds(OWNER).await.unwrap();
    let urls: Vec<&str> = feeds.iter().map(|f| f.url.as_str()).collect();
    // a.invalid already existed (deduped, not duplicated); b.invalid newly added; the
    // javascript: URL and the url-less grouping outline are both skipped.
    assert_eq!(feeds.len(), 2, "urls were {urls:?}");
    assert!(urls.contains(&"https://a.invalid/feed.xml"));
    assert!(urls.contains(&"https://b.invalid/rss"));
    assert!(!urls.iter().any(|u| u.contains("javascript")));
}

#[tokio::test]
async fn opml_import_requires_csrf() {
    let state = build_dev_state();
    // No CSRF cookie -> rejected with 400 (no subscriptions created).
    let req = Request::builder()
        .method("POST")
        .uri("/opml")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::from(
            "csrf_token=tok&opml=%3Copml%3E%3Cbody%3E%3C%2Fbody%3E%3C%2Fopml%3E",
        ))
        .unwrap();
    let (status, _, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(state.store.list_feeds(OWNER).await.unwrap().is_empty());
}

#[tokio::test]
async fn opml_import_empty_rerenders_error() {
    let state = build_dev_state();
    // A well-formed but feed-less OPML -> 400 with an inline message, nothing subscribed.
    let opml = r#"<opml version="2.0"><body><outline text="folder"/></body></opml>"#;
    let body = format!("csrf_token=tok&opml={}", urlencode(opml));
    let (status, body, _) = call(&state, post_owned("/opml", &body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("No feeds found"));
    assert!(state.store.list_feeds(OWNER).await.unwrap().is_empty());
}
