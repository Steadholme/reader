//! DB-free + network-free end-to-end tests for the in-app reader (`GET /read/{id}`).
//!
//! Drives the real `app` Router in-process via `tower::oneshot`, seeding the in-memory store
//! through the public `Store` trait exactly as Sluice would (injected `X-Auth-*`). The cached and
//! summary-fallback paths need NO network; the fetch-failure path aims at a non-resolving host so
//! it fails fast and deterministically to the summary fallback.

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
        category_id: None,
        full_content: false,
    }
}

fn item(id: &str, feed_id: &str, summary: &str, link: &str, full_text: Option<&str>) -> Item {
    Item {
        id: id.into(),
        feed_id: feed_id.into(),
        guid: id.into(),
        title: "The Story Title".into(),
        link: link.into(),
        summary: summary.into(),
        published_at: Some(now_secs()),
        read: false,
        full_text: full_text.map(str::to_string),
        starred: false,
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn reader_renders_cached_full_text_without_network() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state
        .store
        .upsert_item(&item(
            "i1",
            "f1",
            "short",
            "https://ex.com/a",
            Some("First cached paragraph.\n\nSecond cached paragraph with detail."),
        ))
        .await
        .unwrap();

    let (status, body) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("The Story Title"));
    assert!(html.contains("First cached paragraph."));
    assert!(html.contains("Second cached paragraph with detail."));
    assert!(html.contains("Full article"));
    // Reading marks it read: the river no longer lists it.
    let (_, river) = call(&state, get("/")).await;
    assert!(!String::from_utf8_lossy(&river).contains("The Story Title"));
}

#[tokio::test]
async fn reader_escapes_cached_content() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state
        .store
        .upsert_item(&item(
            "i1",
            "f1",
            "short",
            "https://ex.com/a",
            Some("<script>alert(1)</script> hostile body"),
        ))
        .await
        .unwrap();

    let (status, body) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("hostile body"));
}

#[tokio::test]
async fn reader_uses_summary_when_content_is_long_enough() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    // A long summary (> READER_SHORT_CONTENT_CHARS) means no fetch is attempted.
    let long = "This is a full and complete summary sentence. ".repeat(20);
    state
        .store
        .upsert_item(&item("i1", "f1", &long, "https://ex.com/a", None))
        .await
        .unwrap();

    let (status, body) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("full and complete summary sentence"));
    assert!(html.contains("Feed summary"));
    // Nothing was cached (no fetch happened).
    let entry = state.store.get_item_owned("i1", OWNER).await.unwrap().unwrap();
    assert!(entry.item.full_text.is_none());
}

#[tokio::test]
async fn reader_falls_back_to_summary_when_fetch_fails() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    // Short summary + a non-resolving link -> fetch fails fast -> summary fallback.
    state
        .store
        .upsert_item(&item(
            "i1",
            "f1",
            "brief blurb",
            "https://nope.invalid/article",
            None,
        ))
        .await
        .unwrap();

    let (status, body) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("brief blurb"));
    assert!(html.contains("Feed summary"));
}

#[tokio::test]
async fn reader_foreign_item_is_not_found() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", "other", "https://ex.com/rss")).await.unwrap();
    state
        .store
        .upsert_item(&item("i1", "f1", "secret", "https://ex.com/a", Some("secret body")))
        .await
        .unwrap();

    let (status, _) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
