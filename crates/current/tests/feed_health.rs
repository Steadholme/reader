//! Feed health status and manual refresh coverage.
//!
//! DB-free by default: store behavior uses `InMemoryStore`, and the refresh success path uses a
//! one-shot localhost RSS response instead of external network.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use current::model::Feed;
use current::store::{InMemoryStore, Store};
use current::{app, build_dev_state, now_secs, AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const ALICE: &str = "u_alice";
const BOB: &str = "u_bob";
const EMAIL: &str = "test@steadholme.local";
const CSRF: &str = "tok";

fn feed(id: &str, owner: &str, url: &str) -> Feed {
    Feed {
        id: id.into(),
        owner_sub: owner.into(),
        url: url.into(),
        title: "Test Feed".into(),
        last_fetched: None,
        last_error: None,
        last_error_at: None,
        consecutive_failures: 0,
        created_at: now_secs(),
        category_id: None,
        full_content: false,
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String, HeaderMap) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string(), headers)
}

fn get_as(uri: &str, owner: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", owner)
        .header("x-auth-email", EMAIL)
        .body(Body::empty())
        .unwrap()
}

fn post_as(uri: &str, owner: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", owner)
        .header("x-auth-email", EMAIL)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_without_csrf(uri: &str, owner: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-auth-subject", owner)
        .header("x-auth-email", EMAIL)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn one_shot_feed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Recovered Feed</title>
    <item>
      <title>Recovered Story</title>
      <link>https://example.com/recovered</link>
      <guid>recovered-1</guid>
      <description>ok</description>
    </item>
  </channel>
</rss>"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });
    format!("http://{addr}/feed.xml")
}

#[tokio::test]
async fn record_fetch_failure_increments() {
    let store = InMemoryStore::new();
    store
        .add_feed(&feed("f1", ALICE, "https://example.com/rss"))
        .await
        .unwrap();

    store
        .record_fetch_failure("f1", 100, "first")
        .await
        .unwrap();
    store
        .record_fetch_failure("f1", 200, "second <script>")
        .await
        .unwrap();

    let f = store.get_feed("f1").await.unwrap().unwrap();
    assert_eq!(f.consecutive_failures, 2);
    assert_eq!(f.last_error.as_deref(), Some("second <script>"));
    assert_eq!(f.last_error_at, Some(200));
}

#[tokio::test]
async fn success_resets_health() {
    let store = InMemoryStore::new();
    store
        .add_feed(&feed("f1", ALICE, "https://example.com/rss"))
        .await
        .unwrap();
    store.record_fetch_failure("f1", 100, "down").await.unwrap();

    store
        .update_feed_meta("f1", "Recovered", 300)
        .await
        .unwrap();

    let f = store.get_feed("f1").await.unwrap().unwrap();
    assert_eq!(f.title, "Recovered");
    assert_eq!(f.last_fetched, Some(300));
    assert_eq!(f.last_error, None);
    assert_eq!(f.last_error_at, None);
    assert_eq!(f.consecutive_failures, 0);
}

#[tokio::test]
async fn failing_badge_renders_escaped() {
    let state = build_dev_state();
    let mut f = feed("f1", ALICE, "https://example.com/rss");
    f.last_error = Some("<script>alert(1)</script>".into());
    f.last_error_at = Some(now_secs());
    f.consecutive_failures = 1;
    state.store.add_feed(&f).await.unwrap();

    let (status, body, _) = call(&state, get_as("/feeds", ALICE)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("failing"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!body.contains("<script>alert(1)</script>"));
}

#[tokio::test]
async fn refresh_is_owner_scoped_and_csrf() {
    let state = build_dev_state();
    let mut foreign = feed("foreign", ALICE, "https://invalid.invalid/feed.xml");
    foreign.last_error = Some("old failure".into());
    foreign.last_error_at = Some(10);
    foreign.consecutive_failures = 7;
    state.store.add_feed(&foreign).await.unwrap();

    let (status, _, _) = call(
        &state,
        post_as("/feeds/foreign/refresh", BOB, &format!("csrf_token={CSRF}")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let unchanged = state.store.get_feed("foreign").await.unwrap().unwrap();
    assert_eq!(unchanged.consecutive_failures, 7);
    assert_eq!(unchanged.last_error.as_deref(), Some("old failure"));

    let (status, _, _) = call(
        &state,
        post_without_csrf(
            "/feeds/foreign/refresh",
            ALICE,
            &format!("csrf_token={CSRF}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let url = one_shot_feed_url().await;
    let mut own = feed("own", ALICE, &url);
    own.last_error = Some("previous failure".into());
    own.last_error_at = Some(20);
    own.consecutive_failures = 2;
    state.store.add_feed(&own).await.unwrap();

    let (status, _, headers) = call(
        &state,
        post_as("/feeds/own/refresh", ALICE, &format!("csrf_token={CSRF}")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/feeds");
    let refreshed = state.store.get_feed("own").await.unwrap().unwrap();
    assert_eq!(refreshed.title, "Recovered Feed");
    assert_eq!(refreshed.last_error, None);
    assert_eq!(refreshed.consecutive_failures, 0);
    assert!(refreshed.last_fetched.is_some());
}

#[tokio::test]
async fn backward_compat_no_failing_badge_for_healthy_feed() {
    let state = build_dev_state();
    state
        .store
        .add_feed(&feed("f1", ALICE, "https://example.com/rss"))
        .await
        .unwrap();

    let (status, body, _) = call(&state, get_as("/feeds", ALICE)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("failing"));
    assert!(!body.contains("last error"));
}
