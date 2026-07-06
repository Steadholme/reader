//! DB-free + network-free end-to-end tests for the wave-7 Feeds surfaces:
//! categories grouping + unread counts, the star/save filter, and the full-content entry cache.
//!
//! Drives the real `app` Router via `tower::oneshot`, seeding the in-memory store through the public
//! `Store` trait exactly as Sluice would (injected `X-Auth-*`), and exercising the CSRF authoring
//! paths for every mutation.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use current::model::{Feed, Item};
use current::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const OWNER: &str = "u_test";
const EMAIL: &str = "test@holdfast.local";
const CSRF: &str = "tok_for_tests";

fn feed(id: &str, owner: &str, url: &str) -> Feed {
    Feed {
        id: id.into(),
        owner_sub: owner.into(),
        url: url.into(),
        title: format!("Feed {id}"),
        last_fetched: None,
        last_error: None,
        last_error_at: None,
        consecutive_failures: 0,
        created_at: now_secs(),
        category_id: None,
        full_content: false,
    }
}

fn item(id: &str, feed_id: &str, title: &str, starred: bool, read: bool) -> Item {
    Item {
        id: id.into(),
        feed_id: feed_id.into(),
        guid: id.into(),
        title: title.into(),
        link: "https://ex.com/a".into(),
        summary: "short".into(),
        published_at: Some(now_secs()),
        read,
        full_text: None,
        starred,
    }
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::empty())
        .unwrap()
}

fn post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", OWNER)
        .header("x-auth-email", EMAIL)
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn star_filter_view_and_toggle() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "Alpha Story", false, false)).await.unwrap();
    state.store.upsert_item(&item("i2", "f1", "Beta Story", false, false)).await.unwrap();

    // Star i1 through the CSRF authoring path.
    let (status, _) = call(&state, post("/i/i1/star", &format!("csrf_token={CSRF}&filter=unread"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state.store.get_item_owned("i1", OWNER).await.unwrap().unwrap().item.starred);

    // Starred view shows only i1.
    let (status, body) = call(&state, get("/?filter=starred")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Alpha Story"), "starred item shown");
    assert!(!body.contains("Beta Story"), "unstarred item hidden in starred view");
    assert!(body.contains("Saved"), "starred pill rendered");

    // Unread view still shows both (starring does not mark read).
    let (_, body) = call(&state, get("/?filter=unread")).await;
    assert!(body.contains("Alpha Story") && body.contains("Beta Story"));

    // The filter tabs render and mark the active view.
    assert!(body.contains("class=\"tabs\""), "filter tabs present");

    // Un-star i1: it leaves the starred view.
    let (status, _) = call(&state, post("/i/i1/star", &format!("csrf_token={CSRF}&filter=starred"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!state.store.get_item_owned("i1", OWNER).await.unwrap().unwrap().item.starred);
    let (_, body) = call(&state, get("/?filter=starred")).await;
    assert!(!body.contains("Alpha Story"), "un-starred item gone from starred view");

    // Bad CSRF is rejected.
    let (status, _) = call(&state, post("/i/i2/star", "csrf_token=WRONG&filter=unread")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn categories_grouping_with_unread_counts() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://a.com/rss")).await.unwrap();
    state.store.add_feed(&feed("f2", OWNER, "https://b.com/rss")).await.unwrap();
    // f1 has 2 unread, f2 has 1 unread.
    state.store.upsert_item(&item("i1", "f1", "A1", false, false)).await.unwrap();
    state.store.upsert_item(&item("i2", "f1", "A2", false, false)).await.unwrap();
    state.store.upsert_item(&item("i3", "f2", "B1", false, false)).await.unwrap();

    // Create a category through the CSRF path.
    let (status, _) = call(&state, post("/categories", &format!("csrf_token={CSRF}&name=News"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cats = state.store.list_categories(OWNER).await.unwrap();
    assert_eq!(cats.len(), 1);
    let cid = cats[0].id.clone();

    // Assign f1 to the category.
    let (status, _) = call(
        &state,
        post("/feeds/f1/category", &format!("csrf_token={CSRF}&category_id={cid}")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        state.store.get_feed("f1").await.unwrap().unwrap().category_id.as_deref(),
        Some(cid.as_str())
    );

    // The feeds page groups f1 under "News" (unread subtotal 2) and f2 under Uncategorized.
    let (status, body) = call(&state, get("/feeds")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("News"), "category header rendered");
    assert!(body.contains("Uncategorized"), "uncategorized group rendered");
    assert!(body.contains("2 unread"), "News subtotal is 2 unread");
    assert!(body.contains("1 unread"), "per-feed unread count for f2");

    // Delete the category: f1 becomes uncategorized (but is not removed).
    let (status, _) = call(&state, post(&format!("/categories/{cid}/delete"), &format!("csrf_token={CSRF}"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state.store.get_feed("f1").await.unwrap().unwrap().category_id.is_none());
    assert!(state.store.list_categories(OWNER).await.unwrap().is_empty());
}

#[tokio::test]
async fn full_content_toggle_and_entry_cache_render() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://a.com/rss")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "Story", false, false)).await.unwrap();

    // Flip the per-feed full-content toggle on through the CSRF path.
    let (status, _) = call(&state, post("/feeds/f1/full-content", &format!("csrf_token={CSRF}&on=1"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(state.store.get_feed("f1").await.unwrap().unwrap().full_content);

    // Seed the per-entry content cache (as a successful extraction would) — no network.
    state
        .store
        .set_entry_content("i1", OWNER, "Extracted paragraph one.\n\nExtracted paragraph two.")
        .await
        .unwrap();

    // Opening the reader renders the cached full body (Cached provenance), not the RSS summary.
    let (status, body) = call(&state, get("/read/i1")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Extracted paragraph one."));
    assert!(body.contains("Extracted paragraph two."));
    assert!(body.contains("Full article"), "cached full content provenance");

    // Toggle it back off.
    let (status, _) = call(&state, post("/feeds/f1/full-content", &format!("csrf_token={CSRF}&on=0"))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!state.store.get_feed("f1").await.unwrap().unwrap().full_content);

    // A non-owner cannot see the cached content (ownership-scoped).
    assert!(state.store.get_entry_content("i1", "intruder").await.unwrap().is_none());
}
