//! End-to-end coverage for the additive deepening: cross-source story dedup in the river and the
//! extractive item-summary API. DB-free (in-memory store), driving the real `app` Router via
//! `tower::oneshot` exactly as Sluice would (injected `X-Auth-*` headers).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use current::model::{Feed, Item};
use current::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const OWNER: &str = "u_test";
const EMAIL: &str = "test@holdfast.local";

fn feed(id: &str, owner: &str, url: &str, title: &str) -> Feed {
    Feed {
        id: id.into(),
        owner_sub: owner.into(),
        url: url.into(),
        title: title.into(),
        last_fetched: None,
        created_at: now_secs(),
    }
}

fn item(id: &str, feed_id: &str, guid: &str, title: &str, summary: &str) -> Item {
    Item {
        id: id.into(),
        feed_id: feed_id.into(),
        guid: guid.into(),
        title: title.into(),
        link: "https://example.com/x".into(),
        summary: summary.into(),
        published_at: Some(now_secs()),
        read: false,
        full_text: None,
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
async fn river_collapses_same_story_across_feeds() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://globe.example/rss", "The Globe")).await.unwrap();
    state.store.add_feed(&feed("f2", OWNER, "https://times.example/rss", "The Times")).await.unwrap();
    // Same story, two outlets.
    state.store.upsert_item(&item("i1", "f1", "g1", "Mars rover discovers water on the planet", "huge find")).await.unwrap();
    state.store.upsert_item(&item("i2", "f2", "g2", "Rover finds water on Mars planet surface", "report")).await.unwrap();
    // Unrelated story.
    state.store.upsert_item(&item("i3", "f1", "g3", "Local football team wins championship final", "great game")).await.unwrap();

    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);

    // The cluster is collapsed: one "Also in" disclosure naming the second feed.
    assert!(html.contains("Also in 1 feed"), "expected an 'Also in N feed' label");
    assert!(html.contains("The Times"), "the other source feed title is listed");
    // The unrelated story stays its own entry.
    assert!(html.contains("championship"));
    // Exactly two top-level entries are rendered (Mars cluster + football), not three.
    assert_eq!(html.matches("class=\"entry\"").count(), 2, "duplicate story folded into one entry");
}

#[tokio::test]
async fn single_feed_river_is_unchanged_no_also_block() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss", "Solo")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "g1", "A unique standalone headline", "short")).await.unwrap();

    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("standalone headline"));
    // A standalone, short item gets neither the dedup disclosure nor a TL;DR. (The class names
    // live in the inlined CSS, so assert on the rendered markup/text instead.)
    assert!(!html.contains("Also in "));
    assert!(!html.contains("<details class=\"entry__also\""));
    assert!(!html.contains("<span class=\"tldr-tag\">"));
}

#[tokio::test]
async fn long_item_shows_inline_tldr() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss", "Science Daily")).await.unwrap();
    let body_text = "Scientists confirmed the Mars rover found water. \
                     The weather that week was unremarkable and mild. \
                     The water discovery on Mars thrilled the rover science team.";
    state.store.upsert_item(&item("i1", "f1", "g1", "Mars rover water discovery", body_text)).await.unwrap();

    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<span class=\"tldr-tag\">TL;DR</span>"), "multi-sentence item gets an inline TL;DR");
    // The salient water sentence is surfaced; the weather filler is dropped from the TL;DR.
    assert!(html.contains("Scientists confirmed"));
}

#[tokio::test]
async fn summary_api_returns_extractive_json() {
    let state = build_dev_state();
    state.store.add_feed(&feed("f1", OWNER, "https://ex.com/rss", "Daily")).await.unwrap();
    let body_text = "Scientists confirmed the Mars rover found water. \
                     The weather that week was mild. \
                     The water discovery on Mars thrilled the rover team.";
    state.store.upsert_item(&item("i1", "f1", "g1", "Mars rover water", body_text)).await.unwrap();

    let (status, body) = call(&state, get("/api/item/i1/summary")).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["id"], "i1");
    assert_eq!(v["source"], "extractive");
    assert!(v["sentences"].as_array().unwrap().len() <= 2);
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.to_lowercase().contains("water"), "summary keeps the salient topic");
    // The mild-weather filler sentence is not the strongest signal.
    assert!(!summary.contains("mild"));
}

#[tokio::test]
async fn summary_api_foreign_item_is_not_found() {
    let state = build_dev_state();
    // Item owned by someone else.
    state.store.add_feed(&feed("f1", "other", "https://ex.com/rss", "Theirs")).await.unwrap();
    state.store.upsert_item(&item("i1", "f1", "g1", "Secret headline body here", "x")).await.unwrap();

    let (status, _) = call(&state, get("/api/item/i1/summary")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
