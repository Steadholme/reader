//! End-to-end HTTP flow for the wave-7 Social surfaces (in-memory store, no network):
//! hashtags + tag pages, boosts (store + timeline render + un-boost), and list membership filtering.
//!
//! Drives the real `app` router via `tower::oneshot`, seeding remote home-timeline notes directly
//! through the public `Store` trait (as the inbox would) and exercising the CSRF authoring paths.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crier::store::{Following, HomeNote};
use crier::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";
const OWNER: &str = "u_w33d";
const EMAIL: &str = "w@hf";

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get_auth(uri: &str) -> Request<Body> {
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

async fn seed_home_note(state: &AppState, actor: &str, id: &str, content: &str) {
    state
        .store
        .add_following(&Following {
            actor: actor.into(),
            inbox_url: String::new(),
            created_at: now_secs(),
        })
        .await
        .unwrap();
    state
        .store
        .add_home_note(&HomeNote {
            id: id.into(),
            actor: actor.into(),
            content: content.into(),
            url: id.into(),
            published: 0,
            in_reply_to: String::new(),
            received_at: now_secs(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn hashtags_parse_render_and_tag_page() {
    let state = build_dev_state();

    // Compose a note carrying two distinct hashtags (with a duplicate + case variation).
    let body = format!("content=loving+%23Rust+and+%23rust+and+%23WebDev&csrf_token={CSRF}");
    let (status, _) = call(&state, post("/api/notes", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Stored lower-cased + deduped.
    let notes = state.store.list_notes().await;
    assert_eq!(notes.len(), 1);
    let with_rust = state.store.notes_with_tag("rust").await;
    assert_eq!(with_rust.len(), 1, "note is indexed under #rust");
    assert_eq!(state.store.notes_with_tag("webdev").await.len(), 1);
    let top = state.store.top_tags(10).await;
    assert!(top.iter().any(|(t, c)| t == "rust" && *c == 1));

    // The timeline linkifies hashtags and renders the Tags section.
    let (status, timeline) = call(&state, get_auth("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        timeline.contains(r#"href="/tags/rust""#),
        "hashtag linkified"
    );
    assert!(timeline.contains(r#"href="/tags/webdev""#));
    assert!(timeline.contains(">Tags<"), "Tags section header present");

    // The tag page lists the note; an unused tag shows the empty state.
    let (status, page) = call(&state, get_auth("/tags/rust")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("loving"), "note shown on its tag page");
    let (_, empty) = call(&state, get_auth("/tags/nope")).await;
    assert!(empty.contains("No posts with this tag"));

    // A hashtag-shaped XSS attempt is still escaped (the tag scanner never emits raw markup).
    let body = format!("content=x+%23tag+%3Cscript%3Ealert(1)%3C%2Fscript%3E&csrf_token={CSRF}");
    let (status, _) = call(&state, post("/api/notes", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, timeline) = call(&state, get_auth("/")).await;
    assert!(!timeline.contains("<script>alert(1)"), "script escaped");
    assert!(timeline.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn boost_store_render_and_unboost() {
    let state = build_dev_state();
    seed_home_note(
        &state,
        "https://remote.example/users/alice",
        "https://remote.example/notes/1",
        "hello from alice",
    )
    .await;

    // The home timeline offers a Boost control for the note.
    let (status, home) = call(&state, get_auth("/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(home.contains("hello from alice"));
    assert!(home.contains("Boost"), "boost control present");

    // Boost it (from the home page).
    let body =
        format!("csrf_token={CSRF}&note_uri=https%3A%2F%2Fremote.example%2Fnotes%2F1&from=home");
    let (status, _) = call(&state, post("/api/boost", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        state
            .store
            .is_boosted("https://remote.example/notes/1")
            .await
    );
    assert_eq!(state.store.list_boosts().await.len(), 1);

    // The boost appears in the profile timeline, attributed as boosted.
    let (status, timeline) = call(&state, get_auth("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(timeline.contains("Boosted"), "boost attribution rendered");
    assert!(
        timeline.contains("hello from alice"),
        "boosted content rendered"
    );
    assert!(timeline.contains("note--boost"));

    // Re-boosting is idempotent (still one boost).
    let (status, _) = call(&state, post("/api/boost", &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(state.store.list_boosts().await.len(), 1);

    // The home page now offers Un-boost for the same note.
    let (_, home) = call(&state, get_auth("/home")).await;
    assert!(
        home.contains("Un-boost"),
        "un-boost control shown once boosted"
    );

    // Un-boost removes it from the store + timeline.
    let unbody =
        format!("csrf_token={CSRF}&note_uri=https%3A%2F%2Fremote.example%2Fnotes%2F1&from=home");
    let (status, _) = call(&state, post("/api/unboost", &unbody)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        !state
            .store
            .is_boosted("https://remote.example/notes/1")
            .await
    );
    let (_, timeline) = call(&state, get_auth("/")).await;
    assert!(
        !timeline.contains("Boosted"),
        "un-boosted note gone from timeline"
    );

    // Boosting a note we do not have -> 404 (no snapshot to store).
    let bad = format!(
        "csrf_token={CSRF}&note_uri=https%3A%2F%2Fremote.example%2Fnotes%2Fghost&from=home"
    );
    let (status, _) = call(&state, post("/api/boost", &bad)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // CSRF guard on boost.
    let (status, _) = call(&state, post("/api/boost", "csrf_token=WRONG&note_uri=x")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_membership_filters_the_timeline() {
    let state = build_dev_state();
    let alice = "https://remote.example/users/alice";
    let bob = "https://remote.example/users/bob";
    seed_home_note(
        &state,
        alice,
        "https://remote.example/notes/a1",
        "alice speaks",
    )
    .await;
    seed_home_note(&state, bob, "https://remote.example/notes/b1", "bob speaks").await;

    // Create a list.
    let (status, _) = call(
        &state,
        post("/lists", &format!("csrf_token={CSRF}&name=Rustaceans")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let lists = state.store.list_lists(OWNER).await;
    assert_eq!(lists.len(), 1);
    let lid = lists[0].id.clone();

    // Add alice (only) as a member.
    let (status, _) = call(
        &state,
        post(
            &format!("/lists/{lid}/members"),
            &format!("csrf_token={CSRF}&actor=https%3A%2F%2Fremote.example%2Fusers%2Falice"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        state.store.list_members(&lid).await,
        vec![alice.to_string()]
    );

    // The list timeline shows only alice's note.
    let (status, page) = call(&state, get_auth(&format!("/lists/{lid}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("alice speaks"), "member note shown");
    assert!(!page.contains("bob speaks"), "non-member note hidden");

    // A foreign owner cannot see the list.
    let foreign = Request::builder()
        .uri(format!("/lists/{lid}"))
        .header("x-auth-subject", "u_intruder")
        .header("x-auth-email", "x@hf")
        .body(Body::empty())
        .unwrap();
    let (status, _) = call(&state, foreign).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "list is owner-scoped");

    // Remove the member: the timeline empties.
    let (status, _) = call(
        &state,
        post(
            &format!("/lists/{lid}/members/remove"),
            &format!("csrf_token={CSRF}&actor=https%3A%2F%2Fremote.example%2Fusers%2Falice"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = call(&state, get_auth(&format!("/lists/{lid}"))).await;
    assert!(!page.contains("alice speaks"), "removed member's note gone");

    // Delete the list -> its detail page 404s.
    let (status, _) = call(
        &state,
        post(
            &format!("/lists/{lid}/delete"),
            &format!("csrf_token={CSRF}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _) = call(&state, get_auth(&format!("/lists/{lid}"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn notifications_and_thread_view_track_replies_mentions_boosts_and_follows() {
    let state = build_dev_state();

    // Establish the owner subject with a local note.
    let (status, _) = call(
        &state,
        post(
            "/api/notes",
            &format!("content=root+post&csrf_token={CSRF}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let local = state.store.list_notes().await.remove(0);
    let local_uri = state.config.note_url(&local.id);
    let alice = "https://remote.example/users/alice";

    // Follow alice so her reply is stored in home_notes and can render in the thread.
    state
        .store
        .add_following(&Following {
            actor: alice.to_string(),
            inbox_url: String::new(),
            created_at: now_secs(),
        })
        .await
        .unwrap();

    let reply = serde_json::json!({
        "type": "Create",
        "actor": alice,
        "object": {
            "type": "Note",
            "id": "https://remote.example/notes/reply-1",
            "content": "reply from alice",
            "url": "https://remote.example/@alice/reply-1",
            "inReplyTo": local_uri,
            "published": "2026-07-01T10:00:00Z"
        }
    })
    .to_string();
    let (status, _) = call(&state, post_json("/inbox", &reply)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let announce = serde_json::json!({
        "type": "Announce",
        "actor": alice,
        "object": local_uri
    })
    .to_string();
    let (status, _) = call(&state, post_json("/inbox", &announce)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let mention = serde_json::json!({
        "type": "Create",
        "actor": "https://remote.example/users/bob",
        "object": {
            "type": "Note",
            "id": "https://remote.example/notes/mention-1",
            "content": "hello @w33d@social.w33d.xyz",
            "tag": [{
                "type": "Mention",
                "href": "https://social.w33d.xyz/users/w33d",
                "name": "@w33d@social.w33d.xyz"
            }]
        }
    })
    .to_string();
    let (status, _) = call(&state, post_json("/inbox", &mention)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let follow = serde_json::json!({
        "type": "Follow",
        "actor": "https://remote.example/users/carol",
        "object": "https://social.w33d.xyz/users/w33d"
    })
    .to_string();
    let (status, _) = call(&state, post_json("/users/w33d/inbox", &follow)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let notifications = state.store.list_notifications(OWNER).await;
    assert_eq!(notifications.len(), 4);
    assert!(notifications.iter().any(|n| n.kind == "reply"));
    assert!(notifications.iter().any(|n| n.kind == "boost"));
    assert!(notifications.iter().any(|n| n.kind == "mention"));
    assert!(notifications.iter().any(|n| n.kind == "follow"));
    assert_eq!(state.store.count_unread_notifications(OWNER).await, 4);

    let (status, page) = call(&state, get_auth("/notifications")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("4 unread"),
        "unread badge shown before mark-read"
    );
    assert!(page.contains("Reply"));
    assert!(page.contains("Boost"));
    assert!(page.contains("Mention"));
    assert!(page.contains("Follow"));
    assert_eq!(
        state.store.count_unread_notifications(OWNER).await,
        0,
        "view marks notifications read"
    );

    let (status, thread) = call(&state, get_auth(&format!("/thread/{}", local.id))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(thread.contains("root post"), "thread contains local note");
    assert!(
        thread.contains("reply from alice"),
        "thread contains direct remote reply"
    );
    assert!(
        thread.contains("In reply to"),
        "reply context link rendered"
    );

    let (status, timeline) = call(&state, get_auth("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(timeline.contains(&format!(r#"href="/thread/{}""#, local.id)));
}

#[tokio::test]
async fn blocks_and_mutes_filter_home_and_reject_blocked_inbox_activity() {
    let state = build_dev_state();
    let alice = "https://remote.example/users/alice";
    let bob = "https://remote.example/users/bob";
    seed_home_note(
        &state,
        alice,
        "https://remote.example/notes/a-filter",
        "alice visible",
    )
    .await;
    seed_home_note(
        &state,
        bob,
        "https://remote.example/notes/b-filter",
        "bob visible",
    )
    .await;

    let (status, home) = call(&state, get_auth("/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(home.contains("alice visible"));
    assert!(home.contains("bob visible"));

    let (status, _) = call(
        &state,
        post(
            "/blocks/mute",
            &format!("csrf_token={CSRF}&actor=https%3A%2F%2Fremote.example%2Fusers%2Falice"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, home) = call(&state, get_auth("/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !home.contains("alice visible"),
        "muted actor hidden from home"
    );
    assert!(
        home.contains("bob visible"),
        "unmuted actor remains visible"
    );

    let (status, blocks) = call(&state, get_auth("/blocks")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(blocks.contains(alice), "mute appears on management page");

    let (status, _) = call(
        &state,
        post(
            "/blocks/block",
            &format!("csrf_token={CSRF}&actor=https%3A%2F%2Fremote.example%2Fusers%2Fbob"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        state.store.is_blocked(bob).await,
        "user block feeds inbox gate"
    );

    let (status, home) = call(&state, get_auth("/home")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !home.contains("bob visible"),
        "blocked actor hidden from home"
    );

    let create = serde_json::json!({
        "type": "Create",
        "actor": bob,
        "object": {
            "type": "Note",
            "id": "https://remote.example/notes/blocked",
            "content": "blocked delivery"
        }
    })
    .to_string();
    let (status, _) = call(&state, post_json("/inbox", &create)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "blocked actor rejected at inbox"
    );

    let (status, _) = call(
        &state,
        post(
            "/blocks/mute",
            "csrf_token=WRONG&actor=https%3A%2F%2Fremote.example%2Fusers%2Feve",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "CSRF guards actor filters"
    );

    let (status, _) = call(
        &state,
        post(
            "/blocks/unmute",
            &format!("csrf_token={CSRF}&actor=https%3A%2F%2Fremote.example%2Fusers%2Falice"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, home) = call(&state, get_auth("/home")).await;
    assert!(
        home.contains("alice visible"),
        "unmuting restores home visibility"
    );
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
