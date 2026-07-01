//! End-to-end tests for the `/admin` subtree over the in-memory store (NO database, NO network).
//!
//! Covers: the admin gate (403 for a non-admin, 200 for an admin), the blocklist add/remove +
//! the inbox rejection it drives (a blocked sender cannot follow), the remove-follower action, and
//! delete-any-note. Every state-changing POST is double-submit CSRF protected.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crier::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn admin_gate_blocklist_followers_and_delete() {
    let state = build_dev_state();

    // --- gate: a signed-in NON-admin cannot open the panel -> 403 ----------
    let (status, _) = call(&state, get_groups("/admin", "u_user", "readers,writers")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin -> 403");

    // no identity at all -> 403 (require_admin has no group)
    let (status, _) = call(&state, get("/admin")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "anonymous -> 403");

    // --- gate: an admin sees the panel -> 200 ------------------------------
    let (status, body) = call(&state, get_groups("/admin", "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::OK, "admin -> 200");
    assert!(body.contains("Blocklist"), "panel rendered");

    // infra-admins also authorizes.
    let (status, _) = call(&state, get_groups("/admin", "u_ia", "infra-admins")).await;
    assert_eq!(status, StatusCode::OK, "infra-admins -> 200");

    // --- a follower exists (via the public inbox) --------------------------
    let follow = r#"{"type":"Follow","id":"https://remote.example/act/1","actor":"https://remote.example/users/alice","object":"https://social.w33d.xyz/users/w33d"}"#;
    let (status, _) = call(&state, post_json("/users/w33d/inbox", follow)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 1, "alice follows");

    // --- mutation guards on /admin/block: non-admin -> 403, bad CSRF -> 401 -
    let form = "target=remote.example&kind=domain&csrf_token=".to_string() + CSRF;
    let (status, _) = call(&state, admin_post("/admin/block", &form, "u_user", "readers")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin block -> 403");

    let bad = "target=remote.example&kind=domain&csrf_token=WRONG".to_string();
    let (status, _) = call(&state, admin_post("/admin/block", &bad, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "block CSRF mismatch -> 401");

    // --- admin blocks the domain -------------------------------------------
    let (status, _) = call(&state, admin_post("/admin/block", &form, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "block -> 303");
    let (_, body) = call(&state, get_groups("/admin", "u_admin", "admins")).await;
    assert!(body.contains("remote.example"), "blocklist shows the domain");

    // --- the block rejects a new Follow from that domain at the inbox -------
    let follow2 = r#"{"type":"Follow","id":"https://remote.example/act/2","actor":"https://remote.example/users/bob","object":"https://social.w33d.xyz/users/w33d"}"#;
    let (status, _) = call(&state, post_json("/inbox", follow2)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "blocked domain cannot follow");
    // followers unchanged (still just alice)
    let (_, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 1, "blocked follow did not register");

    // --- admin unblocks; the domain can follow again -----------------------
    let unblock = "target=remote.example&csrf_token=".to_string() + CSRF;
    let (status, _) = call(&state, admin_post("/admin/unblock", &unblock, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "unblock -> 303");
    let (status, _) = call(&state, post_json("/inbox", follow2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "unblocked domain follows again");
    let (_, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 2, "bob now follows too");

    // --- admin removes a follower ------------------------------------------
    let rm = "actor=https%3A%2F%2Fremote.example%2Fusers%2Falice&csrf_token=".to_string() + CSRF;
    // non-admin cannot
    let (status, _) = call(&state, admin_post("/admin/followers/remove", &rm, "u_user", "x")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin remove-follower -> 403");
    // admin can
    let (status, _) = call(&state, admin_post("/admin/followers/remove", &rm, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "remove-follower -> 303");
    let (_, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 1, "alice removed");

    // --- delete-any-note: create a note as an ordinary user first ----------
    let note_form = "content=hello+admin+world&csrf_token=".to_string() + CSRF;
    let (status, _) = call(&state, admin_post("/api/notes", &note_form, "u_author", "")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "note created");
    let (_, body) = call(&state, get("/users/w33d/outbox")).await;
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    let note_url = ob["orderedItems"][0]["object"]["id"].as_str().unwrap();
    let note_id = note_url.rsplit('/').next().unwrap().to_string();

    // non-admin cannot delete-any
    let del = format!("id={note_id}&csrf_token={CSRF}");
    let (status, _) = call(&state, admin_post("/admin/notes/delete", &del, "u_user", "readers")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin delete -> 403");

    // admin deletes another user's note
    let (status, _) = call(&state, admin_post("/admin/notes/delete", &del, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "admin delete-any -> 303");
    let (_, body) = call(&state, get("/users/w33d/outbox")).await;
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ob["totalItems"], 0, "note deleted by admin");

    // deleting an already-gone note -> 404
    let (status, _) = call(&state, admin_post("/admin/notes/delete", &del, "u_admin", "admins")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "second delete -> 404");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &crier::AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_groups(uri: &str, sub: &str, groups: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", format!("{sub}@hf"))
        .header("x-auth-groups", groups)
        .body(Body::empty())
        .unwrap()
}

/// A urlencoded admin POST carrying the CSRF cookie + gateway identity (subject + groups).
fn admin_post(uri: &str, body: &str, sub: &str, groups: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", sub)
        .header("x-auth-email", format!("{sub}@hf"))
        .header("x-auth-groups", groups)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
