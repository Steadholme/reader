//! HTTP-Signature + remote-follow / home-timeline flow (NO database, NO network).
//!
//! Drives the real `app` router via `tower::oneshot`. Covers: the actor document now publishing its
//! `publicKey`; inbox signature enforcement (`CRIER_VERIFY_INBOX` on -> unsigned/invalid POST 401);
//! and following a remote actor -> a delivered Create landing in the `/home` timeline (only for a
//! followed sender). The crypto correctness of the signing string + sign/verify round-trip lives in
//! the `httpsig` unit tests.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crier::audit::AuditSink;
use crier::config::Config;
use crier::store::InMemoryStore;
use crier::{app, build_dev_state, federation, httpsig, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

/// Build an in-memory AppState with an explicit `verify_inbox` setting (dev defaults otherwise).
fn state_with(verify_inbox: bool) -> AppState {
    let mut cfg = Config::dev();
    cfg.verify_inbox = verify_inbox;
    let cfg = Arc::new(cfg);
    let kp = httpsig::generate_keypair().expect("keygen");
    let signer =
        Arc::new(httpsig::Signer::load(cfg.key_id(), &kp.private_pem, kp.public_pem).expect("signer"));
    AppState {
        config: cfg,
        store: Arc::new(InMemoryStore::new()),
        http: federation::build_http_client(),
        audit: AuditSink::disabled(),
        signer,
        klaxon: None,
    }
}

#[tokio::test]
async fn actor_document_publishes_public_key() {
    let state = build_dev_state();
    let (status, ct, body) = call(&state, get("/users/w33d")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.contains("application/activity+json"));
    let actor: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(actor["publicKey"]["id"], "https://social.w33d.xyz/users/w33d#main-key");
    assert_eq!(actor["publicKey"]["owner"], "https://social.w33d.xyz/users/w33d");
    let pem = actor["publicKey"]["publicKeyPem"].as_str().unwrap();
    assert!(pem.contains("BEGIN PUBLIC KEY"), "SPKI PEM published");
}

#[tokio::test]
async fn inbox_rejects_unsigned_when_verification_enabled() {
    let state = state_with(true);

    // Unsigned Follow -> 401 (no Signature header at all).
    let follow = r#"{"type":"Follow","id":"https://remote.example/activities/1","actor":"https://remote.example/users/alice","object":"https://social.w33d.xyz/users/w33d"}"#;
    let (status, _, _) = call(&state, post_json("/inbox", follow)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unsigned POST -> 401");

    // A Signature naming an unfetchable key (offline) is also rejected — verification cannot pass.
    let signed_but_unfetchable = post_json_signed(
        "/inbox",
        follow,
        "keyId=\"https://remote.example/users/alice#main-key\",headers=\"(request-target) host date\",signature=\"AAAA\"",
    );
    let (status, _, _) = call(&state, signed_but_unfetchable).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unverifiable signature -> 401");

    // The follower was NOT recorded (the activity was rejected before processing).
    let (_, _, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 0, "rejected Follow never registered");
}

#[tokio::test]
async fn follow_remote_records_home_timeline_notes() {
    // Verification off (the network-free default): the home path is exercised without a key fetch.
    let state = state_with(false);

    // Follow a remote actor by URL (recorded synchronously so the home timeline gates correctly).
    let form = "target=https://remote.example/users/bob&csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(
        &state,
        post_csrf("/api/follow", &form, Some(("u_w33d", "w@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "follow -> 303 redirect to /home");

    // A Create from the followed actor lands in the home timeline.
    let create = r#"{"type":"Create","actor":"https://remote.example/users/bob","object":{"type":"Note","id":"https://remote.example/notes/1","content":"<p>hi from bob</p>","url":"https://remote.example/@bob/1","published":"2026-06-30T12:00:00Z"}}"#;
    let (status, _, _) = call(&state, post_json("/inbox", create)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // A Create from someone we do NOT follow is ignored by the home timeline.
    let other = r#"{"type":"Create","actor":"https://remote.example/users/eve","object":{"type":"Note","id":"https://remote.example/notes/99","content":"<p>spam</p>"}}"#;
    let (status, _, _) = call(&state, post_json("/inbox", other)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // /home shows bob's note (escaped), attributed to bob, and NOT eve's.
    let (status, _, body) = call(&state, get_auth("/home", "u_w33d", "w@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hi from bob"), "followed note shown");
    assert!(body.contains("remote.example/users/bob"), "attributed to sender");
    assert!(!body.contains("<p>hi from bob</p>"), "remote HTML is escaped, not rendered raw");
    assert!(!body.contains("spam"), "non-followed sender's note excluded");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, ct, String::from_utf8_lossy(&bytes).to_string())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json_signed(uri: &str, body: &str, signature: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .header("Signature", signature)
        .body(Body::from(body.to_string()))
        .unwrap()
}
