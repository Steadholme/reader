//! End-to-end HTTP flow over the in-memory store (NO database, NO network).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the SSO/CSRF guards on composing, the public WebFinger/actor/outbox correctness, note
//! creation + timeline rendering + XSS escaping, the dereferenceable Note object, and the inbox
//! Follow -> followers-collection / Undo path.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crier::{app, build_dev_state};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

#[tokio::test]
async fn full_microblog_and_activitypub_flow() {
    let state = build_dev_state();

    // --- health ------------------------------------------------------------
    let (status, _, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);

    // --- WebFinger resolves the configured handle --------------------------
    let (status, ct, body) = call(
        &state,
        get("/.well-known/webfinger?resource=acct:w33d@social.w33d.xyz"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.contains("application/activity+json"), "AP content type");
    let wf: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(wf["subject"], "acct:w33d@social.w33d.xyz");
    assert_eq!(wf["links"][0]["href"], "https://social.w33d.xyz/users/w33d");

    // Unknown handle -> 404.
    let (status, _, _) = call(
        &state,
        get("/.well-known/webfinger?resource=acct:nobody@social.w33d.xyz"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- Actor document ----------------------------------------------------
    let (status, ct, body) = call(&state, get("/users/w33d")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.contains("application/activity+json"));
    let actor: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(actor["type"], "Person");
    assert_eq!(actor["id"], "https://social.w33d.xyz/users/w33d");
    assert_eq!(actor["inbox"], "https://social.w33d.xyz/users/w33d/inbox");
    assert_eq!(actor["outbox"], "https://social.w33d.xyz/users/w33d/outbox");

    // Wrong actor name -> 404.
    let (status, _, _) = call(&state, get("/users/someoneelse")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- empty outbox ------------------------------------------------------
    let (status, _, body) = call(&state, get("/users/w33d/outbox")).await;
    assert_eq!(status, StatusCode::OK);
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ob["type"], "OrderedCollection");
    assert_eq!(ob["totalItems"], 0);

    // --- compose guards: no identity -> 401 --------------------------------
    let form = "content=hi&csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(&state, post_csrf("/api/notes", &form, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // bad CSRF -> 401
    let form = "content=hi&csrf_token=WRONG".to_string();
    let (status, _, _) = call(&state, post_csrf("/api/notes", &form, Some(("u_w33d", "w@hf")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- create a note (with an XSS attempt in the body) -------------------
    let form = "content=hello+%3Cscript%3Ealert(1)%3C%2Fscript%3E+world&csrf_token=".to_string() + CSRF;
    let resp = app(state.clone())
        .oneshot(post_csrf("/api/notes", &form, Some(("u_w33d", "w@hf"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // --- timeline renders it, escaped --------------------------------------
    let (status, _, body) = call(&state, get_auth("/", "u_w33d", "w@hf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hello"), "note shown on timeline");
    assert!(!body.contains("<script>alert(1)"), "raw script must be escaped");
    assert!(body.contains("&lt;script&gt;"), "script shown as escaped text");

    // --- outbox now has one Create wrapping a Note -------------------------
    let (status, _, body) = call(&state, get("/users/w33d/outbox")).await;
    assert_eq!(status, StatusCode::OK);
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ob["totalItems"], 1);
    let item = &ob["orderedItems"][0];
    assert_eq!(item["type"], "Create");
    assert_eq!(item["object"]["type"], "Note");
    let note_id = item["object"]["id"].as_str().unwrap().to_string();
    assert!(note_id.starts_with("https://social.w33d.xyz/users/w33d/notes/note_"));
    // The note content is HTML-escaped inside a <p>.
    let content = item["object"]["content"].as_str().unwrap();
    assert!(content.contains("&lt;script&gt;"));
    assert!(!content.contains("<script>"));

    // --- the Note object is dereferenceable --------------------------------
    let path = note_id.strip_prefix("https://social.w33d.xyz").unwrap();
    let (status, ct, body) = call(&state, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.contains("application/activity+json"));
    let obj: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(obj["type"], "Note");
    assert_eq!(obj["@context"], "https://www.w3.org/ns/activitystreams");

    // --- inbox: a Follow registers the follower ----------------------------
    let follow = r#"{"type":"Follow","id":"https://remote.example/activities/1","actor":"https://remote.example/users/alice","object":"https://social.w33d.xyz/users/w33d"}"#;
    let (status, _, _) = call(&state, post_json("/users/w33d/inbox", follow)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "Follow accepted");

    let (status, _, body) = call(&state, get("/users/w33d/followers")).await;
    assert_eq!(status, StatusCode::OK);
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 1);
    assert_eq!(fc["orderedItems"][0], "https://remote.example/users/alice");

    // --- inbox: an Undo removes the follower -------------------------------
    let undo = r#"{"type":"Undo","actor":"https://remote.example/users/alice","object":{"type":"Follow","actor":"https://remote.example/users/alice","object":"https://social.w33d.xyz/users/w33d"}}"#;
    let (status, _, _) = call(&state, post_json("/users/w33d/inbox", undo)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, _, body) = call(&state, get("/users/w33d/followers")).await;
    let fc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fc["totalItems"], 0, "follower removed");

    // --- inbox: malformed JSON -> 400 --------------------------------------
    let (status, _, _) = call(&state, post_json("/inbox", "not json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- inbox: shared inbox accepts a Create best-effort ------------------
    let create = r#"{"type":"Create","actor":"https://remote.example/users/bob","object":{"type":"Note","content":"hi"}}"#;
    let (status, _, _) = call(&state, post_json("/inbox", create)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &crier::AppState, req: Request<Body>) -> (StatusCode, String, String) {
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

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
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

/// Build an ActivityPub POST with a JSON body (no identity — the inbox is public).
fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/activity+json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
