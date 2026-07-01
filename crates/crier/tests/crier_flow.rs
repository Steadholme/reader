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

    // The note's bare id (last path segment) is what the /api/notes/{id} routes take; the
    // /users/... URL is only for dereferencing the Note object.
    let raw_id = note_id.rsplit('/').next().unwrap().to_string();
    let deref_path = note_id.strip_prefix("https://social.w33d.xyz").unwrap();

    // --- edit guards: a different subject cannot edit -> 404 ---------------
    let edit_form = "content=edited+by+stranger&csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/edit"), &edit_form, Some(("u_intruder", "x@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-owner edit -> 404");
    // The intruder's attempt left the content untouched.
    let (_, _, body) = call(&state, get(deref_path)).await;
    let obj: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(obj["content"].as_str().unwrap().contains("hello"), "content unchanged by intruder");

    // bad CSRF on edit -> 401
    let (status, _, _) = call(
        &state,
        post_csrf(
            &format!("/api/notes/{raw_id}/edit"),
            "content=x&csrf_token=WRONG",
            Some(("u_w33d", "w@hf")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "edit CSRF mismatch -> 401");

    // no identity on edit -> 401
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/edit"), "content=x&csrf_token=", None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "edit without identity -> 401");

    // --- owner edits the note ---------------------------------------------
    let edit_form = "content=hello+again+%3Cb%3Ebold%3C%2Fb%3E&csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/edit"), &edit_form, Some(("u_w33d", "w@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "owner edit -> 303");

    // The Note object now shows the revised (escaped) content + an `updated` timestamp.
    let (_, _, body) = call(&state, get(deref_path)).await;
    let obj: serde_json::Value = serde_json::from_str(&body).unwrap();
    let content = obj["content"].as_str().unwrap();
    assert!(content.contains("hello again"), "edit reflected");
    assert!(content.contains("&lt;b&gt;"), "edit content still escaped");
    assert!(!content.contains("<b>"), "no raw markup survives");
    assert!(obj["updated"].is_string(), "edited note advertises `updated`");

    // The timeline shows the revised content + an edited marker, still escaped.
    let (_, _, body) = call(&state, get_auth("/", "u_w33d", "w@hf")).await;
    assert!(body.contains("hello again"), "timeline shows edit");
    assert!(body.contains("edited"), "timeline shows edited marker");
    assert!(!body.contains("<b>bold</b>"), "timeline edit escaped");

    // --- delete guards: a different subject cannot delete -> 404 -----------
    let del_form = "csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/delete"), &del_form, Some(("u_intruder", "x@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-owner delete -> 404");
    // Still there after the intruder's failed delete.
    let (status, _, _) = call(&state, get(deref_path)).await;
    assert_eq!(status, StatusCode::OK, "note survives non-owner delete");

    // bad CSRF on delete -> 401
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/delete"), "csrf_token=WRONG", Some(("u_w33d", "w@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "delete CSRF mismatch -> 401");

    // --- owner deletes the note -------------------------------------------
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/delete"), &del_form, Some(("u_w33d", "w@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "owner delete -> 303");

    // The note is gone: dereference -> 404, outbox back to empty.
    let (status, _, _) = call(&state, get(deref_path)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted note not dereferenceable");
    let (_, _, body) = call(&state, get("/users/w33d/outbox")).await;
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ob["totalItems"], 0, "outbox empty after delete");

    // Deleting an already-gone note -> 404.
    let (status, _, _) = call(
        &state,
        post_csrf(&format!("/api/notes/{raw_id}/delete"), &del_form, Some(("u_w33d", "w@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "second delete -> 404");

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

    // --- media attachment: compose a note with an image URL ----------------
    let form = "content=look+at+this&attachment_url=https%3A%2F%2Faperture.w33d.xyz%2Fs%2Fpic.png&csrf_token="
        .to_string()
        + CSRF;
    let (status, _, _) = call(&state, post_csrf("/api/notes", &form, Some(("u_w33d", "w@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "note-with-attachment created");

    // The timeline renders the image inline (escaped src).
    let (_, _, body) = call(&state, get_auth("/", "u_w33d", "w@hf")).await;
    assert!(
        body.contains(r#"src="https://aperture.w33d.xyz/s/pic.png""#),
        "attachment image rendered on timeline"
    );

    // The outbox Note carries an `attachment` Document (mediaType + url).
    let (_, _, body) = call(&state, get("/users/w33d/outbox")).await;
    let ob: serde_json::Value = serde_json::from_str(&body).unwrap();
    let found = ob["orderedItems"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|i| {
            let att = &i["object"]["attachment"][0];
            (att["url"] == "https://aperture.w33d.xyz/s/pic.png").then(|| att.clone())
        })
        .expect("a Note with the attachment Document is in the outbox");
    assert_eq!(found["type"], "Document");
    assert_eq!(found["mediaType"], "image/png");

    // A non-http(s) attachment URL is rejected (blocks javascript:/data: injection) -> 400.
    let form = "content=evil&attachment_url=javascript%3Aalert(1)&csrf_token=".to_string() + CSRF;
    let (status, _, _) = call(&state, post_csrf("/api/notes", &form, Some(("u_w33d", "w@hf")))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "javascript: attachment rejected");

    // --- profile images: set avatar (icon) + header (image) ----------------
    // Guard: no identity -> 401.
    let (status, _, _) = call(
        &state,
        post_csrf("/api/profile", &format!("avatar_url=&header_url=&csrf_token={CSRF}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "profile without identity -> 401");

    // Bad CSRF -> 401.
    let (status, _, _) = call(
        &state,
        post_csrf(
            "/api/profile",
            "avatar_url=&header_url=&csrf_token=WRONG",
            Some(("u_w33d", "w@hf")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "profile CSRF mismatch -> 401");

    // A non-http(s) avatar URL -> 400.
    let (status, _, _) = call(
        &state,
        post_csrf(
            "/api/profile",
            &format!("avatar_url=data%3Aimage%2Fpng&header_url=&csrf_token={CSRF}"),
            Some(("u_w33d", "w@hf")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "data: avatar rejected");

    // Valid set -> 303.
    let prof = "avatar_url=https%3A%2F%2Faperture.w33d.xyz%2Fs%2Favatar.jpg\
                &header_url=https%3A%2F%2Faperture.w33d.xyz%2Fs%2Fbanner.png&csrf_token="
        .to_string()
        + CSRF;
    let (status, _, _) = call(&state, post_csrf("/api/profile", &prof, Some(("u_w33d", "w@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "profile set -> 303");

    // The public Actor document surfaces the avatar as `icon` and header as `image`.
    let (_, _, body) = call(&state, get("/users/w33d")).await;
    let actor: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(actor["icon"]["type"], "Image");
    assert_eq!(actor["icon"]["url"], "https://aperture.w33d.xyz/s/avatar.jpg");
    assert_eq!(actor["icon"]["mediaType"], "image/jpeg");
    assert_eq!(actor["image"]["type"], "Image");
    assert_eq!(actor["image"]["url"], "https://aperture.w33d.xyz/s/banner.png");
    assert_eq!(actor["image"]["mediaType"], "image/png");

    // The timeline shows the avatar + banner images.
    let (_, _, body) = call(&state, get_auth("/", "u_w33d", "w@hf")).await;
    assert!(body.contains("profile__avatar"), "avatar rendered on timeline");
    assert!(
        body.contains(r#"src="https://aperture.w33d.xyz/s/avatar.jpg""#),
        "avatar src on timeline"
    );
    assert!(body.contains("profile__banner"), "header banner rendered on timeline");

    // Clearing the header (empty field) removes `image` from the Actor JSON.
    let prof = "avatar_url=https%3A%2F%2Faperture.w33d.xyz%2Fs%2Favatar.jpg&header_url=&csrf_token="
        .to_string()
        + CSRF;
    let (status, _, _) = call(&state, post_csrf("/api/profile", &prof, Some(("u_w33d", "w@hf")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, _, body) = call(&state, get("/users/w33d")).await;
    let actor: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(actor["icon"]["url"], "https://aperture.w33d.xyz/s/avatar.jpg");
    assert!(actor.get("image").is_none(), "cleared header removes actor image");
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
