//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=crier \
//!   -p 127.0.0.1:55470:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/crier \
//!   cargo test --test pg_store -- --nocapture
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use crier::store::{Follower, Note, PgStore, Store};
use crier::{app, build_dev_state, now_secs, AppState};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");
    let pg = Arc::new(pg);

    // --- direct Store-trait round-trip: notes ------------------------------
    let now = now_secs();
    let note = Note {
        id: "note_pg_1".to_string(),
        author_sub: "u_w33d".to_string(),
        content: "from postgres".to_string(),
        visibility: "public".to_string(),
        created_at: now - 100,
    };
    pg.create_note(&note).await.expect("create note");

    // Duplicate id -> Conflict (the PRIMARY KEY guard).
    assert!(
        matches!(pg.create_note(&note).await, Err(crier::store::StoreError::Conflict(_))),
        "duplicate note id rejected"
    );

    let note2 = Note {
        id: "note_pg_2".to_string(),
        author_sub: "u_w33d".to_string(),
        content: "later".to_string(),
        visibility: "public".to_string(),
        created_at: now,
    };
    pg.create_note(&note2).await.expect("create note 2");

    let listed = pg.list_notes().await;
    assert!(listed.len() >= 2);
    assert_eq!(listed[0].id, "note_pg_2", "newest first");
    assert!(pg.count_notes().await >= 2);
    assert_eq!(pg.get_note("note_pg_1").await.unwrap().content, "from postgres");

    // --- followers: upsert keeps a resolved inbox --------------------------
    pg.add_follower(&Follower {
        actor: "https://remote.example/users/alice".to_string(),
        inbox_url: String::new(),
        created_at: now,
    })
    .await
    .expect("add follower (bare)");
    // Resolve the inbox.
    pg.add_follower(&Follower {
        actor: "https://remote.example/users/alice".to_string(),
        inbox_url: "https://remote.example/users/alice/inbox".to_string(),
        created_at: now,
    })
    .await
    .expect("add follower (resolved)");
    // A later bare re-Follow must NOT erase the resolved inbox.
    pg.add_follower(&Follower {
        actor: "https://remote.example/users/alice".to_string(),
        inbox_url: String::new(),
        created_at: now,
    })
    .await
    .expect("re-follow");

    let followers = pg.list_followers().await;
    assert_eq!(followers.len(), 1, "upsert, not duplicate");
    assert_eq!(
        followers[0].inbox_url, "https://remote.example/users/alice/inbox",
        "resolved inbox preserved across a bare re-Follow"
    );
    assert_eq!(pg.count_followers().await, 1);

    pg.remove_follower("https://remote.example/users/alice")
        .await
        .expect("remove follower");
    assert_eq!(pg.count_followers().await, 0);

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    // Create a note through the SSO+CSRF composer.
    let body = "content=via+http&csrf_token=tok";
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/notes")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, "__Host-csrf=tok")
                .header("x-auth-subject", "u_w33d")
                .header("x-auth-email", "w@holdfast.local")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Read it back through the PG-backed outbox.
    let resp = app(state.clone())
        .oneshot(Request::builder().uri("/users/w33d/outbox").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let ob: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let found = ob["orderedItems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["object"]["content"].as_str().unwrap_or("").contains("via http"));
    assert!(found, "note visible in PG-backed outbox");

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + note create/conflict/list/count + \
         follower upsert/inbox-preserve/remove + full compose->outbox HTTP flow against real Postgres"
    );
}
