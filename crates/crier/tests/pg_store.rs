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
use crier::store::{Boost, Follower, HomeNote, List, Note, PgStore, Profile, Store};
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
        in_reply_to: String::new(),
        updated_at: 0,
        attachment_url: "https://aperture.w33d.xyz/s/pg.png".to_string(),
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
        in_reply_to: String::new(),
        updated_at: 0,
        attachment_url: String::new(),
    };
    pg.create_note(&note2).await.expect("create note 2");

    let listed = pg.list_notes().await;
    assert!(listed.len() >= 2);
    assert_eq!(listed[0].id, "note_pg_2", "newest first");
    assert!(pg.count_notes().await >= 2);
    assert_eq!(pg.get_note("note_pg_1").await.unwrap().content, "from postgres");
    // The nullable image attachment round-trips (set on note 1, NULL/"" on note 2).
    assert_eq!(
        pg.get_note("note_pg_1").await.unwrap().attachment_url,
        "https://aperture.w33d.xyz/s/pg.png"
    );
    assert_eq!(pg.get_note("note_pg_2").await.unwrap().attachment_url, "");

    // --- profile images: default empty, upsert, and clear --------------------
    let p0 = pg.get_profile().await;
    assert_eq!(p0.avatar_url, "", "profile avatar defaults empty");
    assert_eq!(p0.header_url, "", "profile header defaults empty");
    pg.set_profile(&Profile {
        avatar_url: "https://aperture.w33d.xyz/s/a.png".to_string(),
        header_url: "https://aperture.w33d.xyz/s/h.jpg".to_string(),
    })
    .await
    .expect("set profile");
    let p1 = pg.get_profile().await;
    assert_eq!(p1.avatar_url, "https://aperture.w33d.xyz/s/a.png");
    assert_eq!(p1.header_url, "https://aperture.w33d.xyz/s/h.jpg");
    // Upsert clears the header (empty => NULL) while keeping the avatar.
    pg.set_profile(&Profile {
        avatar_url: "https://aperture.w33d.xyz/s/a2.png".to_string(),
        header_url: String::new(),
    })
    .await
    .expect("update profile");
    let p2 = pg.get_profile().await;
    assert_eq!(p2.avatar_url, "https://aperture.w33d.xyz/s/a2.png");
    assert_eq!(p2.header_url, "", "cleared header reads back empty");

    // --- owner-scoped edit + delete ---------------------------------------
    // Wrong owner -> no-op (false), content untouched.
    assert!(!pg.update_note("note_pg_1", "u_intruder", "hijacked", now).await.unwrap());
    assert_eq!(pg.get_note("note_pg_1").await.unwrap().content, "from postgres");
    // Right owner -> edited, updated_at stamped.
    assert!(pg.update_note("note_pg_1", "u_w33d", "edited body", now + 5).await.unwrap());
    let edited = pg.get_note("note_pg_1").await.unwrap();
    assert_eq!(edited.content, "edited body");
    assert_eq!(edited.updated_at, now + 5);
    // Wrong owner delete -> no-op; right owner delete -> gone.
    assert!(!pg.delete_note("note_pg_1", "u_intruder").await.unwrap());
    assert!(pg.get_note("note_pg_1").await.is_some());
    assert!(pg.delete_note("note_pg_1", "u_w33d").await.unwrap());
    assert!(pg.get_note("note_pg_1").await.is_none());
    assert!(!pg.delete_note("note_pg_1", "u_w33d").await.unwrap(), "second delete is false");

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

    // --- wave-7: hashtags + boosts + lists (Postgres) ----------------------
    // Hashtags on note_pg_2 (public): add (idempotent), query, top, remove.
    pg.add_note_hashtags("note_pg_2", &["rust".to_string(), "webdev".to_string()])
        .await
        .expect("add tags");
    pg.add_note_hashtags("note_pg_2", &["rust".to_string()]).await.expect("re-add tag idempotent");
    assert!(pg.notes_with_tag("rust").await.iter().any(|n| n.id == "note_pg_2"));
    assert!(pg.top_tags(10).await.iter().any(|(t, c)| t == "rust" && *c == 1));
    pg.remove_note_hashtags("note_pg_2").await.expect("remove tags");
    assert!(pg.notes_with_tag("rust").await.is_empty());

    // Boosts: seed a home note, boost it (dedup on note_uri), then un-boost.
    pg.add_home_note(&HomeNote {
        id: "https://remote.example/notes/z1".to_string(),
        actor: "https://remote.example/users/zoe".to_string(),
        content: "hi".to_string(),
        url: "https://remote.example/notes/z1".to_string(),
        published: 0,
        in_reply_to: String::new(),
        received_at: now,
    })
    .await
    .expect("home note");
    assert_eq!(
        pg.get_home_note("https://remote.example/notes/z1").await.unwrap().actor,
        "https://remote.example/users/zoe"
    );
    pg.add_boost(&Boost {
        id: "boost_pg_1".to_string(),
        note_uri: "https://remote.example/notes/z1".to_string(),
        actor: "https://remote.example/users/zoe".to_string(),
        content: "hi".to_string(),
        url: "https://remote.example/notes/z1".to_string(),
        created_at: now,
    })
    .await
    .expect("boost");
    pg.add_boost(&Boost {
        id: "boost_pg_2".to_string(),
        note_uri: "https://remote.example/notes/z1".to_string(),
        actor: "x".to_string(),
        content: "x".to_string(),
        url: "x".to_string(),
        created_at: now + 1,
    })
    .await
    .expect("dup boost");
    assert_eq!(pg.list_boosts().await.len(), 1, "one boost per note_uri");
    assert!(pg.is_boosted("https://remote.example/notes/z1").await);
    pg.remove_boost("https://remote.example/notes/z1").await.expect("unboost");
    assert!(!pg.is_boosted("https://remote.example/notes/z1").await);

    // Lists: create (id conflict), owner-scope, member add/filter/remove, delete.
    pg.create_list(&List {
        id: "list_pg_1".to_string(),
        owner_sub: "u_w33d".to_string(),
        name: "Devs".to_string(),
        created_at: now,
    })
    .await
    .expect("create list");
    assert!(matches!(
        pg.create_list(&List {
            id: "list_pg_1".to_string(),
            owner_sub: "u_w33d".to_string(),
            name: "Dup".to_string(),
            created_at: now,
        })
        .await,
        Err(crier::store::StoreError::Conflict(_))
    ));
    assert_eq!(pg.list_lists("u_w33d").await.len(), 1);
    assert!(pg.get_list("list_pg_1", "u_w33d").await.is_some());
    assert!(pg.get_list("list_pg_1", "u_intruder").await.is_none(), "list is owner-scoped");
    assert!(
        !pg.add_list_member("list_pg_1", "u_intruder", "https://remote.example/users/zoe")
            .await
            .expect("foreign add"),
        "foreign owner cannot add a member"
    );
    assert!(pg
        .add_list_member("list_pg_1", "u_w33d", "https://remote.example/users/zoe")
        .await
        .expect("add member"));
    assert_eq!(
        pg.list_members("list_pg_1").await,
        vec!["https://remote.example/users/zoe".to_string()]
    );
    assert!(pg
        .list_home_notes_for_list("list_pg_1")
        .await
        .iter()
        .any(|n| n.id == "https://remote.example/notes/z1"));
    assert!(pg
        .remove_list_member("list_pg_1", "u_w33d", "https://remote.example/users/zoe")
        .await
        .expect("remove member"));
    assert!(pg.list_home_notes_for_list("list_pg_1").await.is_empty());
    assert!(pg.delete_list("list_pg_1", "u_w33d").await.expect("delete list"));
    assert!(pg.get_list("list_pg_1", "u_w33d").await.is_none());

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
