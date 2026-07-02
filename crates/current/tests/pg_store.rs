//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=current \
//!   -p 127.0.0.1:55481:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55481/current \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so it
//! runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use current::model::{Category, Feed, Item};
use current::store::{PgStore, Store};
use current::{app, build_dev_state, now_secs, AppState};
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

    let now = now_secs();
    let owner = "u_alice";

    // --- feeds: add + conflict + list --------------------------------------
    let feed = Feed {
        id: "feed_pg_1".into(),
        owner_sub: owner.into(),
        url: "https://example.com/rss".into(),
        title: "https://example.com/rss".into(),
        last_fetched: None,
        created_at: now - 100,
        category_id: None,
        full_content: false,
    };
    assert!(pg.add_feed(&feed).await.expect("add feed"));
    // Same owner + url -> conflict (no-op).
    let dup = Feed { id: "feed_pg_dup".into(), ..feed.clone() };
    assert!(!pg.add_feed(&dup).await.expect("add dup"), "duplicate url rejected");
    // Different owner, same url -> allowed.
    let other = Feed {
        id: "feed_pg_other".into(),
        owner_sub: "u_bob".into(),
        ..feed.clone()
    };
    assert!(pg.add_feed(&other).await.expect("add other owner"));

    let mine = pg.list_feeds(owner).await.expect("list feeds");
    assert_eq!(mine.len(), 1);

    // --- feed meta update --------------------------------------------------
    pg.update_feed_meta("feed_pg_1", "Example Feed", now).await.expect("meta");
    let f = pg.get_feed("feed_pg_1").await.expect("get").unwrap();
    assert_eq!(f.title, "Example Feed");
    assert_eq!(f.last_fetched, Some(now));

    // --- items: upsert + dedup ---------------------------------------------
    let it1 = Item {
        id: "item_pg_1".into(),
        feed_id: "feed_pg_1".into(),
        guid: "g1".into(),
        title: "First".into(),
        link: "https://example.com/1".into(),
        summary: "one".into(),
        published_at: Some(now - 50),
        read: false,
        full_text: None,
        starred: false,
    };
    let it2 = Item {
        id: "item_pg_2".into(),
        feed_id: "feed_pg_1".into(),
        guid: "g2".into(),
        title: "Second".into(),
        link: "https://example.com/2".into(),
        summary: "two".into(),
        published_at: Some(now),
        read: false,
        full_text: None,
        starred: false,
    };
    assert!(pg.upsert_item(&it1).await.expect("insert it1"));
    assert!(pg.upsert_item(&it2).await.expect("insert it2"));
    // Same (feed_id, guid) -> dedup (no-op).
    let dup_item = Item { id: "item_pg_dup".into(), ..it1.clone() };
    assert!(!pg.upsert_item(&dup_item).await.expect("dedup"), "duplicate guid rejected");

    // --- river: unread, newest-first, owner-scoped + joined feed title -----
    let river = pg.river(owner, 100).await.expect("river");
    let ids: Vec<&str> = river.iter().map(|e| e.item.id.as_str()).collect();
    assert_eq!(ids, vec!["item_pg_2", "item_pg_1"], "newest-first");
    assert_eq!(river[0].feed_title, "Example Feed", "joined feed title");

    // --- mark one read, then river drops it --------------------------------
    assert!(pg.mark_item_read("item_pg_2", owner).await.expect("mark read"));
    assert!(!pg.mark_item_read("item_pg_2", "intruder").await.expect("foreign mark"));
    let river = pg.river(owner, 100).await.expect("river2");
    assert_eq!(river.len(), 1);

    // --- get_item_owned: ownership-scoped ----------------------------------
    assert!(pg.get_item_owned("item_pg_1", owner).await.expect("owned").is_some());
    assert!(pg.get_item_owned("item_pg_1", "intruder").await.expect("foreign").is_none());

    // --- reader full_text cache: owner-scoped write + round-trip -----------
    assert!(!pg
        .set_item_full_text("item_pg_1", "intruder", "hax")
        .await
        .expect("foreign full_text"));
    assert!(pg
        .set_item_full_text("item_pg_1", owner, "Full body paragraph one.\n\nParagraph two.")
        .await
        .expect("set full_text"));
    let cached = pg.get_item_owned("item_pg_1", owner).await.expect("owned2").unwrap();
    assert_eq!(
        cached.item.full_text.as_deref(),
        Some("Full body paragraph one.\n\nParagraph two.")
    );

    // --- wave-7: categories + full-content + star + entry cache (Postgres) --
    // Categories: create, dedup on (owner, name), rename.
    assert!(pg
        .add_category(&Category { id: "cat_pg_1".into(), owner_sub: owner.into(), name: "News".into(), position: 0 })
        .await
        .expect("add cat"));
    assert!(!pg
        .add_category(&Category { id: "cat_pg_dup".into(), owner_sub: owner.into(), name: "News".into(), position: 1 })
        .await
        .expect("dup cat"), "duplicate (owner,name) rejected");
    assert_eq!(pg.list_categories(owner).await.expect("list cats").len(), 1);
    assert!(pg.rename_category("cat_pg_1", owner, "Headlines").await.expect("rename"));

    // Assign the feed to the owned category; a foreign category is rejected.
    assert!(pg.assign_feed_category("feed_pg_1", owner, Some("cat_pg_1")).await.expect("assign"));
    assert_eq!(
        pg.get_feed("feed_pg_1").await.expect("gf").unwrap().category_id.as_deref(),
        Some("cat_pg_1")
    );
    assert!(pg
        .add_category(&Category { id: "cat_pg_foreign".into(), owner_sub: "u_bob".into(), name: "Zzz".into(), position: 0 })
        .await
        .expect("foreign cat"));
    assert!(!pg
        .assign_feed_category("feed_pg_1", owner, Some("cat_pg_foreign"))
        .await
        .expect("assign foreign"), "cannot assign to a foreign category");

    // Full-content toggle.
    assert!(pg.set_feed_full_content("feed_pg_1", owner, true).await.expect("fc"));
    assert!(pg.get_feed("feed_pg_1").await.expect("gf2").unwrap().full_content);

    // Star + filtered river (item_pg_2 is read at this point; item_pg_1 unread).
    assert!(!pg.set_item_starred("item_pg_1", "intruder", true).await.expect("foreign star"));
    assert!(pg.set_item_starred("item_pg_1", owner, true).await.expect("star"));
    let starred = pg.river_filtered(owner, "starred", 100).await.expect("starred river");
    assert_eq!(starred.len(), 1);
    assert_eq!(starred[0].item.id, "item_pg_1");
    assert!(starred[0].item.starred);
    assert_eq!(pg.river_filtered(owner, "all", 100).await.expect("all river").len(), 2);
    assert_eq!(pg.river_filtered(owner, "unread", 100).await.expect("unread river").len(), 1);

    // Per-feed unread counts.
    let counts = pg.feed_unread_counts(owner).await.expect("unread counts");
    let cmap: std::collections::HashMap<String, i64> = counts.into_iter().collect();
    assert_eq!(cmap.get("feed_pg_1"), Some(&1));

    // Entry-content cache, owner-scoped both ways.
    assert!(!pg.set_entry_content("item_pg_1", "intruder", "hax").await.expect("foreign ec"));
    assert!(pg.set_entry_content("item_pg_1", owner, "Body one.\n\nBody two.").await.expect("ec"));
    assert_eq!(
        pg.get_entry_content("item_pg_1", owner).await.expect("gec").as_deref(),
        Some("Body one.\n\nBody two.")
    );
    assert!(pg.get_entry_content("item_pg_1", "intruder").await.expect("foreign gec").is_none());

    // Deleting the category uncategorizes the feed (never deletes it).
    assert!(pg.delete_category("cat_pg_1", owner).await.expect("del cat"));
    assert!(pg.get_feed("feed_pg_1").await.expect("gf3").unwrap().category_id.is_none());
    pg.delete_category("cat_pg_foreign", "u_bob").await.expect("del foreign cat");

    // --- mark all read -----------------------------------------------------
    let n = pg.mark_all_read(owner).await.expect("mark all");
    assert_eq!(n, 1);
    assert!(pg.river(owner, 100).await.expect("river3").is_empty());

    // --- remove feed cascades items + is owner-scoped ----------------------
    assert!(!pg.remove_feed("feed_pg_1", "intruder").await.expect("foreign remove"));
    assert!(pg.remove_feed("feed_pg_1", owner).await.expect("remove"));
    assert!(pg.get_feed("feed_pg_1").await.expect("gone").is_none());
    assert!(pg.get_item_owned("item_pg_1", owner).await.expect("items gone").is_none());

    // --- full HTTP flow through the PG-backed app --------------------------
    let mut state: AppState = build_dev_state();
    state.store = pg.clone();

    // Add a feed through the SSO + CSRF authoring path.
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/feeds")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, "__Host-csrf=tok")
                .header("x-auth-subject", "u_http")
                .header("x-auth-email", "http@holdfast.local")
                .body(Body::from("csrf_token=tok&url=https://invalid.invalid/feed.xml"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Seed an item directly and read it back through the PG-backed river.
    let http_feed = pg.list_feeds("u_http").await.expect("http feeds");
    assert_eq!(http_feed.len(), 1);
    let fid = http_feed[0].id.clone();
    pg.upsert_item(&Item {
        id: "item_http_1".into(),
        feed_id: fid.clone(),
        guid: "ghttp".into(),
        title: "Via HTTP".into(),
        link: "https://example.com/http".into(),
        summary: "served from postgres".into(),
        published_at: Some(now),
        read: false,
        full_text: None,
        starred: false,
    })
    .await
    .expect("seed http item");

    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .uri("/")
                .header("x-auth-subject", "u_http")
                .header("x-auth-email", "http@holdfast.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Via HTTP"));

    // --- clean up everything this test created -----------------------------
    pg.remove_feed(&fid, "u_http").await.expect("cleanup http feed");
    pg.remove_feed("feed_pg_other", "u_bob").await.expect("cleanup other feed");
    assert!(pg.list_feeds("u_http").await.expect("http empty").is_empty());

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + add/conflict/list feeds + meta update \
         + upsert/dedup items + river (newest-first, joined title, owner-scoped) + mark read / \
         mark all + ownership-scoped get + remove cascade + full add/seed/read HTTP flow against \
         real Postgres (cleaned up)"
    );
}
