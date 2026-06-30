//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name magpie-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=magpie \
//!   -p 127.0.0.1:55482:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55482/magpie \
//!   cargo test --test pg_integration -- --nocapture
//! docker rm -f magpie-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use magpie::model::{Clip, Filter};
use magpie::store::{PgStore, Store};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

fn clip(id: &str, owner: &str, url: &str, saved_at: i64) -> Clip {
    Clip {
        id: id.to_string(),
        owner_sub: owner.to_string(),
        url: url.to_string(),
        title: format!("title {id}"),
        excerpt: format!("excerpt {id}"),
        content_text: format!("body of {id}\nsecond line"),
        site: "example.com".to_string(),
        saved_at,
        read: false,
        archived: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Raw pool to reset the table for a clean run.
    let raw = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    sqlx::query("DELETE FROM clips").execute(&raw).await.unwrap();

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = 1_700_000_000i64;

    // --- create + get round-trip (booleans + multi-line text) --------------
    assert!(store.create(&clip("aaaaaa11", "alice", "https://example.com/a", now)).await.unwrap());
    let got = store.get("aaaaaa11").await.unwrap().expect("clip persisted");
    assert_eq!(got.title, "title aaaaaa11");
    assert_eq!(got.content_text, "body of aaaaaa11\nsecond line");
    assert_eq!(got.site, "example.com");
    assert!(!got.read);
    assert!(!got.archived);

    // --- id collision -> create returns false (ON CONFLICT DO NOTHING) -----
    assert!(!store.create(&clip("aaaaaa11", "alice", "https://example.com/dup", now + 5)).await.unwrap());

    // --- de-dup lookup by (owner, url) -------------------------------------
    assert!(store.find_by_owner_url("alice", "https://example.com/a").await.unwrap().is_some());
    assert!(store.find_by_owner_url("alice", "https://example.com/missing").await.unwrap().is_none());
    assert!(store.find_by_owner_url("bob", "https://example.com/a").await.unwrap().is_none());

    // --- list views: All / Unread / Archived, newest-first, owner-scoped ---
    store.create(&clip("bbbbbb22", "alice", "https://example.com/b", now + 10)).await.unwrap();
    store.mark_read("bbbbbb22", "alice").await.unwrap();
    store.create(&clip("cccccc33", "alice", "https://example.com/c", now + 20)).await.unwrap();
    store.set_archived("cccccc33", "alice", true).await.unwrap();
    store.create(&clip("dddddd44", "bob", "https://example.com/d", now + 30)).await.unwrap();

    let all = store.list("alice", Filter::All).await.unwrap();
    assert_eq!(all.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["bbbbbb22", "aaaaaa11"]);
    let unread = store.list("alice", Filter::Unread).await.unwrap();
    assert_eq!(unread.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["aaaaaa11"]);
    let archived = store.list("alice", Filter::Archived).await.unwrap();
    assert_eq!(archived.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["cccccc33"]);

    // --- mark_read / set_archived persist (booleans round-trip) ------------
    assert!(store.mark_read("aaaaaa11", "alice").await.unwrap());
    assert!(store.get("aaaaaa11").await.unwrap().unwrap().read);
    assert!(store.set_archived("cccccc33", "alice", false).await.unwrap());
    assert!(!store.get("cccccc33").await.unwrap().unwrap().archived);

    // --- mutations are ownership-scoped ------------------------------------
    assert!(!store.mark_read("aaaaaa11", "bob").await.unwrap());
    assert!(!store.set_archived("aaaaaa11", "bob", true).await.unwrap());
    assert!(!store.delete("aaaaaa11", "bob").await.unwrap());
    assert!(store.get("aaaaaa11").await.unwrap().is_some());
    assert!(store.delete("aaaaaa11", "alice").await.unwrap());
    assert!(store.get("aaaaaa11").await.unwrap().is_none());

    // --- confirm row count via a raw query (portable SQL path is live) -----
    let row = sqlx::query("SELECT count(*) AS n FROM clips WHERE owner_sub = $1")
        .bind("alice")
        .fetch_one(&raw)
        .await
        .unwrap();
    let n: i64 = row.try_get("n").unwrap();
    assert_eq!(n, 2, "alice keeps bbbbbb22 + cccccc33 after deleting aaaaaa11");

    sqlx::query("DELETE FROM clips").execute(&raw).await.unwrap();
    eprintln!("pg_integration test passed.");
}
