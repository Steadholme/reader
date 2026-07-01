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
        tags: None,
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

    // --- tags: set / clear / round-trip + whole-token tag view ---------------
    // alice now owns bbbbbb22 (saved now+10) and cccccc33 (saved now+20), both non-archived.
    assert!(store
        .set_tags("bbbbbb22", "alice", magpie::model::normalize_tags("Rust, Web"))
        .await
        .unwrap());
    assert!(store
        .set_tags("cccccc33", "alice", magpie::model::normalize_tags("gardening"))
        .await
        .unwrap());
    assert_eq!(
        store.get("bbbbbb22").await.unwrap().unwrap().tags.as_deref(),
        Some("rust,web")
    );
    let rust = store.list_by_tag("alice", "rust").await.unwrap();
    assert_eq!(rust.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["bbbbbb22"]);
    // whole-token: "garden" must not match the "gardening" tag as a substring.
    assert!(store.list_by_tag("alice", "garden").await.unwrap().is_empty());
    let gardening = store.list_by_tag("alice", "gardening").await.unwrap();
    assert_eq!(gardening.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["cccccc33"]);
    // tag view is owner-scoped: bob's clip never leaks in.
    assert!(store.list_by_tag("bob", "rust").await.unwrap().is_empty());
    // clearing tags nulls the column.
    assert!(store.set_tags("cccccc33", "alice", None).await.unwrap());
    assert!(store.get("cccccc33").await.unwrap().unwrap().tags.is_none());

    // --- search: LOWER+LIKE over title+content, keyset-paginated -------------
    // Both bbbbbb22 (now+10) and cccccc33 (now+20) share "second line" in content_text.
    let p1 = store.search("alice", "SECOND LINE", None, 1).await.unwrap();
    assert_eq!(p1.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["cccccc33"]);
    let cur = magpie::model::Cursor { saved_at: p1[0].saved_at, id: p1[0].id.clone() };
    let p2 = store.search("alice", "second line", Some(&cur), 10).await.unwrap();
    assert_eq!(p2.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["bbbbbb22"]);
    // title match + owner scoping: bob's clip is excluded.
    let by_title = store.search("alice", "title bbbbbb22", None, 10).await.unwrap();
    assert_eq!(by_title.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["bbbbbb22"]);
    assert!(store.search("bob", "title bbbbbb22", None, 10).await.unwrap().is_empty());

    sqlx::query("DELETE FROM clips").execute(&raw).await.unwrap();
    eprintln!("pg_integration test passed.");
}
