//! Feed + item storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the pastefire/keystone/watchtower seam: handlers + the poller depend only on the trait, so a
//! FusionDB-backed store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT/BOOLEAN, PRIMARY KEY/UNIQUE/NOT NULL/DEFAULT, parameterized queries,
//! `INSERT .. ON CONFLICT`, plain indexes) and runtime queries (no compile-time macros), so the
//! build needs NO database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers and the background poller `.await` it directly on the
//! serving runtime, and `PgStore` drives sqlx natively — there is NO `block_in_place` and NO
//! sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{Feed, Item, RiverEntry};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable store. Feed `add` is conflict-aware on `(owner_sub, url)`; item `upsert` is
/// conflict-aware on `(feed_id, guid)`; every owner-scoped read/mutation is filtered by the
/// owner so one person never sees or changes another's feeds.
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a feed. Returns `Ok(true)` when inserted, `Ok(false)` when `(owner_sub, url)`
    /// already existed (the same person re-adding the same URL is a no-op).
    async fn add_feed(&self, feed: &Feed) -> Result<bool, StoreError>;

    /// Fetch a single feed by id (no owner filter — callers that need ownership check it).
    async fn get_feed(&self, id: &str) -> Result<Option<Feed>, StoreError>;

    /// An owner's feeds, newest-subscribed first.
    async fn list_feeds(&self, owner_sub: &str) -> Result<Vec<Feed>, StoreError>;

    /// Every feed across all owners — the poller's work list.
    async fn all_feeds(&self) -> Result<Vec<Feed>, StoreError>;

    /// Delete a feed (and all its items) only if it belongs to `owner_sub`. Returns `true`
    /// when the feed existed AND was owned.
    async fn remove_feed(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// After a successful fetch, record the feed's own title + the fetch time.
    async fn update_feed_meta(
        &self,
        id: &str,
        title: &str,
        last_fetched: i64,
    ) -> Result<(), StoreError>;

    /// Upsert one fetched item. Returns `Ok(true)` when newly inserted, `Ok(false)` when the
    /// `(feed_id, guid)` already existed (dedup — re-polling is idempotent).
    async fn upsert_item(&self, item: &Item) -> Result<bool, StoreError>;

    /// The unified river: an owner's newest UNREAD items across all their feeds, each paired
    /// with its feed title, capped at `limit`.
    async fn river(&self, owner_sub: &str, limit: i64) -> Result<Vec<RiverEntry>, StoreError>;

    /// Fetch one item by id only if it belongs to `owner_sub` (via its feed), paired with the
    /// feed title.
    async fn get_item_owned(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<RiverEntry>, StoreError>;

    /// Mark a single item read, owner-scoped. Returns `true` when a row was updated.
    async fn mark_item_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Mark every unread item across an owner's feeds read. Returns the number affected.
    async fn mark_all_read(&self, owner_sub: &str) -> Result<u64, StoreError>;

    /// Cache the extracted full readable text on one item, owner-scoped (via its feed). Idempotent
    /// from the reader's view: it only writes after a successful fetch+extract. Returns `true`
    /// when a row was updated (the item existed AND was owned).
    async fn set_item_full_text(
        &self,
        id: &str,
        owner_sub: &str,
        full_text: &str,
    ) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. Each `Mutex<Vec<_>>` critical section is fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    feeds: Mutex<Vec<Feed>>,
    items: Mutex<Vec<Item>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn add_feed(&self, feed: &Feed) -> Result<bool, StoreError> {
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        if feeds
            .iter()
            .any(|f| f.owner_sub == feed.owner_sub && f.url == feed.url)
        {
            return Ok(false);
        }
        feeds.push(feed.clone());
        Ok(true)
    }

    async fn get_feed(&self, id: &str) -> Result<Option<Feed>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        Ok(feeds.iter().find(|f| f.id == id).cloned())
    }

    async fn list_feeds(&self, owner_sub: &str) -> Result<Vec<Feed>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        let mut out: Vec<Feed> = feeds
            .iter()
            .filter(|f| f.owner_sub == owner_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        Ok(out)
    }

    async fn all_feeds(&self) -> Result<Vec<Feed>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        Ok(feeds.clone())
    }

    async fn remove_feed(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        let before = feeds.len();
        feeds.retain(|f| !(f.id == id && f.owner_sub == owner_sub));
        let removed = feeds.len() != before;
        drop(feeds);
        if removed {
            let mut items = self.items.lock().expect("items lock poisoned");
            items.retain(|i| i.feed_id != id);
        }
        Ok(removed)
    }

    async fn update_feed_meta(
        &self,
        id: &str,
        title: &str,
        last_fetched: i64,
    ) -> Result<(), StoreError> {
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        if let Some(f) = feeds.iter_mut().find(|f| f.id == id) {
            f.title = title.to_string();
            f.last_fetched = Some(last_fetched);
        }
        Ok(())
    }

    async fn upsert_item(&self, item: &Item) -> Result<bool, StoreError> {
        let mut items = self.items.lock().expect("items lock poisoned");
        if items
            .iter()
            .any(|i| i.feed_id == item.feed_id && i.guid == item.guid)
        {
            return Ok(false);
        }
        items.push(item.clone());
        Ok(true)
    }

    async fn river(&self, owner_sub: &str, limit: i64) -> Result<Vec<RiverEntry>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        let items = self.items.lock().expect("items lock poisoned");
        let mut out: Vec<RiverEntry> = items
            .iter()
            .filter(|i| !i.read)
            .filter_map(|i| {
                feeds
                    .iter()
                    .find(|f| f.id == i.feed_id && f.owner_sub == owner_sub)
                    .map(|f| RiverEntry {
                        item: i.clone(),
                        feed_title: f.title.clone(),
                    })
            })
            .collect();
        // Newest-first; unknown publish time sorts oldest; id as a deterministic tiebreak.
        out.sort_by(|a, b| {
            b.item
                .published_at
                .unwrap_or(i64::MIN)
                .cmp(&a.item.published_at.unwrap_or(i64::MIN))
                .then_with(|| b.item.id.cmp(&a.item.id))
        });
        out.truncate(limit.max(0) as usize);
        Ok(out)
    }

    async fn get_item_owned(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<RiverEntry>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        let items = self.items.lock().expect("items lock poisoned");
        Ok(items.iter().find(|i| i.id == id).and_then(|i| {
            feeds
                .iter()
                .find(|f| f.id == i.feed_id && f.owner_sub == owner_sub)
                .map(|f| RiverEntry {
                    item: i.clone(),
                    feed_title: f.title.clone(),
                })
        }))
    }

    async fn mark_item_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let owned: Vec<String> = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            feeds
                .iter()
                .filter(|f| f.owner_sub == owner_sub)
                .map(|f| f.id.clone())
                .collect()
        };
        let mut items = self.items.lock().expect("items lock poisoned");
        if let Some(i) = items
            .iter_mut()
            .find(|i| i.id == id && owned.contains(&i.feed_id))
        {
            let changed = !i.read;
            i.read = true;
            Ok(changed)
        } else {
            Ok(false)
        }
    }

    async fn mark_all_read(&self, owner_sub: &str) -> Result<u64, StoreError> {
        let owned: Vec<String> = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            feeds
                .iter()
                .filter(|f| f.owner_sub == owner_sub)
                .map(|f| f.id.clone())
                .collect()
        };
        let mut items = self.items.lock().expect("items lock poisoned");
        let mut n = 0u64;
        for i in items.iter_mut() {
            if !i.read && owned.contains(&i.feed_id) {
                i.read = true;
                n += 1;
            }
        }
        Ok(n)
    }

    async fn set_item_full_text(
        &self,
        id: &str,
        owner_sub: &str,
        full_text: &str,
    ) -> Result<bool, StoreError> {
        let owned: Vec<String> = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            feeds
                .iter()
                .filter(|f| f.owner_sub == owner_sub)
                .map(|f| f.id.clone())
                .collect()
        };
        let mut items = self.items.lock().expect("items lock poisoned");
        if let Some(i) = items
            .iter_mut()
            .find(|i| i.id == id && owned.contains(&i.feed_id))
        {
            i.full_text = Some(full_text.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `CURRENT_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the callers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Column list shared by every feed SELECT, so the row decoder stays in lock-step.
const FEED_COLS: &str = "id, owner_sub, url, title, last_fetched, created_at";
/// Column list shared by every item SELECT, so the row decoder stays in lock-step.
const ITEM_COLS: &str = "id, feed_id, guid, title, link, summary, published_at, read, full_text";

/// PostgreSQL-backed [`Store`]. Holds a pooled connection; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    /// `last_fetched` / `published_at` are the nullable columns. The indexes back the poller
    /// (items by feed) and the per-owner feed/river lookups.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS feeds (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 url TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 last_fetched BIGINT, \
                 created_at BIGINT NOT NULL, \
                 UNIQUE (owner_sub, url)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS items (\
                 id TEXT PRIMARY KEY, \
                 feed_id TEXT NOT NULL, \
                 guid TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 link TEXT NOT NULL, \
                 summary TEXT NOT NULL, \
                 published_at BIGINT, \
                 read BOOLEAN NOT NULL DEFAULT FALSE, \
                 UNIQUE (feed_id, guid)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // In-app reader cache column. Idempotent ALTER so existing deployments gain it on the next
        // startup without a destructive migration (portable standard SQL — nullable TEXT).
        sqlx::query("ALTER TABLE items ADD COLUMN IF NOT EXISTS full_text TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_feeds_owner ON feeds (owner_sub)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_items_feed ON items (feed_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_items_unread ON items (read, published_at)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn feed_from_row(row: &sqlx::postgres::PgRow) -> Result<Feed, sqlx::Error> {
        Ok(Feed {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            url: row.try_get("url")?,
            title: row.try_get("title")?,
            last_fetched: row.try_get("last_fetched")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn item_from_row(row: &sqlx::postgres::PgRow) -> Result<Item, sqlx::Error> {
        Ok(Item {
            id: row.try_get("id")?,
            feed_id: row.try_get("feed_id")?,
            guid: row.try_get("guid")?,
            title: row.try_get("title")?,
            link: row.try_get("link")?,
            summary: row.try_get("summary")?,
            published_at: row.try_get("published_at")?,
            read: row.try_get("read")?,
            full_text: row.try_get("full_text")?,
        })
    }
}

#[async_trait]
impl Store for PgStore {
    async fn add_feed(&self, feed: &Feed) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO feeds (id, owner_sub, url, title, last_fetched, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (owner_sub, url) DO NOTHING",
        )
        .bind(&feed.id)
        .bind(&feed.owner_sub)
        .bind(&feed.url)
        .bind(&feed.title)
        .bind(feed.last_fetched)
        .bind(feed.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_feed(&self, id: &str) -> Result<Option<Feed>, StoreError> {
        let row = sqlx::query(&format!("SELECT {FEED_COLS} FROM feeds WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.as_ref()
            .map(Self::feed_from_row)
            .transpose()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_feeds(&self, owner_sub: &str) -> Result<Vec<Feed>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {FEED_COLS} FROM feeds WHERE owner_sub = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::feed_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn all_feeds(&self) -> Result<Vec<Feed>, StoreError> {
        let rows = sqlx::query(&format!("SELECT {FEED_COLS} FROM feeds ORDER BY id"))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::feed_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn remove_feed(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        // Items first (no FK in portable SQL), then the owned feed row.
        sqlx::query(
            "DELETE FROM items WHERE feed_id IN \
                 (SELECT id FROM feeds WHERE id = $1 AND owner_sub = $2)",
        )
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let result = sqlx::query("DELETE FROM feeds WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_feed_meta(
        &self,
        id: &str,
        title: &str,
        last_fetched: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE feeds SET title = $2, last_fetched = $3 WHERE id = $1")
            .bind(id)
            .bind(title)
            .bind(last_fetched)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn upsert_item(&self, item: &Item) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO items \
                 (id, feed_id, guid, title, link, summary, published_at, read, full_text) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (feed_id, guid) DO NOTHING",
        )
        .bind(&item.id)
        .bind(&item.feed_id)
        .bind(&item.guid)
        .bind(&item.title)
        .bind(&item.link)
        .bind(&item.summary)
        .bind(item.published_at)
        .bind(item.read)
        .bind(&item.full_text)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    async fn river(&self, owner_sub: &str, limit: i64) -> Result<Vec<RiverEntry>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {item_cols}, f.title AS feed_title \
             FROM items i JOIN feeds f ON f.id = i.feed_id \
             WHERE f.owner_sub = $1 AND i.read = FALSE \
             ORDER BY COALESCE(i.published_at, 0) DESC, i.id DESC \
             LIMIT $2",
            item_cols = ITEM_COLS
                .split(", ")
                .map(|c| format!("i.{c}"))
                .collect::<Vec<_>>()
                .join(", "),
        ))
        .bind(owner_sub)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(|row| {
                Ok(RiverEntry {
                    item: Self::item_from_row(row)?,
                    feed_title: row.try_get("feed_title")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_item_owned(
        &self,
        id: &str,
        owner_sub: &str,
    ) -> Result<Option<RiverEntry>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {item_cols}, f.title AS feed_title \
             FROM items i JOIN feeds f ON f.id = i.feed_id \
             WHERE i.id = $1 AND f.owner_sub = $2",
            item_cols = ITEM_COLS
                .split(", ")
                .map(|c| format!("i.{c}"))
                .collect::<Vec<_>>()
                .join(", "),
        ))
        .bind(id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        match row {
            Some(row) => Ok(Some(RiverEntry {
                item: Self::item_from_row(&row).map_err(|e| StoreError::Backend(e.to_string()))?,
                feed_title: row
                    .try_get("feed_title")
                    .map_err(|e| StoreError::Backend(e.to_string()))?,
            })),
            None => Ok(None),
        }
    }

    async fn mark_item_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE items SET read = TRUE \
             WHERE id = $1 AND feed_id IN (SELECT id FROM feeds WHERE owner_sub = $2)",
        )
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_all_read(&self, owner_sub: &str) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "UPDATE items SET read = TRUE \
             WHERE read = FALSE AND feed_id IN (SELECT id FROM feeds WHERE owner_sub = $1)",
        )
        .bind(owner_sub)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn set_item_full_text(
        &self,
        id: &str,
        owner_sub: &str,
        full_text: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE items SET full_text = $3 \
             WHERE id = $1 AND feed_id IN (SELECT id FROM feeds WHERE owner_sub = $2)",
        )
        .bind(id)
        .bind(owner_sub)
        .bind(full_text)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(id: &str, owner: &str, url: &str, created: i64) -> Feed {
        Feed {
            id: id.into(),
            owner_sub: owner.into(),
            url: url.into(),
            title: url.into(),
            last_fetched: None,
            created_at: created,
        }
    }

    fn item(id: &str, feed_id: &str, guid: &str, published: Option<i64>) -> Item {
        Item {
            id: id.into(),
            feed_id: feed_id.into(),
            guid: guid.into(),
            title: "t".into(),
            link: "https://example.com".into(),
            summary: "s".into(),
            published_at: published,
            read: false,
            full_text: None,
        }
    }

    #[tokio::test]
    async fn add_feed_is_conflict_aware() {
        let s = InMemoryStore::new();
        assert!(s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap());
        // Same owner + url -> conflict (no-op).
        assert!(!s.add_feed(&feed("f2", "u", "https://a.com/rss", 2)).await.unwrap());
        // Different owner, same url -> allowed.
        assert!(s.add_feed(&feed("f3", "v", "https://a.com/rss", 3)).await.unwrap());
    }

    #[tokio::test]
    async fn upsert_item_dedupes_by_guid() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        assert!(s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap());
        assert!(!s.upsert_item(&item("i2", "f1", "g1", Some(20))).await.unwrap());
    }

    #[tokio::test]
    async fn river_is_unread_owner_scoped_newest_first() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.add_feed(&feed("f2", "other", "https://b.com/rss", 2)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();
        s.upsert_item(&item("i2", "f1", "g2", Some(30))).await.unwrap();
        let mut read_one = item("i3", "f1", "g3", Some(40));
        read_one.read = true;
        s.upsert_item(&read_one).await.unwrap();
        s.upsert_item(&item("i4", "f2", "g4", Some(99))).await.unwrap(); // other owner

        let river = s.river("u", 100).await.unwrap();
        let ids: Vec<&str> = river.iter().map(|e| e.item.id.as_str()).collect();
        assert_eq!(ids, vec!["i2", "i1"]); // newest-first, read + other owner excluded
    }

    #[tokio::test]
    async fn mark_read_and_mark_all_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();
        s.upsert_item(&item("i2", "f1", "g2", Some(20))).await.unwrap();

        // A different owner cannot mark it read.
        assert!(!s.mark_item_read("i1", "intruder").await.unwrap());
        assert!(s.mark_item_read("i1", "u").await.unwrap());
        assert_eq!(s.river("u", 100).await.unwrap().len(), 1);

        let n = s.mark_all_read("u").await.unwrap();
        assert_eq!(n, 1);
        assert!(s.river("u", 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn remove_feed_cascades_items_and_is_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();

        assert!(!s.remove_feed("f1", "intruder").await.unwrap());
        assert!(s.remove_feed("f1", "u").await.unwrap());
        assert!(s.get_feed("f1").await.unwrap().is_none());
        assert!(s.river("u", 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_full_text_is_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();

        // A foreign owner cannot write the cache.
        assert!(!s.set_item_full_text("i1", "intruder", "hax").await.unwrap());
        assert!(s
            .get_item_owned("i1", "u")
            .await
            .unwrap()
            .unwrap()
            .item
            .full_text
            .is_none());

        // The owner can, and it round-trips through get_item_owned.
        assert!(s.set_item_full_text("i1", "u", "the full body").await.unwrap());
        let cached = s.get_item_owned("i1", "u").await.unwrap().unwrap();
        assert_eq!(cached.item.full_text.as_deref(), Some("the full body"));
    }

    #[tokio::test]
    async fn update_feed_meta_sets_title_and_fetch_time() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.update_feed_meta("f1", "Real Title", 12345).await.unwrap();
        let f = s.get_feed("f1").await.unwrap().unwrap();
        assert_eq!(f.title, "Real Title");
        assert_eq!(f.last_fetched, Some(12345));
    }
}
