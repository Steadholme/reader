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

use crate::model::{Category, Feed, Item, RiverEntry};

const MAX_FETCH_ERROR_CHARS: usize = 500;

fn truncate_fetch_error(error: &str) -> String {
    error.chars().take(MAX_FETCH_ERROR_CHARS).collect()
}

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

    /// Record a failed fetch attempt for a feed. Missing feeds are ignored because the feed may
    /// have been removed while a background fetch was in flight.
    async fn record_fetch_failure(
        &self,
        id: &str,
        now: i64,
        error: &str,
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

    // --- Categories -------------------------------------------------------------------

    /// An owner's categories, ordered by `position` then `name`.
    async fn list_categories(&self, owner_sub: &str) -> Result<Vec<Category>, StoreError>;

    /// Create a category. Returns `Ok(false)` when `(owner_sub, name)` already exists (dedup).
    async fn add_category(&self, category: &Category) -> Result<bool, StoreError>;

    /// Rename a category, owner-scoped. Returns `true` when a row was updated.
    async fn rename_category(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError>;

    /// Delete a category, owner-scoped. Feeds in the category are set uncategorized (NOT deleted).
    /// Returns `true` when the category existed AND was owned.
    async fn delete_category(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Set a category's sort position, owner-scoped. Returns `true` when a row was updated.
    async fn set_category_position(
        &self,
        id: &str,
        owner_sub: &str,
        position: i64,
    ) -> Result<bool, StoreError>;

    /// Assign a feed to a category (or clear it with `None`), owner-scoped. A non-`None` category id
    /// is applied only when that category is ALSO owned by `owner_sub`. Returns `true` when the feed
    /// row was updated.
    async fn assign_feed_category(
        &self,
        feed_id: &str,
        owner_sub: &str,
        category_id: Option<&str>,
    ) -> Result<bool, StoreError>;

    // --- Full-content toggle + per-entry content cache --------------------------------

    /// Set the per-feed "fetch full content" toggle, owner-scoped. Returns `true` when updated.
    async fn set_feed_full_content(
        &self,
        id: &str,
        owner_sub: &str,
        on: bool,
    ) -> Result<bool, StoreError>;

    /// Read the cached extracted body for one entry, owner-scoped (via its feed). `None` when the
    /// entry is not cached, missing, or not owned.
    async fn get_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
    ) -> Result<Option<String>, StoreError>;

    /// Cache the extracted body for one entry, owner-scoped (via its feed). Returns `true` when the
    /// entry existed AND was owned (so the cache was written).
    async fn set_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
        content: &str,
    ) -> Result<bool, StoreError>;

    // --- Star / save + filtered river -------------------------------------------------

    /// Set the starred flag on one item, owner-scoped. Returns `true` when a row was updated.
    async fn set_item_starred(
        &self,
        id: &str,
        owner_sub: &str,
        starred: bool,
    ) -> Result<bool, StoreError>;

    /// The river under a filter: `"unread"` (default), `"starred"`, or `"all"` — the owner's items
    /// across all feeds, newest-first, capped at `limit`, each paired with its feed title.
    async fn river_filtered(
        &self,
        owner_sub: &str,
        filter: &str,
        limit: i64,
    ) -> Result<Vec<RiverEntry>, StoreError>;

    /// Per-feed unread counts for an owner: `(feed_id, unread_count)` for every feed with ≥1 unread.
    async fn feed_unread_counts(&self, owner_sub: &str)
        -> Result<Vec<(String, i64)>, StoreError>;
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
    categories: Mutex<Vec<Category>>,
    /// Per-entry extracted-body cache keyed by entry id.
    entry_content: Mutex<Vec<(String, String)>>,
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
            f.last_error = None;
            f.last_error_at = None;
            f.consecutive_failures = 0;
        }
        Ok(())
    }

    async fn record_fetch_failure(
        &self,
        id: &str,
        now: i64,
        error: &str,
    ) -> Result<(), StoreError> {
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        if let Some(f) = feeds.iter_mut().find(|f| f.id == id) {
            f.last_error = Some(truncate_fetch_error(error));
            f.last_error_at = Some(now);
            f.consecutive_failures += 1;
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

    async fn list_categories(&self, owner_sub: &str) -> Result<Vec<Category>, StoreError> {
        let cats = self.categories.lock().expect("categories lock poisoned");
        let mut out: Vec<Category> = cats
            .iter()
            .filter(|c| c.owner_sub == owner_sub)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    async fn add_category(&self, category: &Category) -> Result<bool, StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        if cats
            .iter()
            .any(|c| c.owner_sub == category.owner_sub && c.name == category.name)
        {
            return Ok(false);
        }
        cats.push(category.clone());
        Ok(true)
    }

    async fn rename_category(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        // A rename to a name already used by ANOTHER of this owner's categories is a no-op conflict.
        if cats
            .iter()
            .any(|c| c.owner_sub == owner_sub && c.name == name && c.id != id)
        {
            return Ok(false);
        }
        match cats.iter_mut().find(|c| c.id == id && c.owner_sub == owner_sub) {
            Some(c) => {
                c.name = name.to_string();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_category(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        let before = cats.len();
        cats.retain(|c| !(c.id == id && c.owner_sub == owner_sub));
        let removed = cats.len() != before;
        drop(cats);
        if removed {
            let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
            for f in feeds.iter_mut() {
                if f.owner_sub == owner_sub && f.category_id.as_deref() == Some(id) {
                    f.category_id = None;
                }
            }
        }
        Ok(removed)
    }

    async fn set_category_position(
        &self,
        id: &str,
        owner_sub: &str,
        position: i64,
    ) -> Result<bool, StoreError> {
        let mut cats = self.categories.lock().expect("categories lock poisoned");
        match cats.iter_mut().find(|c| c.id == id && c.owner_sub == owner_sub) {
            Some(c) => {
                c.position = position;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn assign_feed_category(
        &self,
        feed_id: &str,
        owner_sub: &str,
        category_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        // A non-None category must be owned by the same owner, else the assignment is rejected.
        if let Some(cid) = category_id {
            let cats = self.categories.lock().expect("categories lock poisoned");
            if !cats.iter().any(|c| c.id == cid && c.owner_sub == owner_sub) {
                return Ok(false);
            }
        }
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        match feeds.iter_mut().find(|f| f.id == feed_id && f.owner_sub == owner_sub) {
            Some(f) => {
                f.category_id = category_id.map(str::to_string);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn set_feed_full_content(
        &self,
        id: &str,
        owner_sub: &str,
        on: bool,
    ) -> Result<bool, StoreError> {
        let mut feeds = self.feeds.lock().expect("feeds lock poisoned");
        match feeds.iter_mut().find(|f| f.id == id && f.owner_sub == owner_sub) {
            Some(f) => {
                f.full_content = on;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn get_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
    ) -> Result<Option<String>, StoreError> {
        // Ownership gate: the entry must belong to one of the owner's feeds.
        let owned = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            let items = self.items.lock().expect("items lock poisoned");
            items.iter().any(|i| {
                i.id == entry_id
                    && feeds
                        .iter()
                        .any(|f| f.id == i.feed_id && f.owner_sub == owner_sub)
            })
        };
        if !owned {
            return Ok(None);
        }
        let cache = self.entry_content.lock().expect("entry_content lock poisoned");
        Ok(cache
            .iter()
            .find(|(id, _)| id == entry_id)
            .map(|(_, c)| c.clone()))
    }

    async fn set_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
        content: &str,
    ) -> Result<bool, StoreError> {
        let owned = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            let items = self.items.lock().expect("items lock poisoned");
            items.iter().any(|i| {
                i.id == entry_id
                    && feeds
                        .iter()
                        .any(|f| f.id == i.feed_id && f.owner_sub == owner_sub)
            })
        };
        if !owned {
            return Ok(false);
        }
        let mut cache = self.entry_content.lock().expect("entry_content lock poisoned");
        match cache.iter_mut().find(|(id, _)| id == entry_id) {
            Some(entry) => entry.1 = content.to_string(),
            None => cache.push((entry_id.to_string(), content.to_string())),
        }
        Ok(true)
    }

    async fn set_item_starred(
        &self,
        id: &str,
        owner_sub: &str,
        starred: bool,
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
            i.starred = starred;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn river_filtered(
        &self,
        owner_sub: &str,
        filter: &str,
        limit: i64,
    ) -> Result<Vec<RiverEntry>, StoreError> {
        let feeds = self.feeds.lock().expect("feeds lock poisoned");
        let items = self.items.lock().expect("items lock poisoned");
        let mut out: Vec<RiverEntry> = items
            .iter()
            .filter(|i| match filter {
                "starred" => i.starred,
                "all" => true,
                _ => !i.read,
            })
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

    async fn feed_unread_counts(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let owned: Vec<String> = {
            let feeds = self.feeds.lock().expect("feeds lock poisoned");
            feeds
                .iter()
                .filter(|f| f.owner_sub == owner_sub)
                .map(|f| f.id.clone())
                .collect()
        };
        let items = self.items.lock().expect("items lock poisoned");
        let mut counts: Vec<(String, i64)> = Vec::new();
        for fid in &owned {
            let n = items
                .iter()
                .filter(|i| !i.read && &i.feed_id == fid)
                .count() as i64;
            if n > 0 {
                counts.push((fid.clone(), n));
            }
        }
        Ok(counts)
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
const FEED_COLS: &str =
    "id, owner_sub, url, title, last_fetched, created_at, category_id, full_content, last_error, last_error_at, consecutive_failures";
/// Column list shared by every item SELECT, so the row decoder stays in lock-step.
const ITEM_COLS: &str =
    "id, feed_id, guid, title, link, summary, published_at, read, full_text, starred";
/// Column list shared by every category SELECT.
const CATEGORY_COLS: &str = "id, owner_sub, name, position";

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
        // Star/save flag on an item (independent of read). Idempotent ALTER, portable BOOLEAN.
        sqlx::query("ALTER TABLE items ADD COLUMN IF NOT EXISTS starred BOOLEAN NOT NULL DEFAULT FALSE")
            .execute(&self.pool)
            .await?;
        // Category grouping: nullable feed -> category link + per-feed full-content toggle. Both via
        // idempotent ALTERs so pre-existing deployments backfill without a rewrite.
        sqlx::query("ALTER TABLE feeds ADD COLUMN IF NOT EXISTS category_id TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE feeds ADD COLUMN IF NOT EXISTS full_content BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE feeds ADD COLUMN IF NOT EXISTS last_error TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE feeds ADD COLUMN IF NOT EXISTS last_error_at BIGINT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE feeds ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        // User-defined feed categories/groups (per owner).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS feed_categories (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 name TEXT NOT NULL, \
                 position BIGINT NOT NULL DEFAULT 0, \
                 UNIQUE (owner_sub, name)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Per-entry extracted-body cache keyed by entry id (populated by the full-content reader).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS entry_content (\
                 entry_id TEXT PRIMARY KEY, \
                 content TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_feeds_owner ON feeds (owner_sub)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_feed_categories_owner ON feed_categories (owner_sub)",
        )
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
            category_id: row.try_get::<Option<String>, _>("category_id")?,
            full_content: row.try_get("full_content")?,
            last_error: row.try_get("last_error")?,
            last_error_at: row.try_get("last_error_at")?,
            consecutive_failures: row.try_get::<i32, _>("consecutive_failures")? as i64,
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
            starred: row.try_get("starred")?,
        })
    }

    fn category_from_row(row: &sqlx::postgres::PgRow) -> Result<Category, sqlx::Error> {
        Ok(Category {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            name: row.try_get("name")?,
            position: row.try_get("position")?,
        })
    }
}

#[async_trait]
impl Store for PgStore {
    async fn add_feed(&self, feed: &Feed) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO feeds \
                 (id, owner_sub, url, title, last_fetched, created_at, category_id, full_content) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (owner_sub, url) DO NOTHING",
        )
        .bind(&feed.id)
        .bind(&feed.owner_sub)
        .bind(&feed.url)
        .bind(&feed.title)
        .bind(feed.last_fetched)
        .bind(feed.created_at)
        .bind(&feed.category_id)
        .bind(feed.full_content)
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
        sqlx::query(
            "UPDATE feeds SET title = $2, last_fetched = $3, \
                 last_error = NULL, last_error_at = NULL, consecutive_failures = 0 \
             WHERE id = $1",
        )
            .bind(id)
            .bind(title)
            .bind(last_fetched)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn record_fetch_failure(
        &self,
        id: &str,
        now: i64,
        error: &str,
    ) -> Result<(), StoreError> {
        let error = truncate_fetch_error(error);
        sqlx::query(
            "UPDATE feeds SET last_error = $2, last_error_at = $3, \
                 consecutive_failures = consecutive_failures + 1 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(error)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn upsert_item(&self, item: &Item) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO items \
                 (id, feed_id, guid, title, link, summary, published_at, read, full_text, starred) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
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
        .bind(item.starred)
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

    async fn list_categories(&self, owner_sub: &str) -> Result<Vec<Category>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {CATEGORY_COLS} FROM feed_categories \
             WHERE owner_sub = $1 ORDER BY position ASC, name ASC"
        ))
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(Self::category_from_row)
            .collect::<Result<_, _>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn add_category(&self, category: &Category) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO feed_categories (id, owner_sub, name, position) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (owner_sub, name) DO NOTHING",
        )
        .bind(&category.id)
        .bind(&category.owner_sub)
        .bind(&category.name)
        .bind(category.position)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    async fn rename_category(
        &self,
        id: &str,
        owner_sub: &str,
        name: &str,
    ) -> Result<bool, StoreError> {
        // A rename colliding with another of this owner's category names must not violate the UNIQUE
        // constraint, so guard it with a NOT EXISTS on the target name (excluding this row).
        let result = sqlx::query(
            "UPDATE feed_categories SET name = $3 WHERE id = $1 AND owner_sub = $2 \
             AND NOT EXISTS (SELECT 1 FROM feed_categories \
                 WHERE owner_sub = $2 AND name = $3 AND id <> $1)",
        )
        .bind(id)
        .bind(owner_sub)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_category(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        // Detach the category's feeds first (uncategorize; never delete a feed), then drop the row.
        sqlx::query(
            "UPDATE feeds SET category_id = NULL WHERE owner_sub = $2 AND category_id = $1",
        )
        .bind(id)
        .bind(owner_sub)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        let result = sqlx::query("DELETE FROM feed_categories WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_category_position(
        &self,
        id: &str,
        owner_sub: &str,
        position: i64,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("UPDATE feed_categories SET position = $3 WHERE id = $1 AND owner_sub = $2")
                .bind(id)
                .bind(owner_sub)
                .bind(position)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn assign_feed_category(
        &self,
        feed_id: &str,
        owner_sub: &str,
        category_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        // Owner-scoped, and a non-NULL category must ALSO be owned by owner_sub (the EXISTS guard).
        let result = sqlx::query(
            "UPDATE feeds SET category_id = $3 WHERE id = $1 AND owner_sub = $2 \
             AND ($3 IS NULL OR EXISTS (SELECT 1 FROM feed_categories \
                 WHERE id = $3 AND owner_sub = $2))",
        )
        .bind(feed_id)
        .bind(owner_sub)
        .bind(category_id)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_feed_full_content(
        &self,
        id: &str,
        owner_sub: &str,
        on: bool,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("UPDATE feeds SET full_content = $3 WHERE id = $1 AND owner_sub = $2")
                .bind(id)
                .bind(owner_sub)
                .bind(on)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
    ) -> Result<Option<String>, StoreError> {
        // The entry must belong to one of the owner's feeds (join gate).
        let row = sqlx::query(
            "SELECT ec.content AS content FROM entry_content ec \
             JOIN items i ON i.id = ec.entry_id \
             JOIN feeds f ON f.id = i.feed_id \
             WHERE ec.entry_id = $1 AND f.owner_sub = $2",
        )
        .bind(entry_id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        match row {
            Some(r) => Ok(Some(
                r.try_get("content").map_err(|e| StoreError::Backend(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn set_entry_content(
        &self,
        entry_id: &str,
        owner_sub: &str,
        content: &str,
    ) -> Result<bool, StoreError> {
        // Ownership gate: only write when the entry belongs to one of the owner's feeds.
        let owned = sqlx::query(
            "SELECT 1 AS one FROM items i JOIN feeds f ON f.id = i.feed_id \
             WHERE i.id = $1 AND f.owner_sub = $2",
        )
        .bind(entry_id)
        .bind(owner_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        if owned.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO entry_content (entry_id, content, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (entry_id) DO UPDATE SET content = EXCLUDED.content",
        )
        .bind(entry_id)
        .bind(content)
        .bind(crate::now_secs())
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(true)
    }

    async fn set_item_starred(
        &self,
        id: &str,
        owner_sub: &str,
        starred: bool,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE items SET starred = $3 \
             WHERE id = $1 AND feed_id IN (SELECT id FROM feeds WHERE owner_sub = $2)",
        )
        .bind(id)
        .bind(owner_sub)
        .bind(starred)
        .execute(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    async fn river_filtered(
        &self,
        owner_sub: &str,
        filter: &str,
        limit: i64,
    ) -> Result<Vec<RiverEntry>, StoreError> {
        let cond = match filter {
            "starred" => "i.starred = TRUE",
            "all" => "TRUE",
            _ => "i.read = FALSE",
        };
        let rows = sqlx::query(&format!(
            "SELECT {item_cols}, f.title AS feed_title \
             FROM items i JOIN feeds f ON f.id = i.feed_id \
             WHERE f.owner_sub = $1 AND {cond} \
             ORDER BY COALESCE(i.published_at, 0) DESC, i.id DESC \
             LIMIT $2",
            item_cols = ITEM_COLS
                .split(", ")
                .map(|c| format!("i.{c}"))
                .collect::<Vec<_>>()
                .join(", "),
            cond = cond,
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

    async fn feed_unread_counts(
        &self,
        owner_sub: &str,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let rows = sqlx::query(
            "SELECT i.feed_id AS feed_id, COUNT(*) AS c \
             FROM items i JOIN feeds f ON f.id = i.feed_id \
             WHERE f.owner_sub = $1 AND i.read = FALSE \
             GROUP BY i.feed_id",
        )
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(|r| Ok((r.try_get("feed_id")?, r.try_get("c")?)))
            .collect::<Result<_, sqlx::Error>>()
            .map_err(|e| StoreError::Backend(e.to_string()))
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
            last_error: None,
            last_error_at: None,
            consecutive_failures: 0,
            created_at: created,
            category_id: None,
            full_content: false,
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
            starred: false,
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

    fn cat(id: &str, owner: &str, name: &str, pos: i64) -> Category {
        Category {
            id: id.into(),
            owner_sub: owner.into(),
            name: name.into(),
            position: pos,
        }
    }

    #[tokio::test]
    async fn categories_crud_ordering_and_conflict() {
        let s = InMemoryStore::new();
        assert!(s.add_category(&cat("c1", "u", "News", 0)).await.unwrap());
        assert!(s.add_category(&cat("c2", "u", "Blogs", 1)).await.unwrap());
        // Duplicate (owner, name) -> no-op.
        assert!(!s.add_category(&cat("c3", "u", "News", 2)).await.unwrap());
        // Another owner may reuse the name.
        assert!(s.add_category(&cat("c4", "v", "News", 0)).await.unwrap());

        let mine = s.list_categories("u").await.unwrap();
        let ids: Vec<&str> = mine.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["c1", "c2"], "ordered by position");

        // Rename: ok, and a rename onto a sibling's name is rejected.
        assert!(s.rename_category("c1", "u", "Headlines").await.unwrap());
        assert!(!s.rename_category("c1", "u", "Blogs").await.unwrap());
        // Foreign rename -> no-op.
        assert!(!s.rename_category("c1", "intruder", "Hax").await.unwrap());

        // Reorder by swapping positions.
        s.set_category_position("c1", "u", 5).await.unwrap();
        let reordered = s.list_categories("u").await.unwrap();
        assert_eq!(reordered[0].id, "c2", "c2 now sorts first");
    }

    #[tokio::test]
    async fn assign_and_delete_category_is_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.add_category(&cat("c1", "u", "News", 0)).await.unwrap();
        s.add_category(&cat("cv", "v", "Other", 0)).await.unwrap();

        // Assign the feed to an owned category.
        assert!(s.assign_feed_category("f1", "u", Some("c1")).await.unwrap());
        assert_eq!(s.get_feed("f1").await.unwrap().unwrap().category_id.as_deref(), Some("c1"));
        // Cannot assign to a category owned by someone else.
        assert!(!s.assign_feed_category("f1", "u", Some("cv")).await.unwrap());
        assert_eq!(s.get_feed("f1").await.unwrap().unwrap().category_id.as_deref(), Some("c1"));
        // A foreign owner cannot move my feed.
        assert!(!s.assign_feed_category("f1", "intruder", None).await.unwrap());

        // Deleting the category uncategorizes the feed but never deletes it.
        assert!(s.delete_category("c1", "u").await.unwrap());
        let f = s.get_feed("f1").await.unwrap().unwrap();
        assert!(f.category_id.is_none(), "feed uncategorized after category delete");
    }

    #[tokio::test]
    async fn feed_unread_counts_are_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.add_feed(&feed("f2", "u", "https://b.com/rss", 2)).await.unwrap();
        s.add_feed(&feed("f3", "other", "https://c.com/rss", 3)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();
        s.upsert_item(&item("i2", "f1", "g2", Some(20))).await.unwrap();
        let mut read = item("i3", "f1", "g3", Some(30));
        read.read = true;
        s.upsert_item(&read).await.unwrap();
        s.upsert_item(&item("i4", "f2", "g4", Some(40))).await.unwrap();
        s.upsert_item(&item("i5", "f3", "g5", Some(50))).await.unwrap(); // other owner

        let counts = s.feed_unread_counts("u").await.unwrap();
        let map: std::collections::HashMap<String, i64> = counts.into_iter().collect();
        assert_eq!(map.get("f1"), Some(&2));
        assert_eq!(map.get("f2"), Some(&1));
        assert!(!map.contains_key("f3"), "other owner's feed excluded");
    }

    #[tokio::test]
    async fn star_and_river_filtered() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();
        s.upsert_item(&item("i2", "f1", "g2", Some(20))).await.unwrap();

        // Star i1; a foreign owner cannot.
        assert!(!s.set_item_starred("i1", "intruder", true).await.unwrap());
        assert!(s.set_item_starred("i1", "u", true).await.unwrap());

        // unread: both (both unread), starred: only i1, all: both.
        assert_eq!(s.river_filtered("u", "unread", 100).await.unwrap().len(), 2);
        let starred = s.river_filtered("u", "starred", 100).await.unwrap();
        assert_eq!(starred.len(), 1);
        assert_eq!(starred[0].item.id, "i1");
        assert!(starred[0].item.starred);

        // Mark i1 read: it stays in starred (star is independent of read) but leaves unread.
        s.mark_item_read("i1", "u").await.unwrap();
        assert_eq!(s.river_filtered("u", "unread", 100).await.unwrap().len(), 1);
        assert_eq!(s.river_filtered("u", "starred", 100).await.unwrap().len(), 1);
        assert_eq!(s.river_filtered("u", "all", 100).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn full_content_toggle_and_entry_cache_owner_scoped() {
        let s = InMemoryStore::new();
        s.add_feed(&feed("f1", "u", "https://a.com/rss", 1)).await.unwrap();
        s.upsert_item(&item("i1", "f1", "g1", Some(10))).await.unwrap();

        // Toggle the per-feed full-content flag.
        assert!(!s.set_feed_full_content("f1", "intruder", true).await.unwrap());
        assert!(s.set_feed_full_content("f1", "u", true).await.unwrap());
        assert!(s.get_feed("f1").await.unwrap().unwrap().full_content);

        // Entry-content cache is owner-scoped both ways.
        assert!(!s.set_entry_content("i1", "intruder", "hax").await.unwrap());
        assert!(s.get_entry_content("i1", "intruder").await.unwrap().is_none());
        assert!(s.set_entry_content("i1", "u", "Para one.\n\nPara two.").await.unwrap());
        assert_eq!(
            s.get_entry_content("i1", "u").await.unwrap().as_deref(),
            Some("Para one.\n\nPara two.")
        );
    }
}
