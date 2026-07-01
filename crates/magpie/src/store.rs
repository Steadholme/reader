//! Clip storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the pastefire/cortex seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT/BOOLEAN,
//! PRIMARY KEY/NOT NULL/DEFAULT, parameterized queries, `INSERT .. ON CONFLICT`, plain indexes)
//! and runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;
use crate::model::{tags_contain, Clip, Cursor, Filter};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable clip store. `create` is collision-aware on the id; per-row mutations
/// (`mark_read`/`set_archived`/`delete`) are ownership-scoped (only the owner's row changes).
#[async_trait]
pub trait Store: Send + Sync {
    /// Insert a clip. Returns `Ok(true)` when inserted, `Ok(false)` when the id already existed
    /// (the caller retries with a new id). Idempotent at the id level.
    async fn create(&self, clip: &Clip) -> Result<bool, StoreError>;

    /// Fetch a clip by id (ownership is enforced by the caller against `owner_sub`).
    async fn get(&self, id: &str) -> Result<Option<Clip>, StoreError>;

    /// Find an owner's existing clip for an exact URL (de-dup: re-clipping a saved URL updates
    /// the existing row instead of creating a duplicate).
    async fn find_by_owner_url(&self, owner_sub: &str, url: &str)
        -> Result<Option<Clip>, StoreError>;

    /// An owner's clips for `filter`, newest-first, capped at [`LIST_LIMIT`].
    async fn list(&self, owner_sub: &str, filter: Filter) -> Result<Vec<Clip>, StoreError>;

    /// An owner's NON-archived clips carrying `tag` (whole-token match), newest-first, capped at
    /// [`LIST_LIMIT`].
    async fn list_by_tag(&self, owner_sub: &str, tag: &str) -> Result<Vec<Clip>, StoreError>;

    /// Full-text-ish search over an owner's clips (`title` + extracted `content_text`,
    /// case-insensitive substring), newest-first, keyset-paginated: `before` is the last row of the
    /// previous page (exclusive) and at most `limit` rows are returned.
    async fn search(
        &self,
        owner_sub: &str,
        query: &str,
        before: Option<&Cursor>,
        limit: usize,
    ) -> Result<Vec<Clip>, StoreError>;

    /// Replace the tags on an owner's clip (`None` clears them). Returns `true` when a row changed.
    async fn set_tags(
        &self,
        id: &str,
        owner_sub: &str,
        tags: Option<String>,
    ) -> Result<bool, StoreError>;

    /// Mark an owner's clip read. Returns `true` when a row was updated.
    async fn mark_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;

    /// Set the archived flag on an owner's clip. Returns `true` when a row was updated.
    async fn set_archived(
        &self,
        id: &str,
        owner_sub: &str,
        archived: bool,
    ) -> Result<bool, StoreError>;

    /// Delete an owner's clip. Returns `true` when a row was removed (existed AND owned).
    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here.
#[derive(Default)]
pub struct InMemoryStore {
    clips: Mutex<Vec<Clip>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn create(&self, clip: &Clip) -> Result<bool, StoreError> {
        let mut clips = self.clips.lock().expect("clips lock poisoned");
        if clips.iter().any(|c| c.id == clip.id) {
            return Ok(false);
        }
        clips.push(clip.clone());
        Ok(true)
    }

    async fn get(&self, id: &str) -> Result<Option<Clip>, StoreError> {
        let clips = self.clips.lock().expect("clips lock poisoned");
        Ok(clips.iter().find(|c| c.id == id).cloned())
    }

    async fn find_by_owner_url(
        &self,
        owner_sub: &str,
        url: &str,
    ) -> Result<Option<Clip>, StoreError> {
        let clips = self.clips.lock().expect("clips lock poisoned");
        Ok(clips
            .iter()
            .find(|c| c.owner_sub == owner_sub && c.url == url)
            .cloned())
    }

    async fn list(&self, owner_sub: &str, filter: Filter) -> Result<Vec<Clip>, StoreError> {
        let clips = self.clips.lock().expect("clips lock poisoned");
        let mut out: Vec<Clip> = clips
            .iter()
            .filter(|c| c.owner_sub == owner_sub && filter.matches(c))
            .cloned()
            .collect();
        // Newest first; id as a deterministic tiebreak when saved_at collides (same second).
        out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at).then_with(|| b.id.cmp(&a.id)));
        out.truncate(LIST_LIMIT);
        Ok(out)
    }

    async fn list_by_tag(&self, owner_sub: &str, tag: &str) -> Result<Vec<Clip>, StoreError> {
        let clips = self.clips.lock().expect("clips lock poisoned");
        let mut out: Vec<Clip> = clips
            .iter()
            .filter(|c| c.owner_sub == owner_sub && !c.archived && tags_contain(&c.tags, tag))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at).then_with(|| b.id.cmp(&a.id)));
        out.truncate(LIST_LIMIT);
        Ok(out)
    }

    async fn search(
        &self,
        owner_sub: &str,
        query: &str,
        before: Option<&Cursor>,
        limit: usize,
    ) -> Result<Vec<Clip>, StoreError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let clips = self.clips.lock().expect("clips lock poisoned");
        let mut out: Vec<Clip> = clips
            .iter()
            .filter(|c| {
                c.owner_sub == owner_sub
                    && (c.title.to_lowercase().contains(&needle)
                        || c.content_text.to_lowercase().contains(&needle))
            })
            .cloned()
            .collect();
        // Newest-first; the same total order the keyset cursor walks.
        out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at).then_with(|| b.id.cmp(&a.id)));
        // Keyset: keep only rows strictly AFTER the cursor in that order (exclusive).
        if let Some(cur) = before {
            out.retain(|c| {
                c.saved_at < cur.saved_at || (c.saved_at == cur.saved_at && c.id < cur.id)
            });
        }
        out.truncate(limit);
        Ok(out)
    }

    async fn set_tags(
        &self,
        id: &str,
        owner_sub: &str,
        tags: Option<String>,
    ) -> Result<bool, StoreError> {
        let mut clips = self.clips.lock().expect("clips lock poisoned");
        match clips
            .iter_mut()
            .find(|c| c.id == id && c.owner_sub == owner_sub)
        {
            Some(c) => {
                c.tags = tags;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn mark_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut clips = self.clips.lock().expect("clips lock poisoned");
        match clips
            .iter_mut()
            .find(|c| c.id == id && c.owner_sub == owner_sub)
        {
            Some(c) => {
                let changed = !c.read;
                c.read = true;
                Ok(changed)
            }
            None => Ok(false),
        }
    }

    async fn set_archived(
        &self,
        id: &str,
        owner_sub: &str,
        archived: bool,
    ) -> Result<bool, StoreError> {
        let mut clips = self.clips.lock().expect("clips lock poisoned");
        match clips
            .iter_mut()
            .find(|c| c.id == id && c.owner_sub == owner_sub)
        {
            Some(c) => {
                c.archived = archived;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        let mut clips = self.clips.lock().expect("clips lock poisoned");
        let before = clips.len();
        clips.retain(|c| !(c.id == id && c.owner_sub == owner_sub));
        Ok(clips.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `MAGPIE_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Column list shared by every SELECT, so the row decoder stays in lock-step with the query.
const COLS: &str =
    "id, owner_sub, url, title, excerpt, content_text, site, saved_at, read, archived, tags";

/// Escape the LIKE metacharacters (`\`, `%`, `_`) in a user-supplied needle so it matches
/// literally under `LIKE ... ESCAPE '\'`. Backslash first, so the escapes we add are not re-escaped.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

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

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup. The
    /// composite index backs the per-owner reading-list lookup (`owner_sub` filter +
    /// `saved_at` ordering).
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS clips (\
                 id TEXT PRIMARY KEY, \
                 owner_sub TEXT NOT NULL, \
                 url TEXT NOT NULL, \
                 title TEXT NOT NULL, \
                 excerpt TEXT NOT NULL, \
                 content_text TEXT NOT NULL, \
                 site TEXT NOT NULL, \
                 saved_at BIGINT NOT NULL, \
                 read BOOLEAN NOT NULL DEFAULT FALSE, \
                 archived BOOLEAN NOT NULL DEFAULT FALSE\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Additive, idempotent evolution: the nullable tags column. Portable standard SQL
        // (`ADD COLUMN IF NOT EXISTS`) — safe to re-run on every boot, no data migration.
        sqlx::query("ALTER TABLE clips ADD COLUMN IF NOT EXISTS tags TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_clips_owner_saved \
             ON clips (owner_sub, saved_at)",
        )
        .execute(&self.pool)
        .await?;
        // Backs the de-dup lookup (an owner's existing clip for a URL).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_clips_owner_url \
             ON clips (owner_sub, url)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn clip_from_row(row: &sqlx::postgres::PgRow) -> Result<Clip, sqlx::Error> {
        Ok(Clip {
            id: row.try_get("id")?,
            owner_sub: row.try_get("owner_sub")?,
            url: row.try_get("url")?,
            title: row.try_get("title")?,
            excerpt: row.try_get("excerpt")?,
            content_text: row.try_get("content_text")?,
            site: row.try_get("site")?,
            saved_at: row.try_get("saved_at")?,
            read: row.try_get("read")?,
            archived: row.try_get("archived")?,
            tags: row.try_get("tags")?,
        })
    }

    async fn create_async(&self, clip: &Clip) -> Result<bool, sqlx::Error> {
        // ON CONFLICT DO NOTHING => 0 rows affected signals an id collision; the handler then
        // retries with a fresh id. This is the single, race-free insert path.
        let result = sqlx::query(
            "INSERT INTO clips \
                 (id, owner_sub, url, title, excerpt, content_text, site, saved_at, read, archived, tags) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&clip.id)
        .bind(&clip.owner_sub)
        .bind(&clip.url)
        .bind(&clip.title)
        .bind(&clip.excerpt)
        .bind(&clip.content_text)
        .bind(&clip.site)
        .bind(clip.saved_at)
        .bind(clip.read)
        .bind(clip.archived)
        .bind(&clip.tags)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_async(&self, id: &str) -> Result<Option<Clip>, sqlx::Error> {
        let row = sqlx::query(&format!("SELECT {COLS} FROM clips WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(Self::clip_from_row).transpose()
    }

    async fn find_by_owner_url_async(
        &self,
        owner_sub: &str,
        url: &str,
    ) -> Result<Option<Clip>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {COLS} FROM clips WHERE owner_sub = $1 AND url = $2 LIMIT 1"
        ))
        .bind(owner_sub)
        .bind(url)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::clip_from_row).transpose()
    }

    async fn list_async(&self, owner_sub: &str, filter: Filter) -> Result<Vec<Clip>, sqlx::Error> {
        // Each view is a standard-SQL predicate over the boolean flags.
        let predicate = match filter {
            Filter::All => "archived = FALSE",
            Filter::Unread => "archived = FALSE AND read = FALSE",
            Filter::Archived => "archived = TRUE",
        };
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM clips \
             WHERE owner_sub = $1 AND {predicate} \
             ORDER BY saved_at DESC, id DESC LIMIT $2"
        ))
        .bind(owner_sub)
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::clip_from_row).collect()
    }

    async fn list_by_tag_async(
        &self,
        owner_sub: &str,
        tag: &str,
    ) -> Result<Vec<Clip>, sqlx::Error> {
        // Whole-token match against the normalized comma list: wrap both sides in commas so
        // `,tag,` cannot match a substring of a neighbouring tag. `ESCAPE '\'` neutralizes any
        // LIKE metacharacters in the token.
        let pattern = format!("%,{},%", like_escape(&tag.trim().to_lowercase()));
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM clips \
             WHERE owner_sub = $1 AND archived = FALSE AND tags IS NOT NULL \
               AND (',' || LOWER(tags) || ',') LIKE $2 ESCAPE '\\' \
             ORDER BY saved_at DESC, id DESC LIMIT $3"
        ))
        .bind(owner_sub)
        .bind(pattern)
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::clip_from_row).collect()
    }

    async fn search_async(
        &self,
        owner_sub: &str,
        query: &str,
        before: Option<&Cursor>,
        limit: usize,
    ) -> Result<Vec<Clip>, sqlx::Error> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = format!("%{}%", like_escape(&needle));
        // Keyset predicate over the (saved_at DESC, id DESC) order: rows strictly after the cursor.
        // Bound positionally so the same statement runs unchanged on FusionDB over pgwire.
        let (keyset, has_cursor) = match before {
            Some(_) => (" AND (saved_at < $3 OR (saved_at = $3 AND id < $4))", true),
            None => ("", false),
        };
        let limit_pos = if has_cursor { "$5" } else { "$3" };
        let sql = format!(
            "SELECT {COLS} FROM clips \
             WHERE owner_sub = $1 \
               AND (LOWER(title) LIKE $2 ESCAPE '\\' OR LOWER(content_text) LIKE $2 ESCAPE '\\')\
             {keyset} \
             ORDER BY saved_at DESC, id DESC LIMIT {limit_pos}"
        );
        let mut q = sqlx::query(&sql).bind(owner_sub).bind(pattern);
        if let Some(cur) = before {
            q = q.bind(cur.saved_at).bind(&cur.id);
        }
        let rows = q.bind(limit as i64).fetch_all(&self.pool).await?;
        rows.iter().map(Self::clip_from_row).collect()
    }

    async fn set_tags_async(
        &self,
        id: &str,
        owner_sub: &str,
        tags: Option<String>,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE clips SET tags = $3 WHERE id = $1 AND owner_sub = $2")
                .bind(id)
                .bind(owner_sub)
                .bind(&tags)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_read_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE clips SET read = TRUE WHERE id = $1 AND owner_sub = $2")
                .bind(id)
                .bind(owner_sub)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn set_archived_async(
        &self,
        id: &str,
        owner_sub: &str,
        archived: bool,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE clips SET archived = $3 WHERE id = $1 AND owner_sub = $2")
                .bind(id)
                .bind(owner_sub)
                .bind(archived)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_async(&self, id: &str, owner_sub: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM clips WHERE id = $1 AND owner_sub = $2")
            .bind(id)
            .bind(owner_sub)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn create(&self, clip: &Clip) -> Result<bool, StoreError> {
        self.create_async(clip)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get(&self, id: &str) -> Result<Option<Clip>, StoreError> {
        self.get_async(id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn find_by_owner_url(
        &self,
        owner_sub: &str,
        url: &str,
    ) -> Result<Option<Clip>, StoreError> {
        self.find_by_owner_url_async(owner_sub, url)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list(&self, owner_sub: &str, filter: Filter) -> Result<Vec<Clip>, StoreError> {
        self.list_async(owner_sub, filter)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_by_tag(&self, owner_sub: &str, tag: &str) -> Result<Vec<Clip>, StoreError> {
        self.list_by_tag_async(owner_sub, tag)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn search(
        &self,
        owner_sub: &str,
        query: &str,
        before: Option<&Cursor>,
        limit: usize,
    ) -> Result<Vec<Clip>, StoreError> {
        self.search_async(owner_sub, query, before, limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_tags(
        &self,
        id: &str,
        owner_sub: &str,
        tags: Option<String>,
    ) -> Result<bool, StoreError> {
        self.set_tags_async(id, owner_sub, tags)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn mark_read(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.mark_read_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_archived(
        &self,
        id: &str,
        owner_sub: &str,
        archived: bool,
    ) -> Result<bool, StoreError> {
        self.set_archived_async(id, owner_sub, archived)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete(&self, id: &str, owner_sub: &str) -> Result<bool, StoreError> {
        self.delete_async(id, owner_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clip(id: &str, owner: &str, url: &str, saved_at: i64) -> Clip {
        Clip {
            id: id.into(),
            owner_sub: owner.into(),
            url: url.into(),
            title: "t".into(),
            excerpt: "e".into(),
            content_text: "c".into(),
            site: "s".into(),
            saved_at,
            read: false,
            archived: false,
            tags: None,
        }
    }

    fn tagged(id: &str, owner: &str, saved_at: i64, tags: &str) -> Clip {
        let mut c = clip(id, owner, &format!("https://x/{id}"), saved_at);
        c.tags = crate::model::normalize_tags(tags);
        c
    }

    #[tokio::test]
    async fn create_is_collision_aware() {
        let s = InMemoryStore::new();
        assert!(s.create(&clip("a", "u", "https://x", 1)).await.unwrap());
        assert!(!s.create(&clip("a", "u", "https://y", 2)).await.unwrap());
    }

    #[tokio::test]
    async fn list_filters_by_view_and_owner() {
        let s = InMemoryStore::new();
        s.create(&clip("a", "u", "https://a", 10)).await.unwrap();
        s.create(&clip("b", "u", "https://b", 20)).await.unwrap();
        s.mark_read("b", "u").await.unwrap();
        s.create(&clip("c", "u", "https://c", 30)).await.unwrap();
        s.set_archived("c", "u", true).await.unwrap();
        s.create(&clip("d", "other", "https://d", 40)).await.unwrap();

        let all = s.list("u", Filter::All).await.unwrap();
        // newest-first, archived + other-owner excluded
        assert_eq!(all.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["b", "a"]);

        let unread = s.list("u", Filter::Unread).await.unwrap();
        assert_eq!(unread.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["a"]);

        let archived = s.list("u", Filter::Archived).await.unwrap();
        assert_eq!(archived.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["c"]);
    }

    #[tokio::test]
    async fn find_by_owner_url_scopes_to_owner() {
        let s = InMemoryStore::new();
        s.create(&clip("a", "u", "https://x", 1)).await.unwrap();
        assert!(s.find_by_owner_url("u", "https://x").await.unwrap().is_some());
        assert!(s.find_by_owner_url("u", "https://y").await.unwrap().is_none());
        assert!(s.find_by_owner_url("other", "https://x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_by_tag_matches_whole_token_and_scopes_owner() {
        let s = InMemoryStore::new();
        s.create(&tagged("a", "u", 10, "Rust,web")).await.unwrap();
        s.create(&tagged("b", "u", 20, "rust,async")).await.unwrap();
        s.create(&tagged("c", "u", 30, "gardening")).await.unwrap();
        s.create(&tagged("d", "other", 40, "rust")).await.unwrap();
        // archived clip with the tag is excluded from the active tag view.
        s.create(&tagged("e", "u", 50, "rust")).await.unwrap();
        s.set_archived("e", "u", true).await.unwrap();

        let rust = s.list_by_tag("u", "rust").await.unwrap();
        assert_eq!(rust.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["b", "a"]);
        // whole-token: "web" must not match "web-dev"-style substrings
        s.create(&tagged("f", "u", 60, "web-dev")).await.unwrap();
        let web = s.list_by_tag("u", "web").await.unwrap();
        assert_eq!(web.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
    }

    #[tokio::test]
    async fn search_matches_title_and_body_keyset_paginated() {
        let s = InMemoryStore::new();
        for (id, saved) in [("a", 10), ("b", 20), ("c", 30)] {
            let mut c = clip(id, "u", &format!("https://x/{id}"), saved);
            c.title = format!("Widget {id}");
            c.content_text = "shared body about widgets".into();
            s.create(&c).await.unwrap();
        }
        // A non-matching clip and another owner's matching clip are excluded.
        s.create(&clip("z", "u", "https://x/z", 40)).await.unwrap();
        let mut other = clip("o", "other", "https://x/o", 50);
        other.content_text = "widgets".into();
        s.create(&other).await.unwrap();

        // Page 1 (limit 2), newest-first.
        let p1 = s.search("u", "widget", None, 2).await.unwrap();
        assert_eq!(p1.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["c", "b"]);
        // Page 2 continues strictly after the cursor.
        let cur = Cursor { saved_at: p1[1].saved_at, id: p1[1].id.clone() };
        let p2 = s.search("u", "widget", Some(&cur), 2).await.unwrap();
        assert_eq!(p2.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["a"]);
        // Case-insensitive, and matches body-only clips.
        assert_eq!(s.search("u", "WIDGETS", None, 10).await.unwrap().len(), 3);
        // Empty query returns nothing.
        assert!(s.search("u", "  ", None, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_tags_is_ownership_scoped() {
        let s = InMemoryStore::new();
        s.create(&clip("a", "u", "https://x", 1)).await.unwrap();
        assert!(!s.set_tags("a", "intruder", Some("rust".into())).await.unwrap());
        assert!(s.set_tags("a", "u", crate::model::normalize_tags("Rust, Web")).await.unwrap());
        assert_eq!(s.get("a").await.unwrap().unwrap().tags.as_deref(), Some("rust,web"));
        assert!(s.set_tags("a", "u", None).await.unwrap());
        assert!(s.get("a").await.unwrap().unwrap().tags.is_none());
    }

    #[tokio::test]
    async fn mutations_are_ownership_scoped() {
        let s = InMemoryStore::new();
        s.create(&clip("a", "u", "https://x", 1)).await.unwrap();
        assert!(!s.mark_read("a", "intruder").await.unwrap());
        assert!(!s.set_archived("a", "intruder", true).await.unwrap());
        assert!(!s.delete("a", "intruder").await.unwrap());
        assert!(s.get("a").await.unwrap().is_some());
        assert!(s.delete("a", "u").await.unwrap());
        assert!(s.get("a").await.unwrap().is_none());
    }
}
