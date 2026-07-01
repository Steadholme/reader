//! Note + follower storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! inkwell/keystone seam: handlers depend only on the trait, so a FusionDB-backed store can drop in
//! later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT, PK/UNIQUE/NOT NULL/
//! DEFAULT, parameterized queries, `INSERT .. ON CONFLICT`, `CREATE INDEX`) and runtime queries (no
//! compile-time macros), so the build needs NO database and the same statements later run unchanged
//! on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge, so a
//! DB round-trip never blocks a worker thread. The PRIMARY KEY (notes.id, followers.actor) and the
//! `ON CONFLICT` upsert enforce all uniqueness atomically, so no in-process write serializer is
//! needed.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// A local microblog note (maps 1:1 to a `notes` row).
#[derive(Clone, Debug)]
pub struct Note {
    pub id: String,
    pub author_sub: String,
    pub content: String,
    pub visibility: String,
    pub created_at: i64,
    /// Epoch seconds of the last owner edit, or `0` when the note has never been edited.
    pub updated_at: i64,
}

/// A remote actor that follows us (maps 1:1 to a `followers` row).
#[derive(Clone, Debug)]
pub struct Follower {
    /// The follower's actor id URL (the PRIMARY KEY).
    pub actor: String,
    /// The follower's resolved inbox URL, or `""` until discovery succeeds.
    pub inbox_url: String,
    pub created_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A row with this primary key already exists.
    #[error("already exists: {0}")]
    Conflict(String),
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable note + follower store.
#[async_trait]
pub trait Store: Send + Sync {
    /// Public notes, newest-first (`created_at` DESC), capped at [`LIST_LIMIT`].
    async fn list_notes(&self) -> Vec<Note>;
    /// One note by its id.
    async fn get_note(&self, id: &str) -> Option<Note>;
    /// Total number of public notes (the outbox `totalItems`).
    async fn count_notes(&self) -> i64;
    /// Insert a new note. Errors with [`StoreError::Conflict`] if the id is taken.
    async fn create_note(&self, note: &Note) -> Result<(), StoreError>;
    /// Owner-scoped edit of a note's content (stamping `updated_at`). Returns `Ok(true)` when a note
    /// with this id owned by `author_sub` was updated, `Ok(false)` when no such owned note exists (a
    /// missing note OR one belonging to someone else — the caller must NOT distinguish the two).
    async fn update_note(
        &self,
        id: &str,
        author_sub: &str,
        content: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError>;
    /// Owner-scoped delete of a note. Returns `Ok(true)` when a note with this id owned by
    /// `author_sub` was deleted, `Ok(false)` when no such owned note exists.
    async fn delete_note(&self, id: &str, author_sub: &str) -> Result<bool, StoreError>;

    /// All followers, newest-first.
    async fn list_followers(&self) -> Vec<Follower>;
    /// Total number of followers (the followers-collection `totalItems`).
    async fn count_followers(&self) -> i64;
    /// Record/refresh a follower. Idempotent: re-following updates the inbox URL only when the new
    /// one is non-empty (so a later bare re-Follow never erases a resolved inbox).
    async fn add_follower(&self, follower: &Follower) -> Result<(), StoreError>;
    /// Remove a follower by actor id (an `Undo` of a `Follow`).
    async fn remove_follower(&self, actor: &str) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    notes: Mutex<Vec<Note>>,
    followers: Mutex<Vec<Follower>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_notes(&self) -> Vec<Note> {
        let notes = self.notes.lock().expect("notes lock poisoned");
        let mut v: Vec<Note> = notes.iter().filter(|n| n.visibility == "public").cloned().collect();
        // Newest-first; ties broken by id so output is stable.
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(LIST_LIMIT);
        v
    }

    async fn get_note(&self, id: &str) -> Option<Note> {
        self.notes
            .lock()
            .expect("notes lock poisoned")
            .iter()
            .find(|n| n.id == id)
            .cloned()
    }

    async fn count_notes(&self) -> i64 {
        self.notes
            .lock()
            .expect("notes lock poisoned")
            .iter()
            .filter(|n| n.visibility == "public")
            .count() as i64
    }

    async fn create_note(&self, note: &Note) -> Result<(), StoreError> {
        let mut notes = self.notes.lock().expect("notes lock poisoned");
        if notes.iter().any(|n| n.id == note.id) {
            return Err(StoreError::Conflict(note.id.clone()));
        }
        notes.push(note.clone());
        Ok(())
    }

    async fn update_note(
        &self,
        id: &str,
        author_sub: &str,
        content: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let mut notes = self.notes.lock().expect("notes lock poisoned");
        match notes.iter_mut().find(|n| n.id == id && n.author_sub == author_sub) {
            Some(n) => {
                n.content = content.to_string();
                n.updated_at = updated_at;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_note(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        let mut notes = self.notes.lock().expect("notes lock poisoned");
        let before = notes.len();
        notes.retain(|n| !(n.id == id && n.author_sub == author_sub));
        Ok(notes.len() != before)
    }

    async fn list_followers(&self) -> Vec<Follower> {
        let f = self.followers.lock().expect("followers lock poisoned");
        let mut v: Vec<Follower> = f.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.actor.cmp(&a.actor)));
        v
    }

    async fn count_followers(&self) -> i64 {
        self.followers.lock().expect("followers lock poisoned").len() as i64
    }

    async fn add_follower(&self, follower: &Follower) -> Result<(), StoreError> {
        let mut f = self.followers.lock().expect("followers lock poisoned");
        match f.iter_mut().find(|x| x.actor == follower.actor) {
            Some(existing) => {
                // Only overwrite the inbox when the incoming value is non-empty.
                if !follower.inbox_url.is_empty() {
                    existing.inbox_url = follower.inbox_url.clone();
                }
            }
            None => f.push(follower.clone()),
        }
        Ok(())
    }

    async fn remove_follower(&self, actor: &str) -> Result<(), StoreError> {
        self.followers
            .lock()
            .expect("followers lock poisoned")
            .retain(|x| x.actor != actor);
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `CRIER_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The DB enforces the
// PK / ON CONFLICT, so no in-process serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
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
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS notes (\
                 id TEXT PRIMARY KEY, \
                 author_sub TEXT NOT NULL, \
                 content TEXT NOT NULL, \
                 visibility TEXT NOT NULL DEFAULT 'public', \
                 created_at BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Idempotently backfill the edit-timestamp column on pre-existing deployments.
        sqlx::query("ALTER TABLE notes ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes (created_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS followers (\
                 actor TEXT PRIMARY KEY, \
                 inbox_url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn note_from_row(row: &sqlx::postgres::PgRow) -> Result<Note, sqlx::Error> {
        Ok(Note {
            id: row.try_get("id")?,
            author_sub: row.try_get("author_sub")?,
            content: row.try_get("content")?,
            visibility: row.try_get("visibility")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn follower_from_row(row: &sqlx::postgres::PgRow) -> Result<Follower, sqlx::Error> {
        Ok(Follower {
            actor: row.try_get("actor")?,
            inbox_url: row.try_get("inbox_url")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn list_notes_async(&self) -> Result<Vec<Note>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, author_sub, content, visibility, created_at, updated_at \
             FROM notes WHERE visibility = 'public' \
             ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::note_from_row).collect()
    }

    async fn get_note_async(&self, id: &str) -> Result<Option<Note>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, author_sub, content, visibility, created_at, updated_at \
             FROM notes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::note_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn count_notes_async(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM notes WHERE visibility = 'public'")
            .fetch_one(&self.pool)
            .await?;
        row.try_get("c")
    }

    async fn create_note_async(&self, n: &Note) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO notes (id, author_sub, content, visibility, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&n.id)
        .bind(&n.author_sub)
        .bind(&n.content)
        .bind(&n.visibility)
        .bind(n.created_at)
        .bind(n.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_note_async(
        &self,
        id: &str,
        author_sub: &str,
        content: &str,
        updated_at: i64,
    ) -> Result<bool, sqlx::Error> {
        // Owner-scoped: the WHERE clause enforces authorization in the same statement, so a note
        // belonging to someone else is untouched and reports as "not found" to the caller.
        let res = sqlx::query(
            "UPDATE notes SET content = $1, updated_at = $2 WHERE id = $3 AND author_sub = $4",
        )
        .bind(content)
        .bind(updated_at)
        .bind(id)
        .bind(author_sub)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_note_async(&self, id: &str, author_sub: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM notes WHERE id = $1 AND author_sub = $2")
            .bind(id)
            .bind(author_sub)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_followers_async(&self) -> Result<Vec<Follower>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT actor, inbox_url, created_at FROM followers \
             ORDER BY created_at DESC, actor DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::follower_from_row).collect()
    }

    async fn count_followers_async(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM followers")
            .fetch_one(&self.pool)
            .await?;
        row.try_get("c")
    }

    async fn add_follower_async(&self, f: &Follower) -> Result<(), sqlx::Error> {
        // Upsert: a re-Follow refreshes the inbox only when the incoming value is non-empty, so a
        // bare Follow (inbox not yet resolved) never overwrites a previously-resolved inbox.
        sqlx::query(
            "INSERT INTO followers (actor, inbox_url, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (actor) DO UPDATE SET inbox_url = \
                 CASE WHEN EXCLUDED.inbox_url <> '' THEN EXCLUDED.inbox_url \
                      ELSE followers.inbox_url END",
        )
        .bind(&f.actor)
        .bind(&f.inbox_url)
        .bind(f.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_follower_async(&self, actor: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM followers WHERE actor = $1")
            .bind(actor)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_notes(&self) -> Vec<Note> {
        self.list_notes_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_notes failed");
            Vec::new()
        })
    }

    async fn get_note(&self, id: &str) -> Option<Note> {
        self.get_note_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_note failed");
            None
        })
    }

    async fn count_notes(&self) -> i64 {
        self.count_notes_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg count_notes failed");
            0
        })
    }

    async fn create_note(&self, note: &Note) -> Result<(), StoreError> {
        self.create_note_async(note).await.map_err(|e| {
            if is_unique_violation(&e) {
                StoreError::Conflict(note.id.clone())
            } else {
                StoreError::Backend(e.to_string())
            }
        })
    }

    async fn update_note(
        &self,
        id: &str,
        author_sub: &str,
        content: &str,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        self.update_note_async(id, author_sub, content, updated_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_note(&self, id: &str, author_sub: &str) -> Result<bool, StoreError> {
        self.delete_note_async(id, author_sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_followers(&self) -> Vec<Follower> {
        self.list_followers_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_followers failed");
            Vec::new()
        })
    }

    async fn count_followers(&self) -> i64 {
        self.count_followers_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg count_followers failed");
            0
        })
    }

    async fn add_follower(&self, follower: &Follower) -> Result<(), StoreError> {
        self.add_follower_async(follower)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn remove_follower(&self, actor: &str) -> Result<(), StoreError> {
        self.remove_follower_async(actor)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}
