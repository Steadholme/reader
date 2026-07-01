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
    /// URL of a single attached image (an Aperture share URL), or `""` when the note has none.
    /// Surfaced as an ActivityPub `attachment` Document and rendered inline on the timeline.
    pub attachment_url: String,
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

/// A blocklist entry — a remote DOMAIN or a single remote actor id rejected at the inbox (maps 1:1
/// to a `blocklist` row). A blocked sender cannot follow us and cannot deliver to the inbox.
#[derive(Clone, Debug)]
pub struct Blocked {
    /// The blocked value: a bare host (`kind == "domain"`) or an actor id URL (`kind == "actor"`).
    /// This is the PRIMARY KEY.
    pub target: String,
    /// `"domain"` (matches any actor on that host) or `"actor"` (matches one exact actor id).
    pub kind: String,
    pub created_at: i64,
}

/// The host component of an actor id URL, lower-cased (`https://mastodon.social/users/foo` ->
/// `mastodon.social`). Port + userinfo are stripped. Returns `""` when no host can be derived, and
/// echoes a bare non-URL input as-is (already a host) so a `domain` block matches either form.
pub fn actor_domain(actor: &str) -> String {
    let rest = actor
        .strip_prefix("https://")
        .or_else(|| actor.strip_prefix("http://"))
        .unwrap_or(actor);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop any `userinfo@` prefix, then any `:port` suffix.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    host.to_ascii_lowercase()
}

/// The single actor's persisted RSA keypair (maps 1:1 to the one `actor_keys` row). Kept in the
/// store so a restart re-publishes the SAME `publicKeyPem` remotes have already cached.
#[derive(Clone, Debug)]
pub struct ActorKey {
    /// PKCS#8 PEM private key — never leaves the process.
    pub private_pem: String,
    /// SPKI PEM public key — published as the actor's `publicKeyPem`.
    pub public_pem: String,
    pub created_at: i64,
}

/// A REMOTE actor WE follow (maps 1:1 to a `following` row). The mirror of [`Follower`].
#[derive(Clone, Debug)]
pub struct Following {
    /// The remote actor id URL we sent a `Follow` to (the PRIMARY KEY).
    pub actor: String,
    /// The remote actor's resolved inbox URL (where the signed `Follow` was delivered).
    pub inbox_url: String,
    pub created_at: i64,
}

/// A note delivered into our home timeline by a remote we follow (maps 1:1 to a `home_notes` row).
#[derive(Clone, Debug)]
pub struct HomeNote {
    /// The remote Note's object id URL (the PRIMARY KEY — dedupes re-deliveries).
    pub id: String,
    /// The authoring remote actor id URL.
    pub actor: String,
    /// The note's HTML content, exactly as the remote sent it (rendered escaped in the UI).
    pub content: String,
    /// A human URL for the note (falls back to `id` when the remote omits one).
    pub url: String,
    /// The remote's `published` time in epoch seconds (0 when unparseable).
    pub published: i64,
    /// When Crier received it, epoch seconds (the home-timeline sort key).
    pub received_at: i64,
}

/// The single actor's public profile images (maps 1:1 to the one `profile` row). Both are optional
/// URLs (Aperture share URLs): `avatar_url` becomes the actor `icon`, `header_url` the actor
/// `image`. Empty strings mean "unset" — the corresponding field is omitted from the Actor JSON.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    /// Avatar / icon image URL, or `""` when unset.
    pub avatar_url: String,
    /// Header / banner image URL, or `""` when unset.
    pub header_url: String,
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
    /// Admin delete of ANY note regardless of author. Returns `Ok(true)` when a note with this id
    /// existed and was deleted, `Ok(false)` when there was no such note.
    async fn admin_delete_note(&self, id: &str) -> Result<bool, StoreError>;

    /// All followers, newest-first.
    async fn list_followers(&self) -> Vec<Follower>;
    /// Total number of followers (the followers-collection `totalItems`).
    async fn count_followers(&self) -> i64;
    /// Record/refresh a follower. Idempotent: re-following updates the inbox URL only when the new
    /// one is non-empty (so a later bare re-Follow never erases a resolved inbox).
    async fn add_follower(&self, follower: &Follower) -> Result<(), StoreError>;
    /// Remove a follower by actor id (an `Undo` of a `Follow`, or an admin removal).
    async fn remove_follower(&self, actor: &str) -> Result<(), StoreError>;

    /// All blocklist entries, newest-first.
    async fn list_blocks(&self) -> Vec<Blocked>;
    /// Add/refresh a blocklist entry. Idempotent on the target (re-blocking is a no-op).
    async fn add_block(&self, block: &Blocked) -> Result<(), StoreError>;
    /// Remove a blocklist entry by its exact target.
    async fn remove_block(&self, target: &str) -> Result<(), StoreError>;
    /// True when `actor` is blocked: either an exact `actor`-kind match on the id, OR a `domain`-kind
    /// match on the actor's host. Gates the inbox — a blocked sender is rejected and cannot follow.
    async fn is_blocked(&self, actor: &str) -> bool;

    /// The single actor's profile images (avatar + header). Returns an all-empty [`Profile`] before
    /// any have ever been set — a missing row is never an error.
    async fn get_profile(&self) -> Profile;
    /// Set (upsert) the single actor's profile images. Idempotent on the single row; an empty URL
    /// clears that image.
    async fn set_profile(&self, profile: &Profile) -> Result<(), StoreError>;

    /// The persisted actor keypair, or `None` before it has ever been generated.
    async fn get_actor_key(&self) -> Option<ActorKey>;
    /// Persist (once) the actor keypair. Idempotent: a second write with a key already present is a
    /// no-op, so a race between two bootstrappers never rotates the published key.
    async fn set_actor_key(&self, key: &ActorKey) -> Result<(), StoreError>;

    /// Every remote actor we follow, newest-first.
    async fn list_following(&self) -> Vec<Following>;
    /// True when `actor` is a remote we follow (gates whether their Notes enter the home timeline).
    async fn is_following(&self, actor: &str) -> bool;
    /// Record/refresh a remote we follow. Idempotent on the actor id.
    async fn add_following(&self, following: &Following) -> Result<(), StoreError>;

    /// Home-timeline notes delivered by remotes we follow, newest-first, capped at [`LIST_LIMIT`].
    async fn list_home_notes(&self) -> Vec<HomeNote>;
    /// Record a delivered remote note. Idempotent on the note id (a re-delivery is dropped).
    async fn add_home_note(&self, note: &HomeNote) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    notes: Mutex<Vec<Note>>,
    followers: Mutex<Vec<Follower>>,
    blocks: Mutex<Vec<Blocked>>,
    profile: Mutex<Profile>,
    actor_key: Mutex<Option<ActorKey>>,
    following: Mutex<Vec<Following>>,
    home_notes: Mutex<Vec<HomeNote>>,
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

    async fn admin_delete_note(&self, id: &str) -> Result<bool, StoreError> {
        let mut notes = self.notes.lock().expect("notes lock poisoned");
        let before = notes.len();
        notes.retain(|n| n.id != id);
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

    async fn list_blocks(&self) -> Vec<Blocked> {
        let b = self.blocks.lock().expect("blocks lock poisoned");
        let mut v: Vec<Blocked> = b.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.target.cmp(&a.target)));
        v
    }

    async fn add_block(&self, block: &Blocked) -> Result<(), StoreError> {
        let mut b = self.blocks.lock().expect("blocks lock poisoned");
        // Idempotent on the target: re-blocking refreshes the kind but never duplicates the row.
        match b.iter_mut().find(|x| x.target == block.target) {
            Some(existing) => existing.kind = block.kind.clone(),
            None => b.push(block.clone()),
        }
        Ok(())
    }

    async fn remove_block(&self, target: &str) -> Result<(), StoreError> {
        self.blocks
            .lock()
            .expect("blocks lock poisoned")
            .retain(|x| x.target != target);
        Ok(())
    }

    async fn is_blocked(&self, actor: &str) -> bool {
        let domain = actor_domain(actor);
        self.blocks
            .lock()
            .expect("blocks lock poisoned")
            .iter()
            .any(|b| {
                (b.kind == "actor" && b.target == actor)
                    || (b.kind == "domain" && b.target.eq_ignore_ascii_case(&domain))
            })
    }

    async fn get_profile(&self) -> Profile {
        self.profile.lock().expect("profile lock poisoned").clone()
    }

    async fn set_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        *self.profile.lock().expect("profile lock poisoned") = profile.clone();
        Ok(())
    }

    async fn get_actor_key(&self) -> Option<ActorKey> {
        self.actor_key.lock().expect("actor_key lock poisoned").clone()
    }

    async fn set_actor_key(&self, key: &ActorKey) -> Result<(), StoreError> {
        let mut slot = self.actor_key.lock().expect("actor_key lock poisoned");
        // First writer wins — never rotate a key already published to remotes.
        if slot.is_none() {
            *slot = Some(key.clone());
        }
        Ok(())
    }

    async fn list_following(&self) -> Vec<Following> {
        let f = self.following.lock().expect("following lock poisoned");
        let mut v: Vec<Following> = f.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.actor.cmp(&a.actor)));
        v
    }

    async fn is_following(&self, actor: &str) -> bool {
        self.following
            .lock()
            .expect("following lock poisoned")
            .iter()
            .any(|x| x.actor == actor)
    }

    async fn add_following(&self, following: &Following) -> Result<(), StoreError> {
        let mut f = self.following.lock().expect("following lock poisoned");
        match f.iter_mut().find(|x| x.actor == following.actor) {
            Some(existing) => {
                if !following.inbox_url.is_empty() {
                    existing.inbox_url = following.inbox_url.clone();
                }
            }
            None => f.push(following.clone()),
        }
        Ok(())
    }

    async fn list_home_notes(&self) -> Vec<HomeNote> {
        let h = self.home_notes.lock().expect("home_notes lock poisoned");
        let mut v: Vec<HomeNote> = h.clone();
        v.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(LIST_LIMIT);
        v
    }

    async fn add_home_note(&self, note: &HomeNote) -> Result<(), StoreError> {
        let mut h = self.home_notes.lock().expect("home_notes lock poisoned");
        // Dedupe on the remote object id — a re-delivery is silently dropped.
        if h.iter().any(|n| n.id == note.id) {
            return Ok(());
        }
        h.push(note.clone());
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
        // Nullable image-attachment column (a note has zero or one attached image). Added via an
        // idempotent ALTER so pre-existing deployments backfill it without a rewrite; NULL == none.
        sqlx::query("ALTER TABLE notes ADD COLUMN IF NOT EXISTS attachment_url TEXT")
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
        // Blocklist: a remote DOMAIN or a single actor id rejected at the inbox.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocklist (\
                 target TEXT PRIMARY KEY, \
                 kind TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // The single actor's RSA keypair (id is always 'actor' — one row, upserted once).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS actor_keys (\
                 id TEXT PRIMARY KEY, \
                 private_pem TEXT NOT NULL, \
                 public_pem TEXT NOT NULL, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // The single actor's public profile images (id is always 'actor' — one row, upserted).
        // Both columns are NULLABLE (an unset image is absent from the Actor JSON).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS profile (\
                 id TEXT PRIMARY KEY, \
                 avatar_url TEXT, \
                 header_url TEXT\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Idempotent ALTERs so a pre-existing `profile` table gains any missing image column.
        sqlx::query("ALTER TABLE profile ADD COLUMN IF NOT EXISTS avatar_url TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE profile ADD COLUMN IF NOT EXISTS header_url TEXT")
            .execute(&self.pool)
            .await?;
        // Remote actors WE follow (mirror of `followers`).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS following (\
                 actor TEXT PRIMARY KEY, \
                 inbox_url TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Home timeline: notes delivered by remotes we follow.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS home_notes (\
                 id TEXT PRIMARY KEY, \
                 actor TEXT NOT NULL, \
                 content TEXT NOT NULL, \
                 url TEXT NOT NULL DEFAULT '', \
                 published BIGINT NOT NULL DEFAULT 0, \
                 received_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_home_notes_received_at ON home_notes (received_at)")
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
            // Nullable column: a NULL attachment reads back as the empty "no attachment" string.
            attachment_url: row.try_get::<Option<String>, _>("attachment_url")?.unwrap_or_default(),
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
            "SELECT id, author_sub, content, visibility, created_at, updated_at, attachment_url \
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
            "SELECT id, author_sub, content, visibility, created_at, updated_at, attachment_url \
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
        // The nullable `attachment_url` stores NULL when there is no attachment (empty string).
        let attachment: Option<&str> = if n.attachment_url.is_empty() {
            None
        } else {
            Some(n.attachment_url.as_str())
        };
        sqlx::query(
            "INSERT INTO notes (id, author_sub, content, visibility, created_at, updated_at, attachment_url) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&n.id)
        .bind(&n.author_sub)
        .bind(&n.content)
        .bind(&n.visibility)
        .bind(n.created_at)
        .bind(n.updated_at)
        .bind(attachment)
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

    async fn admin_delete_note_async(&self, id: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM notes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_blocks_async(&self) -> Result<Vec<Blocked>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT target, kind, created_at FROM blocklist \
             ORDER BY created_at DESC, target DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Blocked {
                    target: r.try_get("target")?,
                    kind: r.try_get("kind")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn add_block_async(&self, b: &Blocked) -> Result<(), sqlx::Error> {
        // Idempotent on the target: re-blocking refreshes the kind, never duplicates the row.
        sqlx::query(
            "INSERT INTO blocklist (target, kind, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (target) DO UPDATE SET kind = EXCLUDED.kind",
        )
        .bind(&b.target)
        .bind(&b.kind)
        .bind(b.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_block_async(&self, target: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM blocklist WHERE target = $1")
            .bind(target)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn is_blocked_async(&self, actor: &str) -> Result<bool, sqlx::Error> {
        let domain = actor_domain(actor);
        let row = sqlx::query(
            "SELECT 1 AS one FROM blocklist \
             WHERE (kind = 'actor' AND target = $1) OR (kind = 'domain' AND target = $2) LIMIT 1",
        )
        .bind(actor)
        .bind(&domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn get_actor_key_async(&self) -> Result<Option<ActorKey>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT private_pem, public_pem, created_at FROM actor_keys WHERE id = 'actor'",
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(ActorKey {
                private_pem: r.try_get("private_pem")?,
                public_pem: r.try_get("public_pem")?,
                created_at: r.try_get("created_at")?,
            })),
            None => Ok(None),
        }
    }

    async fn set_actor_key_async(&self, key: &ActorKey) -> Result<(), sqlx::Error> {
        // First writer wins: DO NOTHING keeps the already-published key stable across restarts /
        // a concurrent bootstrap race.
        sqlx::query(
            "INSERT INTO actor_keys (id, private_pem, public_pem, created_at) \
             VALUES ('actor', $1, $2, $3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&key.private_pem)
        .bind(&key.public_pem)
        .bind(key.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_profile_async(&self) -> Result<Profile, sqlx::Error> {
        let row = sqlx::query("SELECT avatar_url, header_url FROM profile WHERE id = 'actor'")
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Profile {
                avatar_url: r.try_get::<Option<String>, _>("avatar_url")?.unwrap_or_default(),
                header_url: r.try_get::<Option<String>, _>("header_url")?.unwrap_or_default(),
            }),
            None => Ok(Profile::default()),
        }
    }

    async fn set_profile_async(&self, p: &Profile) -> Result<(), sqlx::Error> {
        // An empty URL is stored as NULL (unset); the single 'actor' row is upserted in place.
        let avatar: Option<&str> = (!p.avatar_url.is_empty()).then_some(p.avatar_url.as_str());
        let header: Option<&str> = (!p.header_url.is_empty()).then_some(p.header_url.as_str());
        sqlx::query(
            "INSERT INTO profile (id, avatar_url, header_url) VALUES ('actor', $1, $2) \
             ON CONFLICT (id) DO UPDATE SET avatar_url = EXCLUDED.avatar_url, \
                 header_url = EXCLUDED.header_url",
        )
        .bind(avatar)
        .bind(header)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_following_async(&self) -> Result<Vec<Following>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT actor, inbox_url, created_at FROM following \
             ORDER BY created_at DESC, actor DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Following {
                    actor: r.try_get("actor")?,
                    inbox_url: r.try_get("inbox_url")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn is_following_async(&self, actor: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT 1 AS one FROM following WHERE actor = $1")
            .bind(actor)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn add_following_async(&self, f: &Following) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO following (actor, inbox_url, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (actor) DO UPDATE SET inbox_url = \
                 CASE WHEN EXCLUDED.inbox_url <> '' THEN EXCLUDED.inbox_url \
                      ELSE following.inbox_url END",
        )
        .bind(&f.actor)
        .bind(&f.inbox_url)
        .bind(f.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_home_notes_async(&self) -> Result<Vec<HomeNote>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, actor, content, url, published, received_at FROM home_notes \
             ORDER BY received_at DESC, id DESC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(HomeNote {
                    id: r.try_get("id")?,
                    actor: r.try_get("actor")?,
                    content: r.try_get("content")?,
                    url: r.try_get("url")?,
                    published: r.try_get("published")?,
                    received_at: r.try_get("received_at")?,
                })
            })
            .collect()
    }

    async fn add_home_note_async(&self, n: &HomeNote) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO home_notes (id, actor, content, url, published, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&n.id)
        .bind(&n.actor)
        .bind(&n.content)
        .bind(&n.url)
        .bind(n.published)
        .bind(n.received_at)
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

    async fn admin_delete_note(&self, id: &str) -> Result<bool, StoreError> {
        self.admin_delete_note_async(id)
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

    async fn list_blocks(&self) -> Vec<Blocked> {
        self.list_blocks_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_blocks failed");
            Vec::new()
        })
    }

    async fn add_block(&self, block: &Blocked) -> Result<(), StoreError> {
        self.add_block_async(block)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn remove_block(&self, target: &str) -> Result<(), StoreError> {
        self.remove_block_async(target)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn is_blocked(&self, actor: &str) -> bool {
        self.is_blocked_async(actor).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg is_blocked failed");
            false
        })
    }

    async fn get_profile(&self) -> Profile {
        self.get_profile_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_profile failed");
            Profile::default()
        })
    }

    async fn set_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.set_profile_async(profile)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_actor_key(&self) -> Option<ActorKey> {
        self.get_actor_key_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_actor_key failed");
            None
        })
    }

    async fn set_actor_key(&self, key: &ActorKey) -> Result<(), StoreError> {
        self.set_actor_key_async(key)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_following(&self) -> Vec<Following> {
        self.list_following_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_following failed");
            Vec::new()
        })
    }

    async fn is_following(&self, actor: &str) -> bool {
        self.is_following_async(actor).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg is_following failed");
            false
        })
    }

    async fn add_following(&self, following: &Following) -> Result<(), StoreError> {
        self.add_following_async(following)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_home_notes(&self) -> Vec<HomeNote> {
        self.list_home_notes_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_home_notes failed");
            Vec::new()
        })
    }

    async fn add_home_note(&self, note: &HomeNote) -> Result<(), StoreError> {
        self.add_home_note_async(note)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}
