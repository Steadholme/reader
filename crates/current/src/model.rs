//! Core domain types: a subscribed `Feed` and a fetched `Item`.
//!
//! Field order/types mirror the agreed schema (db `current`, tables `feeds` + `items`).
//! Ownership (`owner_sub`) always comes from the Sluice-injected `X-Auth-Subject` header,
//! never from client input. `last_fetched` / `published_at` are nullable (NULL = "not yet").

/// A single subscribed feed. The `(owner_sub, url)` pair is unique, so the same person cannot
/// add the same URL twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feed {
    /// Random, URL-safe id (primary key + the `/feeds/{id}/…` slug).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key; never client-supplied).
    pub owner_sub: String,
    /// The feed URL fetched over HTTP(S).
    pub url: String,
    /// Human title — the feed's own `<title>`, or the URL until the first successful fetch.
    pub title: String,
    /// Last successful fetch time, epoch seconds; `None` = never fetched yet.
    pub last_fetched: Option<i64>,
    /// Subscription time, epoch seconds.
    pub created_at: i64,
    /// Owning category id (`feed_categories.id`), or `None` when the feed is uncategorized. The
    /// river/feed list groups feeds under their category; a dangling id (category deleted) reads as
    /// uncategorized in the grouped view.
    pub category_id: Option<String>,
    /// When true, opening an entry of this feed always runs the readability extractor and caches the
    /// full body (see `entry_content`) instead of showing the truncated RSS summary. Default off.
    pub full_content: bool,
}

/// A single fetched item/entry. Deduplicated per feed by `guid` (the `UNIQUE(feed_id, guid)`
/// guard), so re-polling never creates duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Random, URL-safe id (primary key + the `/i/{id}` slug).
    pub id: String,
    /// Owning feed id.
    pub feed_id: String,
    /// Stable per-feed identity from the feed (`<guid>` / Atom `<id>` / link), the dedup key.
    pub guid: String,
    /// Item title (may be empty -> rendered as "(untitled)").
    pub title: String,
    /// Outbound link to the original article (scheme-allowlisted on render).
    pub link: String,
    /// Sanitized plain-text summary (HTML stripped to text at parse time, escaped on render).
    pub summary: String,
    /// Publication time, epoch seconds; `None` = unknown (sorted oldest in the river).
    pub published_at: Option<i64>,
    /// Whether the owner has read/opened this item.
    pub read: bool,
    /// Whether the owner has starred/saved this item (independent of `read`).
    pub starred: bool,
    /// Cached full readable article text (plain text, newline-separated paragraphs), lazily
    /// populated by the in-app reader view when it fetches the item link. `None` = not yet
    /// extracted (the reader falls back to `summary`).
    pub full_text: Option<String>,
}

/// A user-defined feed category/group. The `(owner_sub, name)` pair is unique, so the same person
/// cannot create two categories with the same name. `position` orders the groups on the feed list
/// (ascending; ties broken by name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Category {
    /// Random, URL-safe id (primary key + the `/categories/{id}/…` slug).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key; never client-supplied).
    pub owner_sub: String,
    /// Human display name.
    pub name: String,
    /// Sort position among the owner's categories (ascending).
    pub position: i64,
}

/// One row of the unified river: an unread item plus its feed's display title (the join the
/// reading view needs without a second lookup).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiverEntry {
    pub item: Item,
    pub feed_title: String,
}
