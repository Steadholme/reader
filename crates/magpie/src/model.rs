//! Core domain types: a saved clip + the reading-list filter.
//!
//! One flat record per the agreed schema (db `magpie`, table `clips`). Identity (`owner_sub`)
//! always comes from the Sluice-injected `X-Auth-Subject` header, never from client input.

/// A single saved clip (web article captured for reading later).
///
/// Field order/types mirror the `clips` table exactly. `content_text`/`excerpt`/`title`/`site`
/// are all derived from the REMOTE page and are therefore untrusted: they are stored verbatim
/// as PLAIN TEXT and HTML-escaped on every render (never emitted as raw HTML).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clip {
    /// Short, random, URL-safe id (the `/r/{id}` slug + primary key).
    pub id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key for read/archive/delete).
    pub owner_sub: String,
    /// The original page URL (validated http/https; shown as a link, escaped).
    pub url: String,
    /// Extracted title (`og:title` / `<title>`, else the URL) — plain text.
    pub title: String,
    /// Short plain-text excerpt (first paragraphs, or `og:description`).
    pub excerpt: String,
    /// The full extracted readable plain text (rendered as escaped paragraphs in the reader).
    pub content_text: String,
    /// Source site label (`og:site_name` or the URL host) — plain text.
    pub site: String,
    /// Save time, epoch seconds.
    pub saved_at: i64,
    /// Whether the owner has opened the reader view.
    pub read: bool,
    /// Whether the owner archived it (removed from the active reading list).
    pub archived: bool,
    /// Whether the owner starred it. A favorite is ORTHOGONAL to read/archived (Pocket-style): a
    /// clip can be read, archived AND favorite at once. Backed by a `BOOLEAN NOT NULL DEFAULT FALSE`
    /// column added idempotently.
    pub favorite: bool,
    /// Last saved reading progress as an integer percent, always clamped to `[0, 100]` on write
    /// (0 = not started). Backed by a `BIGINT NOT NULL DEFAULT 0` column added idempotently.
    pub progress: i64,
    /// Owner-supplied tags, normalized to a lowercase comma-separated list (e.g. `rust,web`).
    /// `None` when the owner set none — the column is a NULLABLE TEXT (never an array/JSON).
    pub tags: Option<String>,
}

/// A single owner-made highlight on a saved clip: a verbatim quote from the article plus an
/// optional inline note.
///
/// Field order/types mirror the `highlights` table exactly. `quote` is copied from the (untrusted,
/// remote) article text and `note` is owner-typed; BOTH are stored as PLAIN TEXT and HTML-escaped
/// on every render (never emitted as raw HTML). A highlight is private to its `owner_sub` and is
/// keyed to a `clip_id`; the pair `(owner_sub, clip_id, quote)` is de-duplicated so re-highlighting
/// the same passage just updates the note (idempotent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Highlight {
    /// Short, random, URL-safe id (primary key; the target of the delete form).
    pub id: String,
    /// The clip this highlight belongs to (`clips.id`).
    pub clip_id: String,
    /// Owner subject from `X-Auth-Subject` (ownership key for list/delete).
    pub owner_sub: String,
    /// The highlighted passage, verbatim from the article — plain text, escaped on render.
    pub quote: String,
    /// Optional owner-typed inline note. `None` when the owner left it blank — the column is a
    /// NULLABLE TEXT (never an array/JSON).
    pub note: Option<String>,
    /// Creation time, epoch seconds.
    pub created_at: i64,
}

/// Reading-list view. `All` and `Unread` show only NON-archived clips; `Favorites` shows every
/// starred clip; `Archived` shows the archive. Keeping this a closed enum means both stores agree
/// on what each view contains. The canonical query key is `?view=`; the legacy `?filter=` alias
/// (and the legacy `archived` token) are still accepted by [`Filter::parse`] for compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Active list: every non-archived clip (read + unread).
    All,
    /// Active list, unread only.
    Unread,
    /// Every starred clip (any read/archived state).
    Favorites,
    /// The archive.
    Archived,
}

impl Filter {
    /// Parse a `?view=` (or legacy `?filter=`) token; anything unrecognized (incl. missing) is the
    /// default [`Filter::All`]. Both `archive` and the legacy `archived` map to the archive.
    pub fn parse(token: &str) -> Filter {
        match token {
            "unread" => Filter::Unread,
            "favorites" | "favorite" => Filter::Favorites,
            "archive" | "archived" => Filter::Archived,
            _ => Filter::All,
        }
    }

    /// The canonical query token for this view (round-trips with [`Filter::parse`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::Unread => "unread",
            Filter::Favorites => "favorites",
            Filter::Archived => "archive",
        }
    }

    /// Whether a clip belongs in this view (used by the in-memory store; the PgStore encodes the
    /// same predicate in SQL).
    pub fn matches(self, clip: &Clip) -> bool {
        match self {
            Filter::All => !clip.archived,
            Filter::Unread => !clip.archived && !clip.read,
            Filter::Favorites => clip.favorite,
            Filter::Archived => clip.archived,
        }
    }
}

/// Words-per-minute rate for the reading-time estimate shown on cards and the reader.
pub const WORDS_PER_MINUTE: usize = 200;

/// Count whitespace-delimited words in `text` (the basis for the reading-time estimate).
pub fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Estimated reading time in whole minutes for `words` words at [`WORDS_PER_MINUTE`]. Zero words is
/// zero minutes; any content rounds UP to at least one minute (ceiling division).
pub fn reading_minutes(words: usize) -> usize {
    if words == 0 {
        0
    } else {
        words.div_ceil(WORDS_PER_MINUTE)
    }
}

/// Clamp a raw, client-supplied reading-progress percent into the stored `[0, 100]` range. Every
/// write goes through this so a bogus POST can never store an out-of-range value.
pub fn clamp_progress(pct: i64) -> i64 {
    pct.clamp(0, 100)
}

/// Normalize a raw, owner-typed tag string into the stored canonical form: split on commas, trim,
/// lowercase, drop empties, de-duplicate (order-preserving), and cap the count/length. Returns
/// `None` when nothing usable remains (the column then stays NULL). Commas are the only separator,
/// so a normalized value never contains an empty token — `?tag=` matching stays exact.
pub fn normalize_tags(raw: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let t = part.trim().to_lowercase();
        if t.is_empty() || out.iter().any(|e| e == &t) {
            continue;
        }
        out.push(t);
        if out.len() >= MAX_TAGS {
            break;
        }
    }
    if out.is_empty() {
        return None;
    }
    let mut joined = out.join(",");
    // Defensive cap so a pathological submission can never bloat the row.
    if joined.chars().count() > MAX_TAGS_CHARS {
        if let Some((idx, _)) = joined.char_indices().nth(MAX_TAGS_CHARS) {
            joined.truncate(idx);
        }
    }
    Some(joined)
}

/// Max distinct tags kept per clip.
pub const MAX_TAGS: usize = 24;
/// Max characters of the stored tags string.
pub const MAX_TAGS_CHARS: usize = 200;

/// Whether a (normalized) tags value contains `tag` as a whole comma-delimited token. Matching is
/// case-insensitive; used by the in-memory store (the PgStore encodes the same predicate in SQL).
pub fn tags_contain(tags: &Option<String>, tag: &str) -> bool {
    let needle = tag.trim().to_lowercase();
    if needle.is_empty() {
        return false;
    }
    match tags {
        Some(s) => s.split(',').any(|t| t.trim().eq_ignore_ascii_case(&needle)),
        None => false,
    }
}

/// A keyset-pagination cursor over the newest-first `(saved_at DESC, id DESC)` ordering: the last
/// row of the previous page. Serialized as `{saved_at}_{id}` — `saved_at` is digits and the clip id
/// is alphanumeric (no `_`), so the first `_` splits it unambiguously.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub saved_at: i64,
    pub id: String,
}

impl Cursor {
    /// Parse a `?before=` token; malformed/empty input yields `None` (treated as "first page").
    pub fn parse(token: &str) -> Option<Cursor> {
        let (ts, id) = token.split_once('_')?;
        let saved_at: i64 = ts.parse().ok()?;
        if id.is_empty() {
            return None;
        }
        Some(Cursor {
            saved_at,
            id: id.to_string(),
        })
    }

    /// The `?before=` token for this cursor (round-trips with [`Cursor::parse`]).
    pub fn encode(&self) -> String {
        format!("{}_{}", self.saved_at, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clip(read: bool, archived: bool) -> Clip {
        Clip {
            id: "a".into(),
            owner_sub: "u".into(),
            url: "https://x".into(),
            title: "t".into(),
            excerpt: "e".into(),
            content_text: "c".into(),
            site: "x".into(),
            saved_at: 1,
            read,
            archived,
            favorite: false,
            progress: 0,
            tags: None,
        }
    }

    #[test]
    fn filter_parse_round_trips() {
        for f in [Filter::All, Filter::Unread, Filter::Favorites, Filter::Archived] {
            assert_eq!(Filter::parse(f.as_str()), f);
        }
        // Legacy aliases still resolve.
        assert_eq!(Filter::parse("archived"), Filter::Archived);
        assert_eq!(Filter::parse("favorite"), Filter::Favorites);
        assert_eq!(Filter::parse("bogus"), Filter::All);
        assert_eq!(Filter::parse(""), Filter::All);
    }

    #[test]
    fn filter_matches_partitions_views() {
        // All: non-archived regardless of read.
        assert!(Filter::All.matches(&clip(false, false)));
        assert!(Filter::All.matches(&clip(true, false)));
        assert!(!Filter::All.matches(&clip(false, true)));
        // Unread: non-archived AND unread.
        assert!(Filter::Unread.matches(&clip(false, false)));
        assert!(!Filter::Unread.matches(&clip(true, false)));
        // Archived: archived only.
        assert!(Filter::Archived.matches(&clip(false, true)));
        assert!(!Filter::Archived.matches(&clip(false, false)));
        // Favorites: starred only, regardless of read/archived.
        let mut fav = clip(true, true);
        fav.favorite = true;
        assert!(Filter::Favorites.matches(&fav));
        assert!(!Filter::Favorites.matches(&clip(false, false)));
    }

    #[test]
    fn reading_minutes_ceils_and_floors_at_zero() {
        assert_eq!(reading_minutes(0), 0);
        assert_eq!(reading_minutes(1), 1);
        assert_eq!(reading_minutes(200), 1);
        assert_eq!(reading_minutes(201), 2);
        assert_eq!(reading_minutes(400), 2);
        assert_eq!(reading_minutes(401), 3);
        // word_count is the whitespace split feeding it.
        assert_eq!(word_count("  one   two\tthree\n"), 3);
        assert_eq!(word_count(""), 0);
    }

    #[test]
    fn clamp_progress_bounds_to_0_100() {
        assert_eq!(clamp_progress(-5), 0);
        assert_eq!(clamp_progress(0), 0);
        assert_eq!(clamp_progress(37), 37);
        assert_eq!(clamp_progress(100), 100);
        assert_eq!(clamp_progress(1000), 100);
    }

    #[test]
    fn normalize_tags_lowercases_dedups_and_trims() {
        assert_eq!(normalize_tags("Rust, web ,rust,,  ").as_deref(), Some("rust,web"));
        assert_eq!(normalize_tags("  ").as_deref(), None);
        assert_eq!(normalize_tags(""), None);
        assert_eq!(normalize_tags("A,B,C").as_deref(), Some("a,b,c"));
    }

    #[test]
    fn tags_contain_matches_whole_tokens_case_insensitively() {
        let tags = normalize_tags("Rust,web-dev,async");
        assert!(tags_contain(&tags, "rust"));
        assert!(tags_contain(&tags, "RUST"));
        assert!(tags_contain(&tags, "web-dev"));
        assert!(!tags_contain(&tags, "web")); // whole-token, not substring
        assert!(!tags_contain(&None, "rust"));
        assert!(!tags_contain(&tags, ""));
    }

    #[test]
    fn cursor_round_trips() {
        let c = Cursor { saved_at: 1_700_000_000, id: "abc123XY".into() };
        assert_eq!(Cursor::parse(&c.encode()), Some(c));
        assert_eq!(Cursor::parse("bogus"), None);
        assert_eq!(Cursor::parse("123_"), None);
        assert_eq!(Cursor::parse(""), None);
    }
}
