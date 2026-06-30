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
}

/// Reading-list filter. `All` and `Unread` show only NON-archived clips; `Archived` shows the
/// archive. Keeping this as a closed enum means both stores agree on what each view contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Active list: every non-archived clip (read + unread).
    All,
    /// Active list, unread only.
    Unread,
    /// The archive.
    Archived,
}

impl Filter {
    /// Parse a `?filter=` token; anything unrecognized (incl. missing) is the default [`Filter::All`].
    pub fn parse(token: &str) -> Filter {
        match token {
            "unread" => Filter::Unread,
            "archived" => Filter::Archived,
            _ => Filter::All,
        }
    }

    /// The canonical query token for this filter (round-trips with [`Filter::parse`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::Unread => "unread",
            Filter::Archived => "archived",
        }
    }

    /// Whether a clip belongs in this view (used by the in-memory store; the PgStore encodes the
    /// same predicate in SQL).
    pub fn matches(self, clip: &Clip) -> bool {
        match self {
            Filter::All => !clip.archived,
            Filter::Unread => !clip.archived && !clip.read,
            Filter::Archived => clip.archived,
        }
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
        }
    }

    #[test]
    fn filter_parse_round_trips() {
        for f in [Filter::All, Filter::Unread, Filter::Archived] {
            assert_eq!(Filter::parse(f.as_str()), f);
        }
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
    }
}
