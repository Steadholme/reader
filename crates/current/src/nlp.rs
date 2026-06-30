//! Local, deterministic text intelligence — cross-source story clustering + extractive
//! summaries. Pure Rust, no external model, no network: everything here is a bag-of-words /
//! keyword-overlap / term-frequency heuristic computed from the text already stored on an
//! [`Item`](crate::model::Item). It is additive — the store schema and the existing river query
//! are untouched; these functions run over the rows the river already returns.
//!
//! - [`cluster_river`] greedily groups newest-first river entries whose title+summary token sets
//!   overlap above a threshold (the "same story across different feeds" view).
//! - [`extractive_sentences`] picks the top 1–2 sentences of an item's content by summed term
//!   frequency (a Luhn-style BoW score), with a small boost for title words.
//!
//! Both are stable/deterministic: identical input always yields identical output (greedy single
//! pass in input order; score ties broken by earlier position).

use std::collections::{HashMap, HashSet};

use crate::config::{CLUSTER_MIN_SHARED, CLUSTER_SIMILARITY};
use crate::model::RiverEntry;

/// Common English function words dropped before any similarity / scoring, so matches and
/// sentence scores reflect topical content rather than glue words.
const STOPWORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her", "was",
    "one", "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old",
    "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use",
    "that", "with", "have", "this", "will", "your", "from", "they", "know", "want", "been", "good",
    "much", "some", "time", "very", "when", "come", "here", "just", "like", "long", "make", "many",
    "over", "such", "take", "than", "them", "well", "were", "what", "into", "more", "only", "also",
    "after", "about", "would", "there", "their", "which", "could", "other", "these", "being",
    "while", "should", "where", "those", "still", "between", "because",
];

/// Tokenize into lowercased significant word tokens: split on any non-alphanumeric boundary,
/// keep tokens of ≥3 characters that are not stopwords. Unicode-aware lowercasing.
pub fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .filter(|w| w.chars().count() >= 3 && !is_stopword(w))
        .collect()
}

fn is_stopword(w: &str) -> bool {
    STOPWORDS.contains(&w)
}

/// Split text into trimmed sentences on `.`/`!`/`?` boundaries (a boundary only counts when the
/// next character is whitespace or the end, so `3.14` / `U.S.` stay intact). Empty fragments are
/// dropped. Never panics; deterministic.
pub fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        cur.push(c);
        if matches!(c, '.' | '!' | '?') {
            let boundary = matches!(chars.peek(), Some(n) if n.is_whitespace()) || chars.peek().is_none();
            if boundary {
                let s = cur.trim();
                if !s.is_empty() {
                    out.push(s.to_string());
                }
                cur.clear();
            }
        }
    }
    let s = cur.trim();
    if !s.is_empty() {
        out.push(s.to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// Extractive summary
// ---------------------------------------------------------------------------

/// Pick the top `max_sentences` sentences of `body` by a term-frequency (BoW) score, returning
/// them in their original order. Title words get a 2× boost (they signal the topic). When the
/// body already has `≤ max_sentences` sentences there is nothing to condense, so all of them are
/// returned unchanged. Deterministic: score ties are broken toward the earlier sentence.
pub fn extractive_sentences(title: &str, body: &str, max_sentences: usize) -> Vec<String> {
    let sentences = split_sentences(body);
    if sentences.len() <= max_sentences || max_sentences == 0 {
        return sentences;
    }

    // Term frequency across the whole body.
    let mut tf: HashMap<String, usize> = HashMap::new();
    for t in tokens(body) {
        *tf.entry(t).or_insert(0) += 1;
    }
    let title_tokens: HashSet<String> = tokens(title).into_iter().collect();

    // Average boosted term frequency per sentence (averaging avoids a long-sentence bias).
    let mut scored: Vec<(usize, f64)> = sentences
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let toks = tokens(s);
            if toks.is_empty() {
                return (i, 0.0);
            }
            let mut sum = 0.0;
            for t in &toks {
                let base = *tf.get(t).unwrap_or(&0) as f64;
                let boost = if title_tokens.contains(t) { 2.0 } else { 1.0 };
                sum += base * boost;
            }
            (i, sum / toks.len() as f64)
        })
        .collect();

    // Highest score first; earlier sentence wins a tie.
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });

    // Keep the chosen indices, then restore reading order.
    let mut chosen: Vec<usize> = scored.into_iter().take(max_sentences).map(|(i, _)| i).collect();
    chosen.sort_unstable();
    chosen.into_iter().map(|i| sentences[i].clone()).collect()
}

/// Convenience: the [`extractive_sentences`] joined into one string.
pub fn extractive_summary(title: &str, body: &str, max_sentences: usize) -> String {
    extractive_sentences(title, body, max_sentences).join(" ")
}

// ---------------------------------------------------------------------------
// Cross-source clustering
// ---------------------------------------------------------------------------

/// One cluster of river entries that tell the same story. `head` is the representative (the
/// newest, since the input is newest-first); `others` are the additional sources, in input order.
#[derive(Clone, Debug)]
pub struct Cluster {
    pub head: RiverEntry,
    pub others: Vec<RiverEntry>,
}

impl Cluster {
    /// Total entries in the cluster (head + others).
    pub fn total(&self) -> usize {
        1 + self.others.len()
    }

    /// Number of distinct *other* feeds (by feed title) carrying this story — i.e. feeds beyond
    /// the one shown. 0 means the only extra sources share the head's feed (rare; falls back to
    /// the raw other-count at the call site).
    pub fn extra_feed_count(&self) -> usize {
        self.others
            .iter()
            .map(|e| e.feed_title.as_str())
            .filter(|t| *t != self.head.feed_title)
            .collect::<HashSet<_>>()
            .len()
    }
}

/// The title+summary token set used as a story's fingerprint.
fn token_set(e: &RiverEntry) -> HashSet<String> {
    let mut combined = String::with_capacity(e.item.title.len() + e.item.summary.len() + 1);
    combined.push_str(&e.item.title);
    combined.push(' ');
    combined.push_str(&e.item.summary);
    tokens(&combined).into_iter().collect()
}

/// "Same story" test: at least [`CLUSTER_MIN_SHARED`] shared significant tokens AND an overlap
/// coefficient (`shared / min(|a|,|b|)`) at or above [`CLUSTER_SIMILARITY`]. The overlap
/// coefficient tolerates different outlets rewording the same headline. Empty sets never match.
fn same_story(a: &HashSet<String>, b: &HashSet<String>) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let shared = a.intersection(b).count();
    if shared < CLUSTER_MIN_SHARED {
        return false;
    }
    let denom = a.len().min(b.len()) as f64;
    (shared as f64 / denom) >= CLUSTER_SIMILARITY
}

/// Greedily group newest-first river entries into [`Cluster`]s. Each entry joins the first
/// earlier cluster whose *head* is the same story, otherwise it starts a new cluster. Cluster
/// order follows the input (so the river stays newest-first by representative). Non-destructive:
/// every input entry appears in exactly one cluster; nothing is dropped.
pub fn cluster_river(entries: &[RiverEntry]) -> Vec<Cluster> {
    let sets: Vec<HashSet<String>> = entries.iter().map(token_set).collect();
    // Each tuple: (head index, other indices).
    let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
    for i in 0..entries.len() {
        let mut placed = false;
        for g in groups.iter_mut() {
            if same_story(&sets[g.0], &sets[i]) {
                g.1.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            groups.push((i, Vec::new()));
        }
    }
    groups
        .into_iter()
        .map(|(head, others)| Cluster {
            head: entries[head].clone(),
            others: others.into_iter().map(|j| entries[j].clone()).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Item;

    fn entry(id: &str, feed: &str, feed_title: &str, title: &str, summary: &str) -> RiverEntry {
        RiverEntry {
            item: Item {
                id: id.into(),
                feed_id: feed.into(),
                guid: id.into(),
                title: title.into(),
                link: "https://example.com".into(),
                summary: summary.into(),
                published_at: Some(0),
                read: false,
            },
            feed_title: feed_title.into(),
        }
    }

    #[test]
    fn tokens_drops_short_and_stopwords() {
        let t = tokens("The Mars rover found WATER on the planet");
        assert!(t.contains(&"mars".to_string()));
        assert!(t.contains(&"rover".to_string()));
        assert!(t.contains(&"water".to_string()));
        assert!(t.contains(&"planet".to_string()));
        // stopwords + 2-char tokens removed
        assert!(!t.contains(&"the".to_string()));
        assert!(!t.contains(&"on".to_string()));
    }

    #[test]
    fn split_sentences_keeps_decimals_intact() {
        let s = split_sentences("Pi is 3.14 today. It rained! Did it?");
        assert_eq!(s, vec!["Pi is 3.14 today.", "It rained!", "Did it?"]);
    }

    #[test]
    fn extractive_picks_salient_sentences_in_order() {
        let title = "Mars rover water discovery";
        let body = "Scientists confirmed the Mars rover found water. \
                    The weather was mild that week. \
                    The water discovery on Mars excites the rover science team.";
        let picked = extractive_sentences(title, body, 2);
        assert_eq!(picked.len(), 2);
        // The two water/Mars/rover sentences outscore the weather sentence.
        assert!(picked.iter().all(|s| s.to_lowercase().contains("water")));
        // Original reading order is preserved.
        assert!(picked[0].starts_with("Scientists"));
    }

    #[test]
    fn extractive_returns_all_when_short() {
        let picked = extractive_sentences("t", "Only one sentence here.", 2);
        assert_eq!(picked, vec!["Only one sentence here."]);
    }

    #[test]
    fn cluster_groups_same_story_across_feeds() {
        let entries = vec![
            entry("a", "f1", "Globe", "Mars rover discovers water on planet", "water found"),
            entry("b", "f2", "Times", "Rover finds water on Mars planet", "the discovery"),
            entry("c", "f3", "Sports", "Local team wins championship final", "great game"),
        ];
        let clusters = cluster_river(&entries);
        assert_eq!(clusters.len(), 2, "two distinct stories");
        // First cluster (newest-first representative) carries the Mars story across two feeds.
        assert_eq!(clusters[0].head.item.id, "a");
        assert_eq!(clusters[0].total(), 2);
        assert_eq!(clusters[0].extra_feed_count(), 1);
        assert_eq!(clusters[0].others[0].item.id, "b");
        // The sports story stands alone.
        assert_eq!(clusters[1].head.item.id, "c");
        assert_eq!(clusters[1].total(), 1);
    }

    #[test]
    fn cluster_keeps_unrelated_items_separate() {
        let entries = vec![
            entry("a", "f1", "F1", "Quarterly earnings beat estimates", "profit up"),
            entry("b", "f2", "F2", "New volcano eruption in Iceland", "lava flows"),
        ];
        let clusters = cluster_river(&entries);
        assert_eq!(clusters.len(), 2);
        assert!(clusters.iter().all(|c| c.total() == 1));
    }

    #[test]
    fn cluster_is_non_destructive() {
        let entries = vec![
            entry("a", "f1", "A", "Mars rover water planet", "x"),
            entry("b", "f2", "B", "Mars rover water planet found", "y"),
            entry("c", "f3", "C", "Mars rover water planet again", "z"),
        ];
        let clusters = cluster_river(&entries);
        let total: usize = clusters.iter().map(|c| c.total()).sum();
        assert_eq!(total, 3, "every input entry is preserved exactly once");
    }
}
