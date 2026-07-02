//! Hashtag parsing for note content.
//!
//! A hashtag is a `#` at a word boundary (start of text, or after a non-word character) followed by
//! one or more word characters (`[A-Za-z0-9_]`). Tags are lower-cased and de-duplicated, preserving
//! first-seen order. Pure + transport-agnostic so it is trivially unit tested; the timeline renderer
//! ([`crate::handlers::render_note_html_tagged`]) uses the SAME boundary rule to linkify tags.

/// Hard cap on how many distinct tags one note contributes (bounds storage).
pub const MAX_HASHTAGS_PER_NOTE: usize = 30;
/// Hard cap on a single tag's length, in characters (over-long "tags" are ignored).
pub const MAX_TAG_CHARS: usize = 100;

/// True when `c` is a tag character (`[A-Za-z0-9_]`).
pub fn is_tag_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Parse the distinct lower-cased hashtags out of `content`, in first-seen order, bounded by
/// [`MAX_HASHTAGS_PER_NOTE`]. Over-long tags are skipped.
pub fn parse_hashtags(content: &str) -> Vec<String> {
    let chars: Vec<char> = content.chars().collect();
    let n = chars.len();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < n {
        let at_boundary = i == 0 || !is_tag_char(chars[i - 1]);
        if chars[i] == '#' && at_boundary {
            let start = i + 1;
            let mut j = start;
            while j < n && is_tag_char(chars[j]) {
                j += 1;
            }
            if j > start {
                let tag: String = chars[start..j].iter().collect::<String>().to_lowercase();
                if tag.chars().count() <= MAX_TAG_CHARS
                    && !out.contains(&tag)
                    && out.len() < MAX_HASHTAGS_PER_NOTE
                {
                    out.push(tag);
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lowercased_deduped_in_order() {
        let tags = parse_hashtags("Loving #Rust and #rust and #WebDev! Not a#tag though.");
        assert_eq!(tags, vec!["rust", "webdev"]);
    }

    #[test]
    fn requires_word_boundary_before_hash() {
        // `a#tag` is not a hashtag (no boundary); `(#tag)` and newline-led are.
        let tags = parse_hashtags("email a#b\n#news (#Sports)");
        assert_eq!(tags, vec!["news", "sports"]);
    }

    #[test]
    fn ignores_bare_hash_and_punctuation() {
        assert!(parse_hashtags("# not a tag, ## also not").is_empty());
    }

    #[test]
    fn underscores_and_digits_are_tag_chars() {
        assert_eq!(parse_hashtags("#day_1 #100days"), vec!["day_1", "100days"]);
    }
}
