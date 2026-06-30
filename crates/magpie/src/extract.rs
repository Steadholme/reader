//! Readability extraction: HTML -> plain text title/site/excerpt/content.
//!
//! Pure (no I/O), so it is unit-tested directly and runs identically over a fetched page or a
//! canned test fixture. The output is ALWAYS plain text — the remote HTML is parsed only to pull
//! `<title>`/`og:*` and the readable block text out; it is NEVER re-emitted as HTML (the reader
//! view escapes every line), so stored-XSS is structurally impossible.
//!
//! Heuristic (intentionally simple — full readability is DEFERRED): pick the best content root
//! (`<article>` > `<main>` > `[role=main]` > `<body>`), then collect the text of its block-level
//! descendants (`p`, `h1..h6`, `li`, `pre`, `blockquote`, `figcaption`). `<script>`/`<style>`
//! never live inside those, so they are excluded for free.

use scraper::{Html, Selector};

use crate::config::{EXCERPT_CHARS, MAX_CONTENT_CHARS, MAX_TITLE_CHARS};

/// The plain-text fields pulled out of a page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extracted {
    pub title: String,
    pub site: String,
    pub excerpt: String,
    pub content_text: String,
}

/// Block-level tags whose combined text forms the readable body.
const BLOCK_SELECTOR: &str = "p, h1, h2, h3, h4, h5, h6, li, pre, blockquote, figcaption";

/// Extract title/site/excerpt/content from `html`. `url` is the FINAL fetched URL, used to derive
/// a sensible host-based fallback for the title + site label.
pub fn extract(html: &str, url: &str) -> Extracted {
    let doc = Html::parse_document(html);

    let host = host_of(url);
    let title = first_nonempty([
        meta_content(&doc, "property", "og:title"),
        meta_content(&doc, "name", "twitter:title"),
        title_tag(&doc),
    ])
    .unwrap_or_else(|| fallback_title(url, &host));
    let title = clamp_chars(&collapse_ws(&title), MAX_TITLE_CHARS);

    let site = first_nonempty([
        meta_content(&doc, "property", "og:site_name"),
        if host.is_empty() { None } else { Some(host.clone()) },
    ])
    .map(|s| collapse_ws(&s))
    .unwrap_or_default();

    let root = pick_root(&doc);
    // Full readable body (headings + paragraphs + lists) for the reader view.
    let content_text = block_text(root, BLOCK_SELECTOR);
    // Excerpt source: paragraph text ONLY, so the list summary never just repeats the heading.
    let para_text = block_text(root, "p");

    // Excerpt: prefer the article's opening paragraphs; then any block text; then a meta tag.
    let excerpt = if !para_text.is_empty() {
        make_excerpt(&para_text, EXCERPT_CHARS)
    } else if !content_text.is_empty() {
        make_excerpt(&content_text, EXCERPT_CHARS)
    } else {
        first_nonempty([
            meta_content(&doc, "property", "og:description"),
            meta_content(&doc, "name", "description"),
        ])
        .map(|s| clamp_chars(&collapse_ws(&s), EXCERPT_CHARS))
        .unwrap_or_default()
    };

    Extracted {
        title,
        site,
        excerpt,
        content_text: clamp_chars(&content_text, MAX_CONTENT_CHARS),
    }
}

/// Build an [`Extracted`] from a `text/plain` page (no HTML to parse): the body itself is the
/// readable content; the title/site fall back to the host.
pub fn extract_plaintext(body: &str, url: &str) -> Extracted {
    let host = host_of(url);
    let content_text = clamp_chars(
        &body
            .lines()
            .map(collapse_ws)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        MAX_CONTENT_CHARS,
    );
    let excerpt = make_excerpt(&content_text, EXCERPT_CHARS);
    let title = if host.is_empty() {
        url.to_string()
    } else {
        host.clone()
    };
    Extracted {
        title,
        site: host,
        excerpt,
        content_text,
    }
}

/// Collect the text of `root`'s descendants matching `selector_str`, one element per line. The
/// `<script>`/`<style>` tags never match a block selector, so their text is excluded for free.
fn block_text(root: scraper::ElementRef<'_>, selector_str: &str) -> String {
    let Ok(selector) = Selector::parse(selector_str) else {
        return String::new();
    };
    let mut lines: Vec<String> = Vec::new();
    for el in root.select(&selector) {
        let text = collapse_ws(&el.text().collect::<String>());
        if !text.is_empty() {
            lines.push(text);
        }
    }
    lines.join("\n")
}

/// Choose the content root, preferring semantic containers over the whole body.
fn pick_root(doc: &Html) -> scraper::ElementRef<'_> {
    for sel in ["article", "main", "[role=\"main\"]", "body"] {
        if let Ok(selector) = Selector::parse(sel) {
            if let Some(el) = doc.select(&selector).next() {
                return el;
            }
        }
    }
    doc.root_element()
}

/// `<meta {attr}="{value}" content="...">` content, trimmed, non-empty.
fn meta_content(doc: &Html, attr: &str, value: &str) -> Option<String> {
    let sel = Selector::parse(&format!("meta[{attr}=\"{value}\"]")).ok()?;
    doc.select(&sel)
        .filter_map(|el| el.value().attr("content"))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// The `<title>` element text, trimmed, non-empty.
fn title_tag(doc: &Html) -> Option<String> {
    let sel = Selector::parse("title").ok()?;
    doc.select(&sel)
        .map(|el| el.text().collect::<String>())
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

/// Host portion of a URL (best-effort; empty when unparoseable).
fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string()))
        .unwrap_or_default()
}

/// A readable title when the page exposes none (host + first path segment).
fn fallback_title(url: &str, host: &str) -> String {
    if host.is_empty() {
        return url.to_string();
    }
    host.to_string()
}

/// First `Some` non-empty string from an ordered list of candidates.
fn first_nonempty<const N: usize>(candidates: [Option<String>; N]) -> Option<String> {
    candidates
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

/// Collapse all internal whitespace runs to single spaces and trim the ends.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Truncate to at most `max` chars on a char boundary (no panic on multi-byte text).
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

/// Build a one-line excerpt: take up to `max` chars of the (single-spaced) text, trimming back to
/// the last word boundary and appending an ellipsis when truncated.
fn make_excerpt(content: &str, max: usize) -> String {
    let flat = collapse_ws(content);
    let total = flat.chars().count();
    if total <= max {
        return flat;
    }
    let mut cut = clamp_chars(&flat, max);
    if let Some(idx) = cut.rfind(' ') {
        if idx > max / 2 {
            cut.truncate(idx);
        }
    }
    format!("{}…", cut.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<!DOCTYPE html>
<html><head>
  <title>Fallback Title</title>
  <meta property="og:title" content="The Real Title">
  <meta property="og:site_name" content="Example News">
  <script>var x = "<p>not content</p>";</script>
  <style>.x{color:red}</style>
</head>
<body>
  <nav><a href="/">Home</a></nav>
  <article>
    <h1>The Real Title</h1>
    <p>First paragraph of the actual article body that should be extracted.</p>
    <p>Second paragraph with <a href="/x">a link</a> inside it.</p>
  </article>
  <footer><p>Copyright junk</p></footer>
</body></html>"#;

    #[test]
    fn prefers_og_title_over_title_tag() {
        let e = extract(PAGE, "https://www.example.com/story");
        assert_eq!(e.title, "The Real Title");
    }

    #[test]
    fn site_uses_og_site_name() {
        let e = extract(PAGE, "https://www.example.com/story");
        assert_eq!(e.site, "Example News");
    }

    #[test]
    fn content_excludes_script_and_style() {
        let e = extract(PAGE, "https://example.com/story");
        assert!(e.content_text.contains("First paragraph of the actual article"));
        assert!(e.content_text.contains("a link")); // inline anchor text kept
        assert!(!e.content_text.contains("not content"));
        assert!(!e.content_text.contains("color:red"));
    }

    #[test]
    fn excerpt_is_derived_from_body() {
        let e = extract(PAGE, "https://example.com/story");
        assert!(e.excerpt.starts_with("First paragraph"));
    }

    #[test]
    fn falls_back_to_host_when_no_title() {
        let html = "<html><body><p>hi</p></body></html>";
        let e = extract(html, "https://www.blog.example.org/p/1");
        assert_eq!(e.title, "blog.example.org");
        assert_eq!(e.site, "blog.example.org");
    }

    #[test]
    fn description_meta_is_excerpt_fallback_when_no_body() {
        let html = r#"<html><head><meta name="description" content="A short summary.">
            </head><body></body></html>"#;
        let e = extract(html, "https://example.com");
        assert_eq!(e.excerpt, "A short summary.");
    }

    #[test]
    fn excerpt_truncates_long_text_on_word_boundary() {
        let long = "word ".repeat(200);
        let html = format!("<article><p>{long}</p></article>");
        let e = extract(&html, "https://example.com");
        assert!(e.excerpt.chars().count() <= EXCERPT_CHARS + 1);
        assert!(e.excerpt.ends_with('…'));
    }
}
