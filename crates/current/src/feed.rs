//! Feed fetching, RSS 2.0 + Atom parsing, and summary sanitization.
//!
//! SECURITY: a feed body is UNTRUSTED REMOTE content. Item summaries are stripped to PLAIN
//! TEXT here ([`html_to_text`]) — every tag is removed and entities decoded — and then HTML-
//! escaped again at render time, so no remote `<script>`/`onerror`/`javascript:` can ever
//! reach the page (defense-in-depth against stored XSS). Item links are scheme-allowlisted to
//! http/https by [`safe_link`]; anything else is dropped (rendered as non-link text).
//!
//! The parser is a small hand-rolled state machine over the `quick-xml` streaming pull-parser
//! (pure Rust, no C deps). It understands both RSS 2.0 (`<channel><item>…`) and Atom
//! (`<feed><entry>…`) in one pass; a malformed body stops the parse early and keeps whatever
//! was read, so a bad feed never panics.

use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;

use crate::config::{
    MAX_FEED_BYTES, MAX_GUID_CHARS, MAX_ITEMS_PER_FETCH, MAX_OPML_OUTLINES, MAX_SUMMARY_CHARS,
    MAX_TITLE_CHARS,
};
use crate::model::{Feed, Item};
use crate::store::Store;
use crate::{random_alnum, FEED_ID_LEN, ITEM_ID_LEN};

// ---------------------------------------------------------------------------
// Parsed (in-flight) shapes
// ---------------------------------------------------------------------------

/// The result of parsing a feed body: the feed's own title + its entries.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedFeed {
    pub title: Option<String>,
    pub items: Vec<ParsedItem>,
}

/// One parsed entry, before normalization into a stored [`Item`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedItem {
    pub title: Option<String>,
    pub link: Option<String>,
    pub guid: Option<String>,
    pub summary: Option<String>,
    /// Epoch seconds, if a publish/updated date was present and parseable.
    pub published: Option<i64>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse an RSS 2.0 or Atom document into a [`ParsedFeed`]. Never panics: a malformed body
/// ends the parse early, keeping whatever entries were already read.
pub fn parse_feed(xml: &str) -> ParsedFeed {
    let mut reader = Reader::from_str(xml);
    let mut feed = ParsedFeed::default();
    let mut stack: Vec<String> = Vec::new();
    let mut cur: Option<ParsedItem> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(_) => break,
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = local_lower(e.name());
                if name == "item" || name == "entry" {
                    cur = Some(ParsedItem::default());
                } else if name == "link" {
                    if let (Some(item), Some(href)) = (cur.as_mut(), atom_link(&e)) {
                        if item.link.is_none() {
                            item.link = Some(href);
                        }
                    }
                }
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = local_lower(e.name());
                if name == "link" {
                    if let (Some(item), Some(href)) = (cur.as_mut(), atom_link(&e)) {
                        if item.link.is_none() {
                            item.link = Some(href);
                        }
                    }
                }
                // self-closing element: no stack push (no matching End)
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map(|c| c.into_owned()).unwrap_or_default();
                handle_text(&mut feed, &mut cur, &stack, &text);
            }
            Ok(Event::CData(e)) => {
                let text = String::from_utf8_lossy(&e.into_inner()).into_owned();
                handle_text(&mut feed, &mut cur, &stack, &text);
            }
            Ok(Event::End(e)) => {
                let name = local_lower(e.name());
                if name == "item" || name == "entry" {
                    if let Some(item) = cur.take() {
                        feed.items.push(item);
                        if feed.items.len() >= MAX_ITEMS_PER_FETCH {
                            break;
                        }
                    }
                }
                stack.pop();
            }
            _ => {}
        }
        buf.clear();
    }
    feed
}

/// Route a text/CDATA run to the right field, based on the current element and its parent.
fn handle_text(feed: &mut ParsedFeed, cur: &mut Option<ParsedItem>, stack: &[String], text: &str) {
    let Some(top) = stack.last().map(String::as_str) else {
        return;
    };
    if let Some(item) = cur.as_mut() {
        match top {
            "title" => push_opt(&mut item.title, text),
            // RSS text link (`<link>http://…</link>`); Atom uses the href attribute instead.
            "link" if item.link.is_none() => push_opt(&mut item.link, text),
            "guid" => push_opt(&mut item.guid, text),
            // Atom entry id — only as a guid fallback (RSS `<guid>` wins).
            "id" if item.guid.is_none() => push_opt(&mut item.guid, text),
            "description" | "summary" | "content" | "encoded" if item.summary.is_none() => {
                push_opt(&mut item.summary, text)
            }
            "pubdate" | "published" | "date" | "updated" if item.published.is_none() => {
                item.published = parse_date(text)
            }
            _ => {}
        }
    } else {
        // Feed-level title: only the channel/feed's own `<title>` (never `<image><title>`).
        let parent = stack
            .len()
            .checked_sub(2)
            .and_then(|i| stack.get(i))
            .map(String::as_str);
        if top == "title"
            && matches!(parent, Some("channel") | Some("feed"))
            && feed.title.is_none()
        {
            let t = text.trim();
            if !t.is_empty() {
                feed.title = Some(t.to_string());
            }
        }
    }
}

/// Lowercased local name (namespace prefix stripped), e.g. `content:encoded` -> `encoded`.
fn local_lower(name: QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().into_inner()).to_ascii_lowercase()
}

/// Extract the article href from an Atom `<link>` element, accepting only `rel="alternate"` or
/// a missing `rel` (skips `self`/`enclosure`/`edit`/…). Returns `None` for an RSS `<link>`
/// (which carries the URL as text, handled separately).
fn atom_link(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    let mut href: Option<String> = None;
    let mut rel: Option<String> = None;
    for attr in e.attributes() {
        let Ok(attr) = attr else { continue };
        let key = local_lower(attr.key);
        let Ok(val) = attr.unescape_value() else {
            continue;
        };
        match key.as_str() {
            "href" => href = Some(val.into_owned()),
            "rel" => rel = Some(val.into_owned()),
            _ => {}
        }
    }
    let href = href?;
    match rel.as_deref() {
        None | Some("alternate") => Some(href),
        _ => None,
    }
}

fn push_opt(field: &mut Option<String>, text: &str) {
    match field {
        Some(s) => s.push_str(text),
        None => *field = Some(text.to_string()),
    }
}

/// Parse an RFC3339 (Atom) or RFC2822 (RSS `pubDate`) timestamp into epoch seconds.
fn parse_date(s: &str) -> Option<i64> {
    use time::format_description::well_known::{Rfc2822, Rfc3339};
    let s = s.trim();
    if let Ok(dt) = time::OffsetDateTime::parse(s, &Rfc3339) {
        return Some(dt.unix_timestamp());
    }
    if let Ok(dt) = time::OffsetDateTime::parse(s, &Rfc2822) {
        return Some(dt.unix_timestamp());
    }
    None
}

// ---------------------------------------------------------------------------
// OPML import
// ---------------------------------------------------------------------------

/// Extract every `xmlUrl` from an OPML document's `<outline>` elements (subscription import).
/// Order-preserving, bounded by [`MAX_OPML_OUTLINES`], and never panics (a malformed body ends
/// the parse early, keeping whatever was already read). Values are XML-unescaped and trimmed;
/// scheme validation + dedup are the caller's job (via [`safe_link`] and the store's uniqueness).
pub fn parse_opml_urls(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut urls: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Err(_) | Ok(Event::Eof) => break,
            // Outlines are usually self-closing (`Empty`) but may carry nested children (`Start`).
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_lower(e.name()) == "outline" {
                    if let Some(u) = outline_xmlurl(&e) {
                        urls.push(u);
                        if urls.len() >= MAX_OPML_OUTLINES {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
    urls
}

/// The `xmlUrl` attribute of an OPML `<outline>` (case-insensitive), trimmed; `None` when absent
/// or empty (a grouping outline with no feed URL).
fn outline_xmlurl(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    for attr in e.attributes() {
        let Ok(attr) = attr else { continue };
        if local_lower(attr.key) == "xmlurl" {
            if let Ok(val) = attr.unescape_value() {
                let v = val.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/// Convert an untrusted (possibly HTML) feed summary into bounded PLAIN TEXT: strip tags,
/// decode entities, strip again (catches double-escaped markup), collapse whitespace, and cap
/// the length. The caller still HTML-escapes the result on render — this is defense-in-depth.
pub fn html_to_text(input: &str) -> String {
    let stripped = strip_tags(input);
    let decoded = decode_entities(&stripped);
    let stripped = strip_tags(&decoded);
    let collapsed = collapse_ws(&stripped);
    let trimmed = collapsed.trim();
    if trimmed.chars().count() > MAX_SUMMARY_CHARS {
        let s: String = trimmed.chars().take(MAX_SUMMARY_CHARS).collect();
        format!("{}…", s.trim_end())
    } else {
        trimmed.to_string()
    }
}

/// Drop everything between `<` and the next `>` (tags). Unbalanced `<` with no `>` drops the
/// tail — acceptable, since the goal is to never let markup through.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Decode the common named + numeric HTML entities (so the plain text reads naturally).
fn decode_entities(s: &str) -> String {
    let v: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == '&' {
            if let Some(semi) = (i + 1..(i + 12).min(v.len())).find(|&j| v[j] == ';') {
                let ent: String = v[i + 1..semi].iter().collect();
                if let Some(ch) = entity_char(&ent) {
                    out.push(ch);
                    i = semi + 1;
                    continue;
                }
            }
            out.push('&');
            i += 1;
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    out
}

fn entity_char(ent: &str) -> Option<char> {
    match ent {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "nbsp" => Some(' '),
        "hellip" => Some('…'),
        "mdash" => Some('—'),
        "ndash" => Some('–'),
        "lsquo" => Some('\u{2018}'),
        "rsquo" | "#8217" => Some('\u{2019}'),
        "ldquo" => Some('\u{201C}'),
        "rdquo" => Some('\u{201D}'),
        _ => {
            if let Some(num) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                u32::from_str_radix(num, 16).ok().and_then(char::from_u32)
            } else if let Some(num) = ent.strip_prefix('#') {
                num.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                None
            }
        }
    }
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out
}

/// Allow only absolute http/https links (after stripping whitespace/control chars). Anything
/// else returns `None`, so a `javascript:`/`data:` link is never emitted as an href.
pub fn safe_link(url: &str) -> Option<String> {
    let cleaned: String = url
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_control())
        .collect();
    let lower = cleaned.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some(cleaned)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Fetch + store
// ---------------------------------------------------------------------------

/// Fetch one feed over HTTP(S), parse it, update the feed's title/fetch-time, and upsert its
/// items (dedup by guid). Returns the count of newly-inserted items. Every failure path is an
/// `Err(String)` the caller logs — a bad/unreachable feed never panics and never breaks a page.
pub async fn fetch_and_store(
    client: &reqwest::Client,
    store: &dyn Store,
    feed: &Feed,
    now: i64,
) -> Result<usize, String> {
    let resp = client
        .get(&feed.url)
        .header(
            reqwest::header::ACCEPT,
            "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
        )
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let slice = &bytes[..bytes.len().min(MAX_FEED_BYTES)];
    let xml = String::from_utf8_lossy(slice);
    let parsed = parse_feed(&xml);

    // Adopt the feed's own title once we have it; otherwise keep the existing (URL) title.
    let title = parsed
        .title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_TITLE_CHARS).collect::<String>())
        .unwrap_or_else(|| feed.title.clone());
    store
        .update_feed_meta(&feed.id, &title, now)
        .await
        .map_err(|e| e.to_string())?;

    let mut inserted = 0usize;
    for pi in parsed.items {
        // Stable dedup key: guid, else link, else title. No key -> skip (can't dedup safely).
        let guid = pi
            .guid
            .clone()
            .or_else(|| pi.link.clone())
            .or_else(|| pi.title.clone())
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());
        let Some(guid) = guid else { continue };

        let item = Item {
            id: random_alnum(ITEM_ID_LEN),
            feed_id: feed.id.clone(),
            guid: guid.chars().take(MAX_GUID_CHARS).collect(),
            title: pi
                .title
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .chars()
                .take(MAX_TITLE_CHARS)
                .collect(),
            link: pi
                .link
                .as_deref()
                .map(str::trim)
                .and_then(safe_link)
                .unwrap_or_default(),
            summary: pi.summary.as_deref().map(html_to_text).unwrap_or_default(),
            // No date in the feed -> surface as freshly fetched so it still rivers to the top.
            published_at: pi.published.or(Some(now)),
            read: false,
        };
        if store.upsert_item(&item).await.map_err(|e| e.to_string())? {
            inserted += 1;
        }
    }
    Ok(inserted)
}

/// Mint a fresh feed id (exposed so handlers and the parser share one alphabet/length).
pub fn new_feed_id() -> String {
    random_alnum(FEED_ID_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rss2() {
        let xml = r#"<?xml version="1.0"?>
        <rss version="2.0"><channel>
          <title>Example Blog</title>
          <link>https://example.com</link>
          <item>
            <title>First Post</title>
            <link>https://example.com/1</link>
            <guid>https://example.com/1</guid>
            <description>&lt;p&gt;Hello &lt;b&gt;world&lt;/b&gt;&lt;/p&gt;</description>
            <pubDate>Wed, 02 Oct 2002 13:00:00 +0000</pubDate>
          </item>
          <item>
            <title>Second Post</title>
            <link>https://example.com/2</link>
            <description><![CDATA[<script>alert(1)</script>raw &amp; text]]></description>
          </item>
        </channel></rss>"#;
        let feed = parse_feed(xml);
        assert_eq!(feed.title.as_deref(), Some("Example Blog"));
        assert_eq!(feed.items.len(), 2);
        let first = &feed.items[0];
        assert_eq!(first.title.as_deref(), Some("First Post"));
        assert_eq!(first.link.as_deref(), Some("https://example.com/1"));
        assert!(first.published.is_some());
        // Summary stays markup-free.
        let s = html_to_text(first.summary.as_deref().unwrap());
        assert_eq!(s, "Hello world");
    }

    #[test]
    fn parses_atom() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <title>Atom Example</title>
          <entry>
            <title>Atom One</title>
            <link rel="alternate" href="https://example.org/a"/>
            <link rel="self" href="https://example.org/self"/>
            <id>urn:uuid:1234</id>
            <summary>Just a summary</summary>
            <updated>2003-12-13T18:30:02Z</updated>
          </entry>
        </feed>"#;
        let feed = parse_feed(xml);
        assert_eq!(feed.title.as_deref(), Some("Atom Example"));
        assert_eq!(feed.items.len(), 1);
        let e = &feed.items[0];
        assert_eq!(e.title.as_deref(), Some("Atom One"));
        assert_eq!(e.link.as_deref(), Some("https://example.org/a"));
        assert_eq!(e.guid.as_deref(), Some("urn:uuid:1234"));
        assert!(e.published.is_some());
    }

    #[test]
    fn html_to_text_neutralizes_script_and_decodes() {
        let s = html_to_text("<script>alert(1)</script>Tom &amp; Jerry &#8217;s show");
        assert!(!s.contains('<'));
        assert!(!s.contains("script"));
        assert!(s.contains("Tom & Jerry"));
    }

    #[test]
    fn html_to_text_handles_double_escaped() {
        // After XML unescape this could be `&lt;script&gt;`; decode then re-strip must clear it.
        let s = html_to_text("&amp;lt;script&amp;gt;hi&amp;lt;/script&amp;gt;");
        assert!(!s.contains("<script"));
        assert!(s.contains("hi"));
    }

    #[test]
    fn safe_link_allows_only_http() {
        assert_eq!(
            safe_link("https://example.com/x"),
            Some("https://example.com/x".to_string())
        );
        assert_eq!(safe_link("javascript:alert(1)"), None);
        assert_eq!(safe_link("data:text/html,<script>"), None);
        assert_eq!(safe_link("/relative"), None);
    }

    #[test]
    fn malformed_xml_does_not_panic() {
        let feed = parse_feed("<rss><channel><item><title>broken");
        // Whatever was read is kept; no panic.
        let _ = feed.items.len();
    }

    #[test]
    fn parses_opml_xmlurls_in_order() {
        let opml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <opml version="2.0">
          <head><title>Subscriptions</title></head>
          <body>
            <outline text="News">
              <outline type="rss" text="A" xmlUrl="https://a.com/feed.xml"/>
              <outline type="rss" text="B &amp; co" xmlUrl="https://b.com/atom" htmlUrl="https://b.com"/>
            </outline>
            <outline text="Grouping only, no url"/>
          </body>
        </opml>"#;
        let urls = parse_opml_urls(opml);
        assert_eq!(
            urls,
            vec![
                "https://a.com/feed.xml".to_string(),
                "https://b.com/atom".to_string(),
            ]
        );
    }

    #[test]
    fn malformed_opml_does_not_panic() {
        let urls = parse_opml_urls("<opml><body><outline xmlUrl=\"https://a.com/x\"");
        // Truncated body: whatever was read is kept; no panic.
        let _ = urls.len();
    }
}
