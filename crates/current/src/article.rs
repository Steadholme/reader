//! In-app reader: SSRF-guarded article fetch + lightweight readability extraction.
//!
//! The reader view ([`crate::handlers::reader`]) fetches an item's `link` when the stored summary
//! is missing/short, extracts the readable main text, and caches it on the item. Both steps live
//! here so they are unit-testable in isolation (extraction is pure; the fetch is the only network
//! surface).
//!
//! SECURITY — this fetches a URL that ORIGINATES from an untrusted feed body, from INSIDE the
//! `holdfast` Docker network, so a naive fetch is a server-side request forgery (SSRF) vector (a
//! feed could point an item link at `http://postgres:5432`, the cloud metadata IP, …). The guard
//! mirrors the sibling Magpie clipper:
//!   * only `http`/`https`;
//!   * resolves the host and REJECTS any private / loopback / link-local / reserved address
//!     (incl. IPv4-mapped IPv6 and 169.254.169.254);
//!   * follows redirects MANUALLY so EVERY hop is re-validated;
//!   * caps the total bytes read (and the shared client caps the time).
//!
//! Extraction ALWAYS yields PLAIN TEXT (tags stripped, entities decoded) — the reader escapes
//! every line again on render, so remote `<script>`/`onerror` can never reach the page.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::redirect::Policy;
use reqwest::Url;
use thiserror::Error;
use tokio::net::lookup_host;

use crate::config::{
    DEFAULT_FETCH_TIMEOUT_SECS, MAX_ARTICLE_BYTES, MAX_ARTICLE_REDIRECTS, MAX_FULLTEXT_CHARS,
};
use crate::feed::{collapse_ws, decode_entities};

/// A failed article fetch. The reader maps every variant to the same graceful fallback (show the
/// feed summary); the message is logged, not surfaced to the reader.
#[derive(Debug, Error)]
pub enum ArticleError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("blocked host: {0}")]
    Blocked(String),
    #[error("remote returned status {0}")]
    Status(u16),
    #[error("network error: {0}")]
    Network(String),
}

/// The process-wide no-redirect client used for article fetches. Redirects are disabled so the
/// SSRF guard runs on EVERY hop (the shared `AppState.http` follows redirects automatically, which
/// would let a redirect escape to an internal host — hence a dedicated client here). Installs the
/// `ring` rustls provider (idempotent) exactly like [`crate::build_http_client`].
fn article_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(10))
            .user_agent("HOLDFAST-Current/0.1 (+https://rss.w33d.xyz)")
            .redirect(Policy::none())
            .build()
            .expect("build article reqwest client")
    })
}

/// Fetch an article page over http/https with the SSRF guard + manual redirect loop + size cap.
/// Returns the (size-capped, lossily-decoded) response body on success.
pub async fn fetch_article(url: &str) -> Result<String, ArticleError> {
    let client = article_client();
    let mut current = parse_http_url(url)?;

    for _ in 0..=MAX_ARTICLE_REDIRECTS {
        guard_url(&current).await?;
        let resp = client
            .get(current.clone())
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            )
            .send()
            .await
            .map_err(|e| ArticleError::Network(e.to_string()))?;

        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| ArticleError::Network("redirect without Location".into()))?;
            current = current
                .join(location)
                .map_err(|e| ArticleError::InvalidUrl(e.to_string()))?;
            continue;
        }
        if !status.is_success() {
            return Err(ArticleError::Status(status.as_u16()));
        }
        return read_capped(resp).await;
    }
    Err(ArticleError::Network("too many redirects".into()))
}

/// Parse + scheme-check a candidate URL (http/https only).
fn parse_http_url(input: &str) -> Result<Url, ArticleError> {
    let url = Url::parse(input.trim()).map_err(|e| ArticleError::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(ArticleError::InvalidUrl(format!("unsupported scheme '{other}'"))),
    }
}

/// Resolve the URL's host and reject it if ANY resolved address is internal/reserved.
async fn guard_url(url: &Url) -> Result<(), ArticleError> {
    let host = url
        .host_str()
        .ok_or_else(|| ArticleError::InvalidUrl("missing host".into()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().unwrap_or(80);

    let addrs = lookup_host((host, port))
        .await
        .map_err(|e| ArticleError::Network(format!("dns: {e}")))?;
    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if ip_blocked(addr.ip()) {
            return Err(ArticleError::Blocked(format!("{host} -> {}", addr.ip())));
        }
    }
    if !saw_any {
        return Err(ArticleError::Network(format!("no address for {host}")));
    }
    Ok(())
}

/// Stream the response body, stopping once [`MAX_ARTICLE_BYTES`] is reached, then decode lossily.
async fn read_capped(mut resp: reqwest::Response) -> Result<String, ArticleError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ArticleError::Network(e.to_string()))?
    {
        let remaining = MAX_ARTICLE_BYTES.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// True if an address must not be fetched (loopback / private / link-local / reserved / etc).
/// Mirrors Magpie's guard so the two clippers block the identical address space.
pub fn ip_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_blocked(v4);
            }
            v6_blocked(v6)
        }
    }
}

fn v4_blocked(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || o[0] >= 240 // 240/4 reserved + 255/8
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 IETF
}

fn v6_blocked(a: Ipv6Addr) -> bool {
    let seg = a.segments();
    a.is_loopback()
        || a.is_unspecified()
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

// ---------------------------------------------------------------------------
// Readability extraction (pure; HTML -> plain-text paragraphs)
// ---------------------------------------------------------------------------

/// Tags whose ENTIRE content is dropped before extraction (never readable body; keeping their
/// text would just add noise — final render escapes regardless, so this is quality, not safety).
const NOISE_TAGS: &[&str] = &[
    "script", "style", "head", "noscript", "svg", "template", "iframe", "form", "select", "button",
];

/// Tags that mark a paragraph/line boundary: their appearance emits a break so block structure
/// survives the strip-to-text pass.
const BREAK_TAGS: &[&str] = &[
    "p", "div", "br", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre",
    "section", "article", "main", "header", "footer", "aside", "tr", "table", "figure",
    "figcaption", "hr", "dd", "dt", "dl", "nav", "body",
];

/// Extract the readable main text of an HTML page as plain-text paragraphs.
///
/// Heuristic (intentionally simple, mirroring Magpie's altitude): drop noise elements, narrow to
/// the best content root (`<article>` > `<main>` > `<body>` > whole doc), then turn block-level
/// tags into line breaks and strip everything else to text. Returns one entry per non-empty
/// paragraph; the total is char-capped by [`MAX_FULLTEXT_CHARS`].
pub fn extract_readable(html: &str) -> Vec<String> {
    let cleaned = strip_noise_elements(html);
    let region = narrow_region(&cleaned);
    let text = blocks_to_text(region);
    let decoded = decode_entities(&text);

    let mut paras: Vec<String> = Vec::new();
    let mut used = 0usize;
    for line in decoded.split('\n') {
        let p = collapse_ws(line);
        let p = p.trim();
        // Drop empty lines and lone punctuation/bullet fragments.
        if p.chars().filter(|c| c.is_alphanumeric()).count() < 2 {
            continue;
        }
        if used >= MAX_FULLTEXT_CHARS {
            break;
        }
        let remaining = MAX_FULLTEXT_CHARS - used;
        let clipped: String = if p.chars().count() > remaining {
            p.chars().take(remaining).collect()
        } else {
            p.to_string()
        };
        used += clipped.chars().count();
        paras.push(clipped);
    }
    paras
}

/// Join extracted paragraphs into a single cached string (blank line between paragraphs). The
/// reader splits back on the blank lines to render `<p>` elements.
pub fn paragraphs_to_cache(paras: &[String]) -> String {
    paras.join("\n\n")
}

/// Split a cached full-text string back into paragraphs (inverse of [`paragraphs_to_cache`]).
pub fn cache_to_paragraphs(cached: &str) -> Vec<String> {
    cached
        .split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// Remove every `<tag>…</tag>` span for the [`NOISE_TAGS`], case-insensitively. Non-nested
/// scan (adequate for script/style/head/… which do not meaningfully nest inside one another).
fn strip_noise_elements(html: &str) -> String {
    let mut out = html.to_string();
    for tag in NOISE_TAGS {
        out = strip_one_element(&out, tag);
    }
    out
}

/// Remove all `<tag …>…</tag>` spans (and any dangling `<tag …>` with no close) for one tag.
fn strip_one_element(html: &str, tag: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let open_pat = format!("<{tag}");
    let close_pat = format!("</{tag}>");
    let mut out = String::with_capacity(html.len());
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(&open_pat) {
        let start = pos + rel;
        // The char right after the tag name must be a delimiter, else it's a longer tag name.
        let after = start + open_pat.len();
        let ok_boundary = lower[after..]
            .chars()
            .next()
            .map(|c| c == '>' || c == '/' || c.is_ascii_whitespace())
            .unwrap_or(false);
        if !ok_boundary {
            // Not really this tag (e.g. `<selection>` vs `<select>`): copy past the `<` and go on.
            out.push_str(&html[pos..start + 1]);
            pos = start + 1;
            continue;
        }
        out.push_str(&html[pos..start]);
        // Drop through the matching close tag if present, else to end of string.
        match lower[after..].find(&close_pat) {
            Some(crel) => pos = after + crel + close_pat.len(),
            None => {
                pos = html.len();
                break;
            }
        }
    }
    out.push_str(&html[pos..]);
    out
}

/// Narrow to the best content root: the first `<article>`, else `<main>`, else `<body>`, else the
/// whole (cleaned) document. Returns a slice of `html`.
fn narrow_region(html: &str) -> &str {
    for tag in ["article", "main", "body"] {
        if let Some(inner) = element_inner(html, tag) {
            return inner;
        }
    }
    html
}

/// Inner slice of the first `<tag …>…</tag>` (case-insensitive); `None` when absent/unclosed.
fn element_inner<'a>(html: &'a str, tag: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let open_pat = format!("<{tag}");
    let close_pat = format!("</{tag}>");
    let open_start = lower.find(&open_pat)?;
    // Find the end of the opening tag (`>`).
    let gt = lower[open_start..].find('>')? + open_start;
    let inner_start = gt + 1;
    let close_rel = lower[inner_start..].find(&close_pat)?;
    Some(&html[inner_start..inner_start + close_rel])
}

/// Strip tags to text, emitting a `\n` for each block/break tag so paragraph structure survives.
fn blocks_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut chars = html.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '<' {
            out.push(c);
            continue;
        }
        // Read the tag name (skip a leading '/').
        let rest = &html[i + 1..];
        let name_src = rest.strip_prefix('/').unwrap_or(rest);
        let name: String = name_src
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if BREAK_TAGS.contains(&name.as_str()) {
            out.push('\n');
        }
        // Consume the rest of the tag up to and including '>'.
        for (_, tc) in chars.by_ref() {
            if tc == '>' {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_and_metadata_addresses() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_blocked(ip), "{s} should be blocked");
        }
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!ip_blocked(ip), "{s} should be allowed");
        }
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(matches!(
            parse_http_url("file:///etc/passwd"),
            Err(ArticleError::InvalidUrl(_))
        ));
        assert!(parse_http_url("https://example.com/a").is_ok());
    }

    #[test]
    fn extract_prefers_article_and_drops_script() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title>
            <script>var x = "<p>evil</p>";</script><style>.a{color:red}</style></head>
            <body>
              <nav><a href="/">Home</a></nav>
              <article>
                <h1>The Headline</h1>
                <p>First real paragraph of the article body.</p>
                <p>Second paragraph with <a href="/x">a link</a> inside.</p>
              </article>
              <footer><p>Copyright junk here</p></footer>
            </body></html>"#;
        let paras = extract_readable(html);
        let joined = paras.join(" | ");
        assert!(joined.contains("The Headline"));
        assert!(joined.contains("First real paragraph of the article body."));
        assert!(joined.contains("a link")); // inline anchor text kept
        assert!(!joined.contains("evil"));
        assert!(!joined.contains("color:red"));
        // Narrowed to <article>, so the footer is excluded.
        assert!(!joined.contains("Copyright junk"));
    }

    #[test]
    fn extract_strips_tags_and_decodes_entities() {
        let html = "<body><main><p>Tom &amp; Jerry &#8217;s <b>big</b> show</p></main></body>";
        let paras = extract_readable(html);
        assert_eq!(paras.len(), 1);
        // Entities decoded, inline <b> tag stripped (its text kept), no markup left.
        assert!(paras[0].contains("Tom & Jerry"));
        assert!(paras[0].contains("big show"));
        assert!(!paras[0].contains('<'));
        assert!(!paras[0].contains("&amp;"));
    }

    #[test]
    fn cache_round_trips_paragraphs() {
        let paras = vec!["One line.".to_string(), "Two line.".to_string()];
        let cached = paragraphs_to_cache(&paras);
        assert_eq!(cache_to_paragraphs(&cached), paras);
    }

    #[test]
    fn extract_empty_when_no_text() {
        assert!(extract_readable("<html><body><script>x=1</script></body></html>").is_empty());
    }
}
