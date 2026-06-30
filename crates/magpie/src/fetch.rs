//! The clipper's outbound fetch layer.
//!
//! `Fetcher` is a small async trait so the HTTP-bound implementation ([`HttpFetcher`]) can be
//! swapped for a deterministic fake in tests (the default test suite NEVER touches the network).
//! Handlers call `fetch(url)` to obtain the raw bytes of a page; readability extraction is a
//! separate pure step ([`crate::extract`]).
//!
//! SECURITY — Magpie fetches a user-supplied URL from INSIDE the `holdfast` Docker network, so a
//! naive fetcher is a server-side request forgery (SSRF) vector (a signed-in user could aim it at
//! `http://postgres:5432`, `http://keystone:8443`, the cloud metadata IP, …). The guard here:
//!   * allows ONLY `http`/`https`;
//!   * resolves the host and REJECTS any address in a private / loopback / link-local / reserved
//!     range (incl. IPv4-mapped IPv6 and the 169.254.169.254 metadata address);
//!   * follows redirects MANUALLY (reqwest `Policy::none`) so EVERY hop is re-validated;
//!   * caps the total bytes read and the total time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::redirect::Policy;
use reqwest::Url;
use thiserror::Error;
use tokio::net::lookup_host;

use crate::config::{FETCH_TIMEOUT_SECS, MAX_FETCH_BYTES, MAX_REDIRECTS, USER_AGENT};

/// A failed fetch, mapped to a user-facing message by the handler.
#[derive(Debug, Error)]
pub enum FetchError {
    /// The submitted string is not a usable http/https URL.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// The URL resolves to a blocked (internal/reserved) address.
    #[error("blocked host: {0}")]
    Blocked(String),
    /// The remote server returned a non-success status.
    #[error("remote returned status {0}")]
    Status(u16),
    /// A transport-level failure (DNS, connect, TLS, timeout, body read).
    #[error("network error: {0}")]
    Network(String),
}

/// The raw result of a successful fetch (pre-extraction).
#[derive(Clone, Debug)]
pub struct Fetched {
    /// The FINAL URL after redirects (used as the canonical stored URL + extraction base).
    pub final_url: String,
    /// Lower-cased media type (the part before any `;`), e.g. `text/html`.
    pub content_type: String,
    /// The (size-capped, lossily-UTF-8-decoded) response body.
    pub body: String,
}

/// Outbound page fetcher. Async so the handler `.await`s it natively (no blocking).
#[async_trait]
pub trait Fetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Fetched, FetchError>;
}

/// reqwest-backed fetcher with the SSRF guard + manual redirect loop + size/time caps.
pub struct HttpFetcher {
    client: reqwest::Client,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpFetcher {
    /// Build the shared client. Redirects are disabled here and handled manually so the guard
    /// runs on every hop.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(6))
            .build()
            .expect("failed to build reqwest client");
        Self { client }
    }
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn fetch(&self, url: &str) -> Result<Fetched, FetchError> {
        let mut current = parse_http_url(url)?;

        // Manual redirect loop: validate -> request -> follow Location, re-validating each hop.
        for _ in 0..=MAX_REDIRECTS {
            guard_url(&current).await?;
            let resp = self
                .client
                .get(current.clone())
                .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5")
                .send()
                .await
                .map_err(|e| FetchError::Network(e.to_string()))?;

            let status = resp.status();
            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FetchError::Network("redirect without Location".into()))?;
                current = current
                    .join(location)
                    .map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
                continue;
            }
            if !status.is_success() {
                return Err(FetchError::Status(status.as_u16()));
            }

            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();

            let final_url = resp.url().to_string();
            let body = read_capped(resp).await?;
            return Ok(Fetched {
                final_url,
                content_type,
                body,
            });
        }
        Err(FetchError::Network("too many redirects".into()))
    }
}

/// Parse + scheme-check a candidate URL.
pub fn parse_http_url(input: &str) -> Result<Url, FetchError> {
    let url = Url::parse(input.trim()).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(FetchError::InvalidUrl(format!("unsupported scheme '{other}'"))),
    }
}

/// Resolve the URL's host and reject it if ANY resolved address is internal/reserved.
async fn guard_url(url: &Url) -> Result<(), FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::InvalidUrl("missing host".into()))?;
    // url-crate keeps IPv6 literals bracketed; strip for the resolver.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().unwrap_or(80);

    let addrs = lookup_host((host, port))
        .await
        .map_err(|e| FetchError::Network(format!("dns: {e}")))?;
    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if ip_blocked(addr.ip()) {
            return Err(FetchError::Blocked(format!("{host} -> {}", addr.ip())));
        }
    }
    if !saw_any {
        return Err(FetchError::Network(format!("no address for {host}")));
    }
    Ok(())
}

/// Stream the response body, stopping once [`MAX_FETCH_BYTES`] is reached, then decode lossily.
async fn read_capped(mut resp: reqwest::Response) -> Result<String, FetchError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?
    {
        let remaining = MAX_FETCH_BYTES.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break; // hit the cap mid-chunk
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// True if an address must not be fetched (loopback / private / link-local / reserved / etc).
/// Uses stable std predicates plus explicit range checks for the few that are unstable.
pub fn ip_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:a.b.c.d) — evaluate against the v4 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_blocked(v4);
            }
            v6_blocked(v6)
        }
    }
}

fn v4_blocked(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()            // 127/8
        || a.is_private()      // 10/8, 172.16/12, 192.168/16
        || a.is_link_local()   // 169.254/16 (incl. the 169.254.169.254 metadata addr)
        || a.is_broadcast()    // 255.255.255.255
        || a.is_documentation()// 192.0.2/24, 198.51.100/24, 203.0.113/24
        || a.is_unspecified()  // 0.0.0.0
        || o[0] == 0           // 0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || o[0] >= 240         // 240/4 reserved + 255/8
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 IETF
}

fn v6_blocked(a: Ipv6Addr) -> bool {
    let seg = a.segments();
    a.is_loopback()             // ::1
        || a.is_unspecified()   // ::
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        assert!(matches!(
            parse_http_url("file:///etc/passwd"),
            Err(FetchError::InvalidUrl(_))
        ));
        assert!(matches!(
            parse_http_url("ftp://example.com"),
            Err(FetchError::InvalidUrl(_))
        ));
        assert!(parse_http_url("https://example.com/a").is_ok());
        assert!(parse_http_url("http://example.com").is_ok());
    }

    #[test]
    fn blocks_internal_v4_addresses() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "240.0.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_blocked(ip), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public_v4_addresses() {
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!ip_blocked(ip), "{s} should be allowed");
        }
    }

    #[test]
    fn blocks_internal_v6_and_mapped() {
        for s in ["::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_blocked(ip), "{s} should be blocked");
        }
        // A public v6 address is allowed.
        let pub6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!ip_blocked(pub6));
    }
}
