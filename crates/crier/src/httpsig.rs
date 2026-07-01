//! ActivityPub HTTP Signatures (draft-cavage) — the gate to real federation.
//!
//! Everything crypto lives here, transport-agnostic and pure enough to unit test:
//!
//! - [`generate_keypair`] mints the single actor's RSA-2048 keypair (PKCS#8 + SPKI PEM).
//! - [`Signer`] loads the private key once and signs outbound deliveries: it builds the
//!   `(request-target)` / `host` / `date` / `digest` signing string, RSA-SHA256 signs it
//!   (RSASSA-PKCS1-v1_5), and emits the draft-cavage `Signature` header value Mastodon expects.
//! - [`compute_digest`] / [`http_date`] build the `Digest` + `Date` headers a POST must carry.
//! - [`verify_signature`] / [`build_signing_string`] / [`parse_signature_header`] are the inbound
//!   verification primitives; [`verify_inbound`] wires them to a live remote-key fetch.
//!
//! The implementation is pure Rust (the `rsa` crate + `sha2`), so NO OpenSSL is dragged in — the
//! binary stays glibc/rustls-only, matching the estate posture.

use base64::Engine as _;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer as _, Verifier as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// RSA modulus size for the actor key. 2048 bits is the fediverse floor (Mastodon default).
const RSA_BITS: usize = 2048;

/// A freshly generated actor keypair, both halves PEM-encoded for persistence + publication.
#[derive(Clone, Debug)]
pub struct Keypair {
    /// PKCS#8 PEM (`BEGIN PRIVATE KEY`) — persisted to the store, never leaves the process.
    pub private_pem: String,
    /// SPKI PEM (`BEGIN PUBLIC KEY`) — published verbatim as the actor's `publicKeyPem`.
    pub public_pem: String,
}

/// Generate a new RSA-2048 keypair. Draws from the OS CSPRNG; returns PEM on success.
pub fn generate_keypair() -> Result<Keypair, String> {
    let mut rng = rand_core::OsRng;
    let private = RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|e| format!("rsa keygen: {e}"))?;
    let public = RsaPublicKey::from(&private);
    let private_pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("encode private pkcs8: {e}"))?
        .to_string();
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("encode public spki: {e}"))?;
    Ok(Keypair { private_pem, public_pem })
}

/// The loaded actor signing identity: the private key plus the published metadata every outbound
/// delivery needs (the `keyId` URL + the `publicKeyPem` the actor document advertises).
pub struct Signer {
    /// The `keyId` remote servers dereference to fetch our public key (`<actor>#main-key`).
    pub key_id: String,
    /// The SPKI PEM published as the actor's `publicKey.publicKeyPem`.
    pub public_pem: String,
    private_key: RsaPrivateKey,
}

impl Signer {
    /// Load a signer from a PKCS#8 private-key PEM + the published public PEM. `key_id` is the
    /// `<actor_url>#main-key` URL remote servers dereference.
    pub fn load(key_id: String, private_pem: &str, public_pem: String) -> Result<Self, String> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .map_err(|e| format!("decode private pkcs8: {e}"))?;
        Ok(Signer { key_id, public_pem, private_key })
    }

    /// RSA-SHA256 sign an arbitrary message, returning the raw signature bytes.
    fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        // PKCS#1 v1.5 signatures are deterministic — no RNG needed for the `Signer::sign` path.
        signing_key.sign(message).to_vec()
    }

    /// Sign an outbound POST and return the draft-cavage `Signature` header value.
    ///
    /// `target` is the request path (e.g. `/inbox`), `host` the remote host, `date` the exact
    /// `Date` header value, `digest` the exact `Digest` header value. The four covered headers are
    /// `(request-target) host date digest` — the set Mastodon requires for an inbox POST.
    pub fn sign_post(&self, target: &str, host: &str, date: &str, digest: &str) -> String {
        let signing_string = build_signing_string("post", target, host, date, digest);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(self.sign_bytes(signing_string.as_bytes()));
        format!(
            "keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
            self.key_id, sig_b64
        )
    }
}

/// Build the draft-cavage signing string for the fixed `(request-target) host date digest` header
/// set. `method` is lowercased into the `(request-target)` pseudo-header line. Lines are joined by
/// `\n` with NO trailing newline — the exact bytes both sides must agree on.
pub fn build_signing_string(method: &str, target: &str, host: &str, date: &str, digest: &str) -> String {
    format!(
        "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
        method.to_ascii_lowercase(),
        target,
        host,
        date,
        digest
    )
}

/// Compute the `Digest` header value for a body: `SHA-256=<base64(sha256(body))>` (standard base64,
/// per RFC 3230 / RFC 5843 — what Mastodon sends and verifies).
pub fn compute_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    format!("SHA-256={}", base64::engine::general_purpose::STANDARD.encode(hash))
}

/// Format epoch seconds as an HTTP `Date` header (RFC 7231 IMF-fixdate, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`). Always UTC / `GMT`.
pub fn http_date(secs: i64) -> String {
    let dt = OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let weekday = match dt.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = month_abbr(dt.month());
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday,
        dt.day(),
        month,
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// Verify an RSA-SHA256 signature against a signing string, given the signer's SPKI (or PKCS#1)
/// public-key PEM and the base64 signature. Returns `false` on ANY error (bad PEM, bad base64,
/// bad signature) — a verification failure is never a panic.
pub fn verify_signature(public_pem: &str, signing_string: &[u8], signature_b64: &str) -> bool {
    let Some(public_key) = parse_public_key(public_pem) else {
        return false;
    };
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64.trim()) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    verifying_key.verify(signing_string, &signature).is_ok()
}

/// Parse a public key from PEM: prefer SPKI (`BEGIN PUBLIC KEY`, the fediverse norm), fall back to
/// PKCS#1 (`BEGIN RSA PUBLIC KEY`) for the few servers that emit it.
fn parse_public_key(pem: &str) -> Option<RsaPublicKey> {
    if let Ok(k) = RsaPublicKey::from_public_key_pem(pem) {
        return Some(k);
    }
    use rsa::pkcs1::DecodeRsaPublicKey;
    RsaPublicKey::from_pkcs1_pem(pem).ok()
}

/// The parsed fields of a draft-cavage `Signature` header.
#[derive(Debug, Clone)]
pub struct SignatureParams {
    /// The `keyId` URL (an actor `#main-key` fragment) to dereference for the public key.
    pub key_id: String,
    /// The ordered list of covered header names (lowercased), e.g. `["(request-target)","host",…]`.
    pub headers: Vec<String>,
    /// The base64 signature.
    pub signature: String,
}

/// Parse a `Signature: keyId="…",headers="…",signature="…"` header into its fields. Returns `None`
/// when `keyId` or `signature` is absent. A missing `headers` defaults to `date` per the spec.
pub fn parse_signature_header(value: &str) -> Option<SignatureParams> {
    let mut key_id = None;
    let mut headers: Option<Vec<String>> = None;
    let mut signature = None;
    for part in split_params(value) {
        let Some((k, v)) = part.split_once('=') else { continue };
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        match k {
            "keyId" => key_id = Some(v.to_string()),
            "headers" => {
                headers = Some(v.split_whitespace().map(|s| s.to_ascii_lowercase()).collect())
            }
            "signature" => signature = Some(v.to_string()),
            _ => {}
        }
    }
    Some(SignatureParams {
        key_id: key_id?,
        // Per draft-cavage, an omitted `headers` defaults to just `date`.
        headers: headers.unwrap_or_else(|| vec!["date".to_string()]),
        signature: signature?,
    })
}

/// Split a `Signature` header into its comma-separated `k="v"` params WITHOUT breaking on commas
/// that appear inside a quoted value (the base64 signature can contain none, but keyId URLs and
/// future fields might — be robust).
fn split_params(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in value.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Reconstruct the signing string a remote actually signed, from the covered `header_names`, the
/// request `method` + `target` (path), and a lookup of the request's real header values. Returns
/// `Err` when a covered header is missing from the request.
pub fn reconstruct_signing_string(
    header_names: &[String],
    method: &str,
    target: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let mut lines = Vec::with_capacity(header_names.len());
    for name in header_names {
        if name == "(request-target)" {
            lines.push(format!("(request-target): {} {}", method.to_ascii_lowercase(), target));
        } else {
            let value = lookup(name).ok_or_else(|| format!("signed header missing: {name}"))?;
            lines.push(format!("{name}: {value}"));
        }
    }
    Ok(lines.join("\n"))
}

/// Extract the `publicKeyPem` from a fetched actor document. `publicKey` may be an object or an
/// array of keys; we take the first PEM found.
pub fn public_key_pem_from_actor(actor: &serde_json::Value) -> Option<String> {
    let pk = actor.get("publicKey")?;
    let obj = match pk {
        serde_json::Value::Array(a) => a.first()?,
        v => v,
    };
    obj.get("publicKeyPem")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Length-checked constant-time byte comparison (digest/header equality without a timing oracle).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify an inbound POST's HTTP signature end-to-end.
///
/// Steps: parse the `Signature` header; when `digest` is covered, recompute `SHA-256=…` over the
/// real body and constant-compare it to the `Digest` header (so the signature actually binds the
/// body); reconstruct the signing string from the covered headers; fetch the sender's public key
/// from `keyId`; RSA-SHA256 verify. Any failure yields `Err(reason)` — the caller answers `401`.
pub async fn verify_inbound(
    client: &reqwest::Client,
    headers: &axum::http::HeaderMap,
    method: &str,
    target: &str,
    body: &[u8],
) -> Result<(), String> {
    let header_str = |name: &str| -> Option<String> {
        headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    };

    let raw_sig = header_str("signature").ok_or_else(|| "missing Signature header".to_string())?;
    let params = parse_signature_header(&raw_sig).ok_or_else(|| "malformed Signature header".to_string())?;

    // Bind the body: if `digest` is covered it MUST match a fresh hash of the actual body.
    if params.headers.iter().any(|h| h == "digest") {
        let provided = header_str("digest").ok_or_else(|| "signed digest header absent".to_string())?;
        let expected = compute_digest(body);
        if !ct_eq(provided.trim().as_bytes(), expected.as_bytes()) {
            return Err("digest mismatch (body tampered)".to_string());
        }
    }

    let signing_string = reconstruct_signing_string(&params.headers, method, target, &header_str)?;

    // Dereference the keyId to fetch the sender's public key.
    let key_url = params.key_id.split('#').next().unwrap_or(&params.key_id);
    let public_pem = fetch_actor_public_key(client, key_url, &params.key_id).await?;

    if verify_signature(&public_pem, signing_string.as_bytes(), &params.signature) {
        Ok(())
    } else {
        Err("signature verification failed".to_string())
    }
}

/// Fetch the sender actor document and extract its `publicKeyPem`. `actor_url` is `keyId` without
/// its fragment; `key_id` is the full value (used only for the error message).
async fn fetch_actor_public_key(
    client: &reqwest::Client,
    actor_url: &str,
    key_id: &str,
) -> Result<String, String> {
    let resp = client
        .get(actor_url)
        .header(reqwest::header::ACCEPT, crate::activitypub::ACTIVITY_JSON)
        .send()
        .await
        .map_err(|e| format!("fetch sender actor {actor_url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("sender actor {actor_url} returned {}", resp.status()));
    }
    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse sender actor {actor_url}: {e}"))?;
    public_key_pem_from_actor(&doc)
        .ok_or_else(|| format!("sender actor for keyId {key_id} has no publicKeyPem"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_string_is_exact_cavage_form() {
        let s = build_signing_string(
            "POST",
            "/inbox",
            "remote.example",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "SHA-256=abc",
        );
        assert_eq!(
            s,
            "(request-target): post /inbox\nhost: remote.example\ndate: Sun, 06 Nov 1994 08:49:37 GMT\ndigest: SHA-256=abc"
        );
        // No trailing newline, exactly four lines.
        assert_eq!(s.lines().count(), 4);
        assert!(!s.ends_with('\n'));
    }

    #[test]
    fn digest_is_sha256_base64() {
        // echo -n "" | openssl dgst -sha256 -binary | base64 => 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
        assert_eq!(
            compute_digest(b""),
            "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert!(compute_digest(b"hello").starts_with("SHA-256="));
    }

    #[test]
    fn http_date_is_imf_fixdate() {
        // 784111777 = 1994-11-06 08:49:37 UTC (the RFC 7231 canonical example).
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn parse_signature_header_extracts_fields() {
        let raw = "keyId=\"https://remote.example/users/alice#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"AAAA\"";
        let p = parse_signature_header(raw).unwrap();
        assert_eq!(p.key_id, "https://remote.example/users/alice#main-key");
        assert_eq!(p.headers, vec!["(request-target)", "host", "date", "digest"]);
        assert_eq!(p.signature, "AAAA");
    }

    #[test]
    fn parse_signature_header_defaults_headers_to_date() {
        let p = parse_signature_header("keyId=\"k\",signature=\"S\"").unwrap();
        assert_eq!(p.headers, vec!["date"]);
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = generate_keypair().expect("keygen");
        let signer = Signer::load(
            "https://social.w33d.xyz/users/w33d#main-key".to_string(),
            &kp.private_pem,
            kp.public_pem.clone(),
        )
        .expect("load signer");

        let date = http_date(1_700_000_000);
        let digest = compute_digest(b"{\"type\":\"Create\"}");
        let header = signer.sign_post("/inbox", "remote.example", &date, &digest);

        // The header advertises our keyId + the covered set.
        assert!(header.contains("keyId=\"https://social.w33d.xyz/users/w33d#main-key\""));
        assert!(header.contains("headers=\"(request-target) host date digest\""));

        let params = parse_signature_header(&header).unwrap();
        // Reconstruct the signing string exactly as an inbound verifier would.
        let lookup = |name: &str| match name {
            "host" => Some("remote.example".to_string()),
            "date" => Some(date.clone()),
            "digest" => Some(digest.clone()),
            _ => None,
        };
        let signing_string =
            reconstruct_signing_string(&params.headers, "post", "/inbox", lookup).unwrap();

        // The genuine public key verifies; a different key does not.
        assert!(verify_signature(&kp.public_pem, signing_string.as_bytes(), &params.signature));

        let other = generate_keypair().expect("keygen2");
        assert!(!verify_signature(&other.public_pem, signing_string.as_bytes(), &params.signature));

        // A tampered signing string fails.
        let tampered = signing_string.replace("/inbox", "/evil");
        assert!(!verify_signature(&kp.public_pem, tampered.as_bytes(), &params.signature));
    }

    #[test]
    fn public_key_pem_extracted_from_object_and_array() {
        let obj = serde_json::json!({"publicKey": {"publicKeyPem": "PEMHERE"}});
        assert_eq!(public_key_pem_from_actor(&obj).as_deref(), Some("PEMHERE"));
        let arr = serde_json::json!({"publicKey": [{"publicKeyPem": "FIRST"}]});
        assert_eq!(public_key_pem_from_actor(&arr).as_deref(), Some("FIRST"));
        let none = serde_json::json!({"type": "Person"});
        assert!(public_key_pem_from_actor(&none).is_none());
    }
}
