//! Gateway-injected identity + double-submit CSRF.
//!
//! Crier does NO login of its own. The web surface (`/` timeline + composer) sits behind a Sluice
//! `auth=sso` route, where the gateway runs the OIDC browser login against Keystone, STRIPS any
//! inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`. Because Crier is
//! internal-only for that surface (never publicly reachable except for the explicit public
//! ActivityPub paths, which read no identity), it TRUSTS those headers as the authenticated author.
//! Crier never re-emits `X-Auth-*` to any upstream, so there is nothing to strip on the way out.
//!
//! State-changing POSTs (compose) are double-submit CSRF protected: a random token lives in a
//! JS-readable `__Host-csrf` cookie AND in a hidden form field; the POST is accepted only when the
//! two match. The token is minted once and REUSED across page renders.

use axum::http::{header, HeaderMap};

use crate::error::AppError;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser
/// only ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The authenticated author's subject (stable user id), if the gateway injected one.
pub fn author_sub(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SUBJECT)
}

/// The authenticated author's email, if the gateway injected one.
pub fn author_email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_EMAIL)
}

/// The author's email for display, falling back to a neutral label when unauthenticated.
pub fn display_email(headers: &HeaderMap) -> String {
    author_email(headers).unwrap_or_else(|| "—".to_string())
}

/// Require an authenticated author. Returns `(subject, email)`, or `Unauthorized` when no SSO
/// identity is present — defense in depth behind the gateway.
pub fn require_author(headers: &HeaderMap) -> Result<(String, String), AppError> {
    let sub = author_sub(headers).ok_or_else(|| {
        AppError::Unauthorized("no gateway SSO identity (X-Auth-Subject missing)".to_string())
    })?;
    let email = author_email(headers).unwrap_or_default();
    Ok((sub, email))
}

/// The two GLOBAL admin groups that authorize every crate's `/admin`. These are ALWAYS in effect
/// (nothing that works today breaks) and act as the default seed for [`admin_groups`].
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// Crier's product-facing surface is "social" (social.w33d.xyz), so its DELEGATED admin group is
/// `social-admins`. Overridable via `CRIER_ADMIN_GROUP`. See [`admin_groups`].
const PRODUCT_ADMIN_GROUP: &str = "social-admins";

/// The authenticated user's groups, parsed from the comma-separated `X-Auth-Groups` header
/// (injected AND HMAC-verified by the gateway, so it is trustworthy). Empty when absent/blank.
pub fn author_groups(headers: &HeaderMap) -> Vec<String> {
    header_value(headers, HEADER_GROUPS)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the authenticated user belongs to `group` (exact match against `X-Auth-Groups`).
pub fn has_group(headers: &HeaderMap, group: &str) -> bool {
    author_groups(headers).iter().any(|g| g == group)
}

/// Delegated admin: the effective admin-group set is the two globals ([`ADMIN_GROUPS`]) PLUS a
/// product-specific group (`social-admins` by default, or `CRIER_ADMIN_GROUP`). This lets an
/// operator hand someone Crier's blocklist/moderation panel via Census WITHOUT granting estate-wide
/// admin. Resolved ONCE from the environment; the two globals are ALWAYS present, so this is purely
/// additive — existing `admins`/`infra-admins` behavior is unchanged, and until an operator assigns
/// the product group to someone it authorizes no one.
fn admin_groups() -> &'static [String] {
    static GROUPS: OnceLock<Vec<String>> = OnceLock::new();
    GROUPS.get_or_init(|| {
        let product = std::env::var("CRIER_ADMIN_GROUP")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| PRODUCT_ADMIN_GROUP.to_string());
        let mut groups: Vec<String> = ADMIN_GROUPS.iter().map(|s| s.to_string()).collect();
        if !groups.iter().any(|g| g == &product) {
            groups.push(product);
        }
        groups
    })
}

/// Whether the authenticated user is in ANY effective admin group (the two globals plus the
/// resolved product group — see [`admin_groups`]).
pub fn is_admin(headers: &HeaderMap) -> bool {
    let groups = author_groups(headers);
    admin_groups().iter().any(|a| groups.iter().any(|g| g == a))
}

/// Require admin group membership for an `/admin` action. `Forbidden` (403) when the authenticated
/// user carries no admin group — ordinary signed-in users get 403; only admins see the panel.
pub fn require_admin(headers: &HeaderMap) -> Result<(), AppError> {
    if is_admin(headers) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "admin panel requires an admin group".to_string(),
        ))
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND an
/// identity (`X-Auth-Subject`) is present, a valid `X-Auth-Sig` — HMAC-SHA256 over
/// `subject "\n" groups "\n" minute` for the current OR previous minute — is REQUIRED; a rogue
/// peer that POSTs `X-Auth-Subject` directly (bypassing Sluice) cannot forge it. Returns:
/// - `true` when the key is unset (verification off), or no identity header is present
///   (public/dev path), or the signature is valid;
/// - `false` when an identity is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    let key = gateway_key();
    if key.is_empty() {
        return true;
    }
    let Some(subject) = header_value(headers, HEADER_SUBJECT) else {
        return true; // no injected identity to verify (public route / local dev)
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go).
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token: 32 CSPRNG bytes, hex-encoded.
pub fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Resolve the CSRF token to embed in this render's forms. Reuses the existing cookie token when
/// present (stable across pages/tabs); otherwise mints one and returns the matching `Set-Cookie`.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => (c, None),
        _ => {
            let token = new_csrf_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    let ok = match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Unauthorized("CSRF token mismatch".to_string()))
    }
}

/// Length-checked constant-time byte comparison.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_random_and_hex() {
        let a = new_csrf_token();
        let b = new_csrf_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn csrf_double_submit_matches_and_rejects() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token).is_ok());
        assert!(verify_csrf(&headers, "not-the-token").is_err());
        assert!(verify_csrf(&HeaderMap::new(), &token).is_err());
    }

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go — the cross-language contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, "user-42".parse().unwrap());
        assert!(gateway_identity_ok(&h));
    }

    #[test]
    fn has_group_and_require_admin() {
        // no X-Auth-Groups -> no groups, not an admin, require_admin rejects.
        let mut none = HeaderMap::new();
        none.insert(HEADER_SUBJECT, "u_eve".parse().unwrap());
        assert!(author_groups(&none).is_empty());
        assert!(!has_group(&none, "admins"));
        assert!(!is_admin(&none));
        assert!(require_admin(&none).is_err());

        // comma-separated groups, with whitespace, parse and match by exact name.
        let mut admins = HeaderMap::new();
        admins.insert(HEADER_GROUPS, "dev, infra-admins ,x".parse().unwrap());
        assert!(has_group(&admins, "infra-admins"));
        assert!(has_group(&admins, "dev"));
        assert!(!has_group(&admins, "admins"));
        assert!(is_admin(&admins), "infra-admins authorizes the panel");
        assert!(require_admin(&admins).is_ok());

        // the `admins` group alone also authorizes.
        let mut a2 = HeaderMap::new();
        a2.insert(HEADER_GROUPS, "admins".parse().unwrap());
        assert!(is_admin(&a2));
        assert!(require_admin(&a2).is_ok());

        // delegated admin: the product group (`social-admins`, the CRIER_ADMIN_GROUP default) also
        // authorizes the panel WITHOUT any global admin group present.
        let mut delegated = HeaderMap::new();
        delegated.insert(HEADER_GROUPS, "readers,social-admins".parse().unwrap());
        assert!(is_admin(&delegated), "social-admins is a delegated admin group");
        assert!(require_admin(&delegated).is_ok());

        // a non-admin group alone does not authorize.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, "readers,writers".parse().unwrap());
        assert!(!is_admin(&other));
        assert!(require_admin(&other).is_err());
    }

    #[test]
    fn require_author_needs_subject() {
        assert!(require_author(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_SUBJECT, "u_123".parse().unwrap());
        headers.insert(HEADER_EMAIL, "a@holdfast.local".parse().unwrap());
        let (sub, email) = require_author(&headers).unwrap();
        assert_eq!(sub, "u_123");
        assert_eq!(email, "a@holdfast.local");
    }
}
