//! Application errors, rendered as branded HTML pages.
//!
//! Magpie is a browser-facing app, so a failure renders the enterprise error page (the shared
//! app-bar and design tokens) rather than a JSON envelope. Store failures collapse to a 500; a
//! missing clip is a 404; a CSRF/ownership rejection is a 400/403; a failed remote fetch is a 502.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (e.g. CSRF mismatch, invalid URL).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// Authenticated but not allowed (e.g. acting on someone else's clip).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such clip.
    #[error("not_found: {0}")]
    NotFound(String),

    /// The remote page could not be fetched/clipped.
    #[error("bad_gateway: {0}")]
    BadGateway(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    /// Map to `(status, heading, message)` for the rendered error page.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "Not allowed", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::BadGateway(d) => (StatusCode::BAD_GATEWAY, "Could not save this page", d.clone()),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        // No gateway identity is plumbed through the error path, so the app-bar shows the
        // generic "Magpie" lockup.
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Store failures collapse to a 500 server_error — the clip itself is never wrong, only the
/// underlying storage can fail (DB I/O).
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}

/// Fetch failures map to a 502 (the remote page is the upstream that failed), except an invalid
/// URL which is the caller's fault (400).
impl From<crate::fetch::FetchError> for AppError {
    fn from(e: crate::fetch::FetchError) -> Self {
        use crate::fetch::FetchError;
        match e {
            FetchError::InvalidUrl(d) => {
                AppError::BadRequest(format!("That does not look like a valid web address: {d}"))
            }
            FetchError::Blocked(_) => AppError::BadRequest(
                "That address points at an internal or reserved host and cannot be saved."
                    .to_string(),
            ),
            FetchError::Status(code) => {
                AppError::BadGateway(format!("The page returned HTTP {code}."))
            }
            FetchError::Network(d) => {
                AppError::BadGateway(format!("The page could not be fetched: {d}"))
            }
        }
    }
}
