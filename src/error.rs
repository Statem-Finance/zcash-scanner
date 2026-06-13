//! Error type mapped to HTTP. Crucially, error bodies NEVER echo the UFVK or any
//! decrypted memo — only coarse, safe categories.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("upstream lightwalletd error")]
    Upstream,
    #[error("scan failed")]
    Internal,
}

impl IntoResponse for ScanError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            ScanError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ScanError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ScanError::Upstream => (StatusCode::BAD_GATEWAY, "upstream_error"),
            ScanError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        // Message is intentionally generic for non-BadRequest cases so nothing
        // sensitive (or even the exact failure point) leaks to the caller.
        let message = match &self {
            ScanError::BadRequest(m) => m.clone(),
            _ => code.to_string(),
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}
