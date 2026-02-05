use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Jail not running: {0}")]
    NotRunning(String),

    #[error("Unsupported on this platform: {0}")]
    Unsupported(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::NotRunning(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::Unsupported(msg) => (StatusCode::NOT_IMPLEMENTED, msg.clone()),
            Self::Timeout(msg) => (StatusCode::REQUEST_TIMEOUT, msg.clone()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            Self::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            Self::Io(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Json(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::Anyhow(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let body = ApiResponse::<()>::error(&message);
        (status, Json(body)).into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_ok() {
        let resp = ApiResponse::ok("hello");
        assert!(resp.success);
        assert_eq!(resp.data, Some("hello"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let resp = ApiResponse::<()>::error("something failed");
        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert_eq!(resp.error, Some("something failed".into()));
    }

    #[test]
    fn test_api_response_serialization() {
        let resp = ApiResponse::ok(42);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"data\":42"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_api_error_display() {
        let err = ApiError::BadRequest("invalid name".into());
        assert_eq!(err.to_string(), "Bad request: invalid name");

        let err = ApiError::NotFound("jail_123".into());
        assert_eq!(err.to_string(), "Not found: jail_123");
    }
}
