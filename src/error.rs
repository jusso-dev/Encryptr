//! Application error type and its HTTP mapping.
//!
//! Internal failure details are logged server-side but never leaked to the
//! client; responses carry only a stable machine-readable code and a safe
//! human-readable message.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited")]
    RateLimited,

    #[error("upstream provider error")]
    Provider(#[from] crate::providers::ProviderError),

    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Provider(_) => (StatusCode::BAD_GATEWAY, "provider_error"),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }

    /// Message that is safe to return to the client.
    fn public_message(&self) -> String {
        match self {
            Self::Validation(msg) | Self::Conflict(msg) => msg.clone(),
            Self::Unauthorized => "authentication required or credentials invalid".into(),
            Self::Forbidden => "you do not have access to this resource".into(),
            Self::NotFound => "resource not found".into(),
            Self::RateLimited => "too many requests, slow down".into(),
            Self::Provider(_) => "upstream AI provider request failed".into(),
            Self::Database(_) | Self::Internal(_) => "an internal error occurred".into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();

        if status.is_server_error() {
            // Full detail stays in the logs; the client sees a generic message.
            tracing::error!(error = ?self, code, "request failed");
        } else {
            tracing::debug!(error = %self, code, "request rejected");
        }

        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message: self.public_message(),
            },
        };
        (status, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_details() {
        let err = AppError::Internal(anyhow::anyhow!("secret db password leaked"));
        assert_eq!(err.status_and_code().0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!err.public_message().contains("secret"));
    }

    #[test]
    fn validation_messages_are_returned() {
        let err = AppError::Validation("email is invalid".into());
        assert_eq!(err.status_and_code().0, StatusCode::BAD_REQUEST);
        assert_eq!(err.public_message(), "email is invalid");
    }
}
