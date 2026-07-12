//! Bearer-token authentication extractor.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::error::AppError;
use crate::repositories::sessions;
use crate::state::AppState;

/// An authenticated caller. Extracting this validates the JWT *and* checks
/// that the session it was issued for has not been revoked.
#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    /// Access-token expiry (`exp`, Unix seconds). Long-lived consumers such as
    /// the WebSocket stream enforce this as a hard deadline.
    pub expires_at: i64,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(AppError::Unauthorized)?;
        authenticate(state, token).await
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Shared JWT + session-revocation check, also used by the WebSocket
/// endpoint (which receives the token via query parameter).
pub async fn authenticate(state: &AppState, token: &str) -> Result<AuthUser, AppError> {
    let claims = state.jwt.verify(token).ok_or(AppError::Unauthorized)?;
    if !sessions::is_active(&state.pool, claims.sid).await? {
        return Err(AppError::Unauthorized);
    }
    Ok(AuthUser {
        user_id: claims.sub,
        session_id: claims.sid,
        expires_at: claims.exp,
    })
}
