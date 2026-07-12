//! Authentication endpoints.

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;
use std::net::SocketAddr;

use crate::domain::dto::{
    LoginRequest, MeResponse, RefreshRequest, RegisterRequest, RegisterResponse, TokenResponse,
};
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::repositories::users;
use crate::services::auth::{self, ClientMeta};
use crate::state::AppState;

fn client_meta(headers: &axum::http::HeaderMap, addr: SocketAddr) -> ClientMeta {
    ClientMeta {
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(255).collect()),
        ip_address: Some(addr.ip().to_string()),
    }
}

/// Register a new account.
#[utoipa::path(
    post, path = "/register", tag = "auth",
    security(),
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created", body = RegisterResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 409, description = "Email already registered", body = crate::api::openapi::ApiError),
        (status = 429, description = "Rate limited", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<RegisterResponse>)> {
    let meta = client_meta(&headers, addr);
    let user = auth::register(&state, request, &meta).await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user.id,
            email: user.email,
        }),
    ))
}

/// Exchange credentials for an access/refresh token pair.
#[utoipa::path(
    post, path = "/login", tag = "auth",
    security(),
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated", body = TokenResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 401, description = "Invalid credentials", body = crate::api::openapi::ApiError),
        (status = 429, description = "Rate limited", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<LoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    let meta = client_meta(&headers, addr);
    let tokens = auth::login(&state, &request.email, &request.password, &meta).await?;
    Ok(Json(tokens))
}

/// Rotate a refresh token for a fresh access/refresh pair. Reuse of an
/// already-rotated token revokes the whole session.
#[utoipa::path(
    post, path = "/refresh", tag = "auth",
    security(),
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Rotated", body = TokenResponse),
        (status = 401, description = "Invalid, expired, or reused token", body = crate::api::openapi::ApiError),
        (status = 429, description = "Rate limited", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> AppResult<Json<TokenResponse>> {
    let meta = client_meta(&headers, addr);
    let tokens = auth::refresh(&state, &request.refresh_token, &meta).await?;
    Ok(Json(tokens))
}

/// Revoke the current session and all its refresh tokens.
#[utoipa::path(
    post, path = "/logout", tag = "auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let meta = client_meta(&headers, addr);
    auth::logout(&state, user.user_id, user.session_id, &meta).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Return the authenticated user's profile.
#[utoipa::path(
    get, path = "/me", tag = "auth",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current user", body = MeResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn me(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<MeResponse>> {
    let record = users::find_by_id(&state.pool, user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(record.into()))
}
