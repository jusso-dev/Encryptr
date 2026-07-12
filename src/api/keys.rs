use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::domain::dto::{CreateKeyRequest, KeyResponse};
use crate::error::AppResult;
use crate::middleware::auth::AuthUser;
use crate::services::keys;
use crate::state::AppState;

/// List the caller's public keys.
#[utoipa::path(
    get, path = "/keys", tag = "keys", operation_id = "list_keys",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Public keys", body = Vec<KeyResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<KeyResponse>>> {
    let items = keys::list(&state, user.user_id).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

/// Upload a device public-key pair (Ed25519 + X25519).
#[utoipa::path(
    post, path = "/keys", tag = "keys", operation_id = "create_key",
    security(("bearerAuth" = [])),
    request_body = CreateKeyRequest,
    responses(
        (status = 201, description = "Stored", body = KeyResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
        (status = 409, description = "Duplicate label", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateKeyRequest>,
) -> AppResult<(StatusCode, Json<KeyResponse>)> {
    let record = keys::upload(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(record.into())))
}
