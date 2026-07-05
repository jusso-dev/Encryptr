use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::domain::dto::{CreateKeyRequest, KeyResponse};
use crate::error::AppResult;
use crate::middleware::auth::AuthUser;
use crate::services::keys;
use crate::state::AppState;

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<KeyResponse>>> {
    let items = keys::list(&state, user.user_id).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateKeyRequest>,
) -> AppResult<(StatusCode, Json<KeyResponse>)> {
    let record = keys::upload(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(record.into())))
}
