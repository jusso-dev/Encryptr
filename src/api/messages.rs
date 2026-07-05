use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::domain::dto::{CreateMessageRequest, ListMessagesQuery, MessageResponse};
use crate::error::AppResult;
use crate::middleware::auth::AuthUser;
use crate::services::messages;
use crate::state::AppState;

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListMessagesQuery>,
) -> AppResult<Json<Vec<MessageResponse>>> {
    let items = messages::list(&state, user.user_id, query).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateMessageRequest>,
) -> AppResult<(StatusCode, Json<MessageResponse>)> {
    let message = messages::create(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(message.into())))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    messages::delete(&state, user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
