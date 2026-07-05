use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::domain::dto::{
    ConversationResponse, CreateConversationRequest, UpdateConversationRequest,
};
use crate::error::AppResult;
use crate::middleware::auth::AuthUser;
use crate::services::conversations;
use crate::state::AppState;

pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ConversationResponse>>> {
    let items = conversations::list(&state, user.user_id).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateConversationRequest>,
) -> AppResult<(StatusCode, Json<ConversationResponse>)> {
    let conversation = conversations::create(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(conversation.into())))
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateConversationRequest>,
) -> AppResult<Json<ConversationResponse>> {
    let conversation = conversations::update(&state, user.user_id, id, request).await?;
    Ok(Json(conversation.into()))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    conversations::delete(&state, user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
