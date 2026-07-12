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

/// List the caller's conversations.
#[utoipa::path(
    get, path = "/conversations", tag = "conversations",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Conversations", body = Vec<ConversationResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ConversationResponse>>> {
    let items = conversations::list(&state, user.user_id).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

/// Create a conversation.
#[utoipa::path(
    post, path = "/conversations", tag = "conversations",
    security(("bearerAuth" = [])),
    request_body = CreateConversationRequest,
    responses(
        (status = 201, description = "Created", body = ConversationResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateConversationRequest>,
) -> AppResult<(StatusCode, Json<ConversationResponse>)> {
    let conversation = conversations::create(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(conversation.into())))
}

/// Update a conversation's title or model.
#[utoipa::path(
    put, path = "/conversations/{id}", tag = "conversations",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Conversation id")),
    request_body = UpdateConversationRequest,
    responses(
        (status = 200, description = "Updated", body = ConversationResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
        (status = 404, description = "Not found", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateConversationRequest>,
) -> AppResult<Json<ConversationResponse>> {
    let conversation = conversations::update(&state, user.user_id, id, request).await?;
    Ok(Json(conversation.into()))
}

/// Soft-delete a conversation.
#[utoipa::path(
    delete, path = "/conversations/{id}", tag = "conversations",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Conversation id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
        (status = 404, description = "Not found", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<StatusCode> {
    conversations::delete(&state, user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
