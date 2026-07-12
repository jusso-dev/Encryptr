use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::domain::dto::{CreateMessageRequest, ListMessagesQuery, MessageResponse};
use crate::error::AppResult;
use crate::middleware::auth::AuthUser;
use crate::services::messages;
use crate::state::AppState;

/// List messages in a conversation (newest first, paginated).
#[utoipa::path(
    get, path = "/messages", tag = "messages", operation_id = "list_messages",
    security(("bearerAuth" = [])),
    params(ListMessagesQuery),
    responses(
        (status = 200, description = "Messages", body = Vec<MessageResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
        (status = 404, description = "Conversation not found", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListMessagesQuery>,
) -> AppResult<Json<Vec<MessageResponse>>> {
    let items = messages::list(&state, user.user_id, query).await?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

/// Store a client-encrypted message. The server never sees plaintext.
#[utoipa::path(
    post, path = "/messages", tag = "messages", operation_id = "create_message",
    security(("bearerAuth" = [])),
    request_body = CreateMessageRequest,
    responses(
        (status = 201, description = "Stored", body = MessageResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ApiError),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
        (status = 404, description = "Conversation not found", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateMessageRequest>,
) -> AppResult<(StatusCode, Json<MessageResponse>)> {
    let message = messages::create(&state, user.user_id, request).await?;
    Ok((StatusCode::CREATED, Json(message.into())))
}

/// Delete one of the caller's messages.
#[utoipa::path(
    delete, path = "/messages/{id}", tag = "messages", operation_id = "delete_message",
    security(("bearerAuth" = [])),
    params(("id" = Uuid, Path, description = "Message id")),
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
    messages::delete(&state, user.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
