use serde_json::json;
use uuid::Uuid;

use crate::domain::dto::{CreateConversationRequest, UpdateConversationRequest};
use crate::domain::models::Conversation;
use crate::domain::validate;
use crate::error::{AppError, AppResult};
use crate::repositories::conversations as repo;
use crate::state::AppState;

use super::audit;

pub async fn create(
    state: &AppState,
    user_id: Uuid,
    request: CreateConversationRequest,
) -> AppResult<Conversation> {
    let title = match request.title.as_deref() {
        Some(raw) => validate::title(raw)?,
        None => "New conversation".to_string(),
    };
    let conversation = repo::insert(&state.pool, user_id, &title, request.model.as_deref()).await?;
    audit::record(
        &state.pool,
        Some(user_id),
        "conversation.created",
        json!({ "conversation_id": conversation.id }),
        None,
    )
    .await;
    Ok(conversation)
}

pub async fn list(state: &AppState, user_id: Uuid) -> AppResult<Vec<Conversation>> {
    Ok(repo::list_for_user(&state.pool, user_id).await?)
}

pub async fn update(
    state: &AppState,
    user_id: Uuid,
    id: Uuid,
    request: UpdateConversationRequest,
) -> AppResult<Conversation> {
    let title = request.title.as_deref().map(validate::title).transpose()?;
    repo::update(
        &state.pool,
        id,
        user_id,
        title.as_deref(),
        request.model.as_deref(),
    )
    .await?
    .ok_or(AppError::NotFound)
}

pub async fn delete(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<()> {
    if !repo::soft_delete(&state.pool, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &state.pool,
        Some(user_id),
        "conversation.deleted",
        json!({ "conversation_id": id }),
        None,
    )
    .await;
    Ok(())
}

/// Ensure a conversation exists and belongs to the user.
pub async fn assert_owned(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<Conversation> {
    repo::find_owned(&state.pool, id, user_id)
        .await?
        .ok_or(AppError::NotFound)
}
