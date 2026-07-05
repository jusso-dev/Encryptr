use uuid::Uuid;

use crate::crypto::aead::NONCE_LEN;
use crate::domain::dto::{CreateMessageRequest, ListMessagesQuery};
use crate::domain::models::EncryptedMessage;
use crate::domain::validate;
use crate::error::{AppError, AppResult};
use crate::repositories::{conversations as conversations_repo, messages as repo};
use crate::state::AppState;

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

/// Store a client-encrypted message. The server validates shape (base64,
/// nonce length, role) but by design cannot inspect the content.
pub async fn create(
    state: &AppState,
    user_id: Uuid,
    request: CreateMessageRequest,
) -> AppResult<EncryptedMessage> {
    super::conversations::assert_owned(state, user_id, request.conversation_id).await?;

    let role = validate::message_role(&request.role)?;
    let ciphertext = validate::base64_field(
        &request.ciphertext,
        "ciphertext",
        validate::MAX_CIPHERTEXT_BYTES,
    )?;
    let nonce = validate::base64_field(&request.nonce, "nonce", NONCE_LEN)?;
    if nonce.len() != NONCE_LEN {
        return Err(AppError::Validation(format!(
            "nonce must be exactly {NONCE_LEN} bytes"
        )));
    }
    let algorithm = request
        .algorithm
        .unwrap_or_else(|| "AES-256-GCM".to_string());

    let message = repo::insert(
        &state.pool,
        request.conversation_id,
        user_id,
        &role,
        &ciphertext,
        &nonce,
        &algorithm,
        request.key_id,
    )
    .await?;

    conversations_repo::touch(&state.pool, request.conversation_id).await?;
    Ok(message)
}

pub async fn list(
    state: &AppState,
    user_id: Uuid,
    query: ListMessagesQuery,
) -> AppResult<Vec<EncryptedMessage>> {
    super::conversations::assert_owned(state, user_id, query.conversation_id).await?;
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    Ok(repo::list_for_conversation(
        &state.pool,
        query.conversation_id,
        user_id,
        limit,
        query.before,
    )
    .await?)
}

pub async fn delete(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<()> {
    if !repo::delete_owned(&state.pool, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(())
}
