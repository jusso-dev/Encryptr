use serde_json::json;
use uuid::Uuid;

use crate::crypto::keys as crypto_keys;
use crate::domain::dto::CreateKeyRequest;
use crate::domain::models::PublicKeyRecord;
use crate::domain::validate;
use crate::error::{AppError, AppResult};
use crate::repositories::keys as repo;
use crate::state::AppState;

use super::audit;

pub async fn upload(
    state: &AppState,
    user_id: Uuid,
    request: CreateKeyRequest,
) -> AppResult<PublicKeyRecord> {
    let ed25519_bytes = validate::base64_field(
        &request.ed25519_public_key,
        "ed25519_public_key",
        crypto_keys::PUBLIC_KEY_LEN,
    )?;
    let x25519_bytes = validate::base64_field(
        &request.x25519_public_key,
        "x25519_public_key",
        crypto_keys::PUBLIC_KEY_LEN,
    )?;

    let ed25519 = crypto_keys::validate_ed25519_public_key(&ed25519_bytes)
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let x25519 = crypto_keys::validate_x25519_public_key(&x25519_bytes)
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let label = match request.label.as_deref() {
        Some(raw) => validate::label(raw)?,
        None => "default".to_string(),
    };

    let record = repo::insert(&state.pool, user_id, &ed25519, &x25519, &label)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict(format!("a key with label '{label}' already exists"))
            }
            _ => AppError::Database(e),
        })?;

    audit::record(
        &state.pool,
        Some(user_id),
        "key.uploaded",
        json!({ "key_id": record.id, "label": record.label }),
        None,
    )
    .await;

    Ok(record)
}

pub async fn list(state: &AppState, user_id: Uuid) -> AppResult<Vec<PublicKeyRecord>> {
    Ok(repo::list_for_user(&state.pool, user_id).await?)
}
