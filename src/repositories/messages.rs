use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::EncryptedMessage;

const COLUMNS: &str =
    "id, conversation_id, user_id, role, ciphertext, nonce, algorithm, key_id, created_at";

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &PgPool,
    conversation_id: Uuid,
    user_id: Uuid,
    role: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    algorithm: &str,
    key_id: Option<Uuid>,
) -> Result<EncryptedMessage, sqlx::Error> {
    sqlx::query_as::<_, EncryptedMessage>(&format!(
        "INSERT INTO encrypted_messages
             (conversation_id, user_id, role, ciphertext, nonce, algorithm, key_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING {COLUMNS}"
    ))
    .bind(conversation_id)
    .bind(user_id)
    .bind(role)
    .bind(ciphertext)
    .bind(nonce)
    .bind(algorithm)
    .bind(key_id)
    .fetch_one(pool)
    .await
}

pub async fn list_for_conversation(
    pool: &PgPool,
    conversation_id: Uuid,
    user_id: Uuid,
    limit: i64,
    before: Option<DateTime<Utc>>,
) -> Result<Vec<EncryptedMessage>, sqlx::Error> {
    sqlx::query_as::<_, EncryptedMessage>(&format!(
        "SELECT {COLUMNS} FROM encrypted_messages
         WHERE conversation_id = $1
           AND user_id = $2
           AND ($3::timestamptz IS NULL OR created_at < $3)
         ORDER BY created_at DESC
         LIMIT $4"
    ))
    .bind(conversation_id)
    .bind(user_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn delete_owned(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM encrypted_messages WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
