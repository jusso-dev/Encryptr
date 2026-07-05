use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::PublicKeyRecord;

const COLUMNS: &str =
    "id, user_id, ed25519_public_key, x25519_public_key, label, created_at, revoked_at";

pub async fn insert(
    pool: &PgPool,
    user_id: Uuid,
    ed25519_public_key: &[u8],
    x25519_public_key: &[u8],
    label: &str,
) -> Result<PublicKeyRecord, sqlx::Error> {
    sqlx::query_as::<_, PublicKeyRecord>(&format!(
        "INSERT INTO public_keys (user_id, ed25519_public_key, x25519_public_key, label)
         VALUES ($1, $2, $3, $4)
         RETURNING {COLUMNS}"
    ))
    .bind(user_id)
    .bind(ed25519_public_key)
    .bind(x25519_public_key)
    .bind(label)
    .fetch_one(pool)
    .await
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<PublicKeyRecord>, sqlx::Error> {
    sqlx::query_as::<_, PublicKeyRecord>(&format!(
        "SELECT {COLUMNS} FROM public_keys
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY created_at ASC"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
}
