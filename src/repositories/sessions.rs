//! Sessions and refresh tokens (they rotate together).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::{RefreshToken, Session};

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<Session, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        r#"
        INSERT INTO sessions (user_id, user_agent, ip_address)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, user_agent, ip_address, created_at, revoked_at
        "#,
    )
    .bind(user_id)
    .bind(user_agent)
    .bind(ip_address)
    .fetch_one(pool)
    .await
}

/// Returns true when the session exists and has not been revoked.
pub async fn is_active(pool: &PgPool, session_id: Uuid) -> Result<bool, sqlx::Error> {
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM sessions WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

pub async fn revoke_session(pool: &PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now()
         WHERE session_id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

pub async fn insert_refresh_token(
    pool: &PgPool,
    session_id: Uuid,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<RefreshToken, sqlx::Error> {
    sqlx::query_as::<_, RefreshToken>(
        r#"
        INSERT INTO refresh_tokens (session_id, user_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, session_id, user_id, token_hash, expires_at, created_at,
                  rotated_at, revoked_at
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn find_refresh_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshToken>, sqlx::Error> {
    sqlx::query_as::<_, RefreshToken>(
        "SELECT id, session_id, user_id, token_hash, expires_at, created_at,
                rotated_at, revoked_at
         FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Mark a token as rotated (single-use exchange during refresh).
pub async fn mark_rotated(pool: &PgPool, token_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(pool)
        .await?;
    Ok(())
}
