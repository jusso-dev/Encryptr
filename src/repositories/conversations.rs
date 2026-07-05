use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::Conversation;

const COLUMNS: &str = "id, user_id, title, model, created_at, updated_at, deleted_at";

pub async fn insert(
    pool: &PgPool,
    user_id: Uuid,
    title: &str,
    model: Option<&str>,
) -> Result<Conversation, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(&format!(
        "INSERT INTO conversations (user_id, title, model)
         VALUES ($1, $2, $3)
         RETURNING {COLUMNS}"
    ))
    .bind(user_id)
    .bind(title)
    .bind(model)
    .fetch_one(pool)
    .await
}

pub async fn list_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Conversation>, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(&format!(
        "SELECT {COLUMNS} FROM conversations
         WHERE user_id = $1 AND deleted_at IS NULL
         ORDER BY updated_at DESC"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn find_owned(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<Conversation>, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(&format!(
        "SELECT {COLUMNS} FROM conversations
         WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
    title: Option<&str>,
    model: Option<&str>,
) -> Result<Option<Conversation>, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(&format!(
        "UPDATE conversations
         SET title = COALESCE($3, title),
             model = COALESCE($4, model),
             updated_at = now()
         WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(user_id)
    .bind(title)
    .bind(model)
    .fetch_optional(pool)
    .await
}

/// Soft delete; encrypted messages remain until a retention job purges them.
pub async fn soft_delete(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE conversations SET deleted_at = now()
         WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE conversations SET updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
