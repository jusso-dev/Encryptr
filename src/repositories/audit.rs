use sqlx::PgPool;
use uuid::Uuid;

/// Insert a structured audit event. Metadata must never contain prompts,
/// responses, or secrets — callers pass identifiers and outcomes only.
pub async fn insert(
    pool: &PgPool,
    user_id: Option<Uuid>,
    event_type: &str,
    metadata: serde_json::Value,
    ip_address: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (user_id, event_type, metadata, ip_address)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(event_type)
    .bind(metadata)
    .bind(ip_address)
    .execute(pool)
    .await?;
    Ok(())
}
