//! Structured audit events. Fire-and-forget: an audit failure is logged but
//! never fails the user-facing request.

use sqlx::PgPool;
use uuid::Uuid;

use crate::repositories;

pub async fn record(
    pool: &PgPool,
    user_id: Option<Uuid>,
    event_type: &'static str,
    metadata: serde_json::Value,
    ip_address: Option<&str>,
) {
    if let Err(error) =
        repositories::audit::insert(pool, user_id, event_type, metadata, ip_address).await
    {
        tracing::warn!(%event_type, ?error, "failed to record audit event");
    }
}
