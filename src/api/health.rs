use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::domain::dto::HealthResponse;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Liveness/readiness probe including a database round-trip.
#[utoipa::path(
    get, path = "/health", tag = "system",
    security(),
    responses(
        (status = 200, description = "Healthy", body = HealthResponse),
        (status = 503, description = "Database unavailable", body = HealthResponse),
    ),
)]
pub async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let (status, database) = if db_ok {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    (
        status,
        Json(HealthResponse {
            status: if db_ok { "ok" } else { "degraded" },
            version: env!("CARGO_PKG_VERSION"),
            database,
        }),
    )
}

/// Operational metrics. Requires authentication: the counters expose internal
/// volumes (sessions, provider/error totals) that should not be public. Scrape
/// with a service account's bearer token, or expose via an internal-only proxy.
#[utoipa::path(
    get, path = "/metrics", tag = "system",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Prometheus text exposition", content_type = "text/plain"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn metrics(
    _auth: AuthUser,
    State(state): State<AppState>,
) -> ([(&'static str, &'static str); 1], String) {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(),
    )
}
