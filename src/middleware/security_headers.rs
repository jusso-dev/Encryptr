//! Security response headers and the request metrics recorder.

use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// Add defense-in-depth headers to every response.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    let set = |headers: &mut axum::http::HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    };
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    set(headers, "cache-control", "no-store");
    response
}

/// Record request counts and latency into the metrics registry.
pub async fn track_metrics(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    state
        .metrics
        .record_response(response.status().as_u16(), elapsed);
    response
}
