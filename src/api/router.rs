//! Route table and middleware stack.

use axum::http::{HeaderValue, Method};
use axum::middleware as axum_mw;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::middleware::rate_limit::{auth_rate_limit, global_rate_limit};
use crate::middleware::security_headers::{security_headers, track_metrics};
use crate::state::AppState;

use super::{auth, chat_stream, conversations, health, keys, messages};

pub fn build_router(state: AppState) -> Router {
    // Credential endpoints get a stricter rate limit on top of the global one.
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route_layer(axum_mw::from_fn_with_state(state.clone(), auth_rate_limit));

    let api_routes = Router::new()
        .merge(auth_routes)
        .route("/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route(
            "/conversations",
            get(conversations::list).post(conversations::create),
        )
        .route(
            "/conversations/{id}",
            put(conversations::update).delete(conversations::delete),
        )
        .route("/messages", get(messages::list).post(messages::create))
        .route("/messages/{id}", delete(messages::delete))
        .route("/keys", get(keys::list).post(keys::create))
        .route("/chat/stream", get(chat_stream::chat_stream));

    let cors = cors_layer(&state);

    Router::new()
        .merge(api_routes)
        .route("/health", get(health::health))
        .route("/metrics", get(health::metrics))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            global_rate_limit,
        ))
        .layer(axum_mw::from_fn(security_headers))
        .layer(axum_mw::from_fn_with_state(state.clone(), track_metrics))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(
            state.config.request_body_limit_bytes,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown");
                tracing::info_span!(
                    "request",
                    method = %request.method(),
                    uri = %request.uri().path(),
                    request_id,
                )
            },
        ))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    let allow_origin = if origins.is_empty() {
        // No configured origins: deny cross-origin browser access entirely.
        AllowOrigin::list(Vec::new())
    } else {
        AllowOrigin::list(origins)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .max_age(std::time::Duration::from_secs(3600))
}
