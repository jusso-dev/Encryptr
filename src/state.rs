//! Shared application state.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::crypto::jwt::JwtService;
use crate::middleware::metrics::Metrics;
use crate::middleware::rate_limit::RateLimiter;
use crate::providers::ChatProvider;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub jwt: Arc<JwtService>,
    pub provider: Arc<dyn ChatProvider>,
    pub rate_limiter: Arc<RateLimiter>,
    pub auth_rate_limiter: Arc<RateLimiter>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config, provider: Arc<dyn ChatProvider>) -> Self {
        let jwt = Arc::new(JwtService::new(
            config.jwt_secret.as_bytes(),
            config.access_token_ttl,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_requests,
            config.rate_limit_window,
        ));
        let auth_rate_limiter = Arc::new(RateLimiter::new(
            config.auth_rate_limit_requests,
            config.rate_limit_window,
        ));
        Self {
            pool,
            config: Arc::new(config),
            jwt,
            provider,
            rate_limiter,
            auth_rate_limiter,
            metrics: Arc::new(Metrics::default()),
        }
    }
}
