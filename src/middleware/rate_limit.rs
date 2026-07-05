//! Fixed-window, per-client rate limiting.
//!
//! In-memory and per-instance by design; put a shared limiter (or a
//! rate-limiting proxy) in front when running multiple replicas.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;

use crate::error::AppError;
use crate::state::AppState;

pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    windows: DashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            windows: DashMap::new(),
        }
    }

    /// Record a hit for `key`; returns false when the client is over budget.
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> bool {
        let mut entry = self.windows.entry(key.to_string()).or_insert((now, 0));
        let (window_start, count) = *entry;
        if now.duration_since(window_start) >= self.window {
            *entry = (now, 1);
            return true;
        }
        if count >= self.max_requests {
            return false;
        }
        *entry = (window_start, count + 1);
        true
    }

    /// Drop windows that have expired; called opportunistically.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.windows
            .retain(|_, (start, _)| now.duration_since(*start) < self.window);
    }
}

/// Middleware applying the general limiter to every request.
pub async fn global_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    enforce(&state, &state.rate_limiter.clone(), addr, request, next).await
}

/// Stricter limiter for credential endpoints (login/register/refresh).
pub async fn auth_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    enforce(
        &state,
        &state.auth_rate_limiter.clone(),
        addr,
        request,
        next,
    )
    .await
}

async fn enforce(
    state: &AppState,
    limiter: &Arc<RateLimiter>,
    addr: SocketAddr,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let key = client_key(&request, addr);
    if !limiter.check(&key) {
        state
            .metrics
            .rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError::RateLimited);
    }
    Ok(next.run(request).await)
}

/// Prefer the leftmost X-Forwarded-For hop (set by our own proxy) and fall
/// back to the socket address.
fn client_key(request: &Request, addr: SocketAddr) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(!limiter.check("1.2.3.4"));
    }

    #[test]
    fn separate_keys_have_separate_budgets() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"));
        assert!(limiter.check("b"));
    }

    #[test]
    fn window_resets() {
        let limiter = RateLimiter::new(1, Duration::from_millis(10));
        let start = Instant::now();
        assert!(limiter.check_at("a", start));
        assert!(!limiter.check_at("a", start));
        assert!(limiter.check_at("a", start + Duration::from_millis(11)));
    }

    #[test]
    fn sweep_removes_expired_windows() {
        let limiter = RateLimiter::new(1, Duration::from_millis(1));
        limiter.check("a");
        std::thread::sleep(Duration::from_millis(5));
        limiter.sweep();
        assert!(limiter.windows.is_empty());
    }
}
