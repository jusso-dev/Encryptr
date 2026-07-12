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

/// Upper bound on distinct keys tracked at once. Bounds memory against a flood
/// of distinct client identities (e.g. many source IPs); once reached, a sweep
/// of expired windows runs before admitting a new key, and if that does not
/// free space the new client is rejected rather than growing the map without
/// limit.
const MAX_TRACKED_KEYS: usize = 100_000;

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
        // Bound memory: if the map is full and this is a new key, try a sweep,
        // then refuse rather than allocate an unbounded number of entries.
        if !self.windows.contains_key(key) && self.windows.len() >= MAX_TRACKED_KEYS {
            self.sweep();
            if self.windows.len() >= MAX_TRACKED_KEYS {
                return false;
            }
        }
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
    let key = client_key(&request, addr, state.config.trust_proxy_headers);
    if !limiter.check(&key) {
        state
            .metrics
            .rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError::RateLimited);
    }
    Ok(next.run(request).await)
}

/// Derive the client identity used for rate limiting.
///
/// `X-Forwarded-For`/`X-Real-IP` are attacker-controlled unless a trusted proxy
/// overwrites them, so they are honored ONLY when `trust_proxy_headers` is set
/// (see `Config::trust_proxy_headers`). When trusted, the *rightmost* forwarded
/// hop is used — that is the address the trusted proxy actually saw, and it
/// cannot be forged by prepending fake entries. Otherwise the unspoofable
/// socket peer address is used.
fn client_key(request: &Request, addr: SocketAddr, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        if let Some(ip) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next_back())
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
        {
            return ip;
        }
        if let Some(ip) = request
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
        {
            return ip;
        }
    }
    addr.ip().to_string()
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

    fn request_with_xff(value: &str) -> Request {
        Request::builder()
            .header("x-forwarded-for", value)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn ignores_forwarded_header_when_untrusted() {
        let addr: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let req = request_with_xff("1.1.1.1, 2.2.2.2");
        // Untrusted: spoofed header is ignored, socket IP wins.
        assert_eq!(client_key(&req, addr, false), "203.0.113.9");
    }

    #[test]
    fn uses_rightmost_forwarded_hop_when_trusted() {
        let addr: SocketAddr = "10.0.0.1:5555".parse().unwrap();
        let req = request_with_xff("1.1.1.1, 2.2.2.2");
        // Trusted proxy appends the real client; rightmost is what it saw.
        assert_eq!(client_key(&req, addr, true), "2.2.2.2");
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
