//! Minimal, dependency-free Prometheus-style metrics.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

pub struct Metrics {
    started_at: Instant,
    pub http_requests_total: AtomicU64,
    pub http_responses_2xx: AtomicU64,
    pub http_responses_4xx: AtomicU64,
    pub http_responses_5xx: AtomicU64,
    pub http_request_duration_micros_sum: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub ws_sessions_active: AtomicI64,
    pub ws_sessions_total: AtomicU64,
    pub provider_requests_total: AtomicU64,
    pub provider_chunks_total: AtomicU64,
    pub provider_errors_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            http_requests_total: AtomicU64::new(0),
            http_responses_2xx: AtomicU64::new(0),
            http_responses_4xx: AtomicU64::new(0),
            http_responses_5xx: AtomicU64::new(0),
            http_request_duration_micros_sum: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            ws_sessions_active: AtomicI64::new(0),
            ws_sessions_total: AtomicU64::new(0),
            provider_requests_total: AtomicU64::new(0),
            provider_chunks_total: AtomicU64::new(0),
            provider_errors_total: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn record_response(&self, status: u16, duration_micros: u64) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        self.http_request_duration_micros_sum
            .fetch_add(duration_micros, Ordering::Relaxed);
        match status {
            200..=299 => &self.http_responses_2xx,
            400..=499 => &self.http_responses_4xx,
            500..=599 => &self.http_responses_5xx,
            _ => return,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Render in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let uptime = self.started_at.elapsed().as_secs();
        let mut out = String::with_capacity(1024);
        let mut counter = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };
        counter(
            "encryptr_http_requests_total",
            "Total HTTP requests received",
            self.http_requests_total.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_http_responses_2xx_total",
            "HTTP responses with 2xx status",
            self.http_responses_2xx.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_http_responses_4xx_total",
            "HTTP responses with 4xx status",
            self.http_responses_4xx.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_http_responses_5xx_total",
            "HTTP responses with 5xx status",
            self.http_responses_5xx.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_http_request_duration_micros_sum",
            "Sum of HTTP request durations in microseconds",
            self.http_request_duration_micros_sum
                .load(Ordering::Relaxed),
        );
        counter(
            "encryptr_rate_limited_total",
            "Requests rejected by the rate limiter",
            self.rate_limited_total.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_ws_sessions_total",
            "Total WebSocket chat sessions",
            self.ws_sessions_total.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_provider_requests_total",
            "Requests sent to the AI provider",
            self.provider_requests_total.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_provider_chunks_total",
            "Streamed chunks received from the AI provider",
            self.provider_chunks_total.load(Ordering::Relaxed),
        );
        counter(
            "encryptr_provider_errors_total",
            "Errors from the AI provider",
            self.provider_errors_total.load(Ordering::Relaxed),
        );
        out.push_str(&format!(
            "# HELP encryptr_ws_sessions_active Currently open WebSocket chat sessions\n# TYPE encryptr_ws_sessions_active gauge\nencryptr_ws_sessions_active {}\n",
            self.ws_sessions_active.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP encryptr_uptime_seconds Process uptime in seconds\n# TYPE encryptr_uptime_seconds gauge\nencryptr_uptime_seconds {uptime}\n"
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders() {
        let metrics = Metrics::default();
        metrics.record_response(200, 1500);
        metrics.record_response(404, 300);
        metrics.record_response(500, 900);
        let text = metrics.render();
        assert!(text.contains("encryptr_http_requests_total 3"));
        assert!(text.contains("encryptr_http_responses_2xx_total 1"));
        assert!(text.contains("encryptr_http_responses_4xx_total 1"));
        assert!(text.contains("encryptr_http_responses_5xx_total 1"));
        assert!(text.contains("encryptr_http_request_duration_micros_sum 2700"));
    }
}
