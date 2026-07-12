//! Environment-variable driven configuration.
//!
//! Every setting comes from the process environment so the same binary runs
//! unchanged across development, testing, production, and Docker.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Testing,
    Production,
}

impl Environment {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "testing" | "test" => Ok(Self::Testing),
            "production" | "prod" => Ok(Self::Production),
            other => bail!("unknown ENVIRONMENT value: {other}"),
        }
    }

    pub fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    OpenAi,
    Anthropic,
    Ollama,
}

impl ProviderKind {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "openai" => Ok(Self::OpenAi),
            "anthropic" => Ok(Self::Anthropic),
            "ollama" => Ok(Self::Ollama),
            other => bail!("unknown PROVIDER value: {other} (expected openai|anthropic|ollama)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: Environment,
    pub bind_addr: String,
    pub database_url: String,
    pub database_max_connections: u32,

    pub jwt_secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,

    pub provider: ProviderKind,
    pub provider_default_model: String,
    pub openai_api_key: Option<String>,
    pub openai_base_url: String,
    pub anthropic_api_key: Option<String>,
    pub anthropic_base_url: String,
    pub ollama_base_url: String,

    pub rate_limit_requests: u32,
    pub rate_limit_window: Duration,
    pub auth_rate_limit_requests: u32,

    pub cors_allowed_origins: Vec<String>,
    pub request_body_limit_bytes: usize,
    /// Honor `X-Forwarded-For`/`X-Real-IP` for the client identity only when
    /// set. Leave false unless a trusted reverse proxy sits in front and
    /// overwrites the header — otherwise clients spoof it to defeat rate
    /// limiting.
    pub trust_proxy_headers: bool,
    /// Overall per-request timeout applied to non-streaming endpoints.
    pub request_timeout: Duration,

    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,

    pub log_json: bool,
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&vars)
    }

    /// Load configuration from an explicit map (used by tests).
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self> {
        let get = |key: &str| {
            vars.get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let get_or = |key: &str, default: &str| get(key).unwrap_or_else(|| default.to_string());

        let environment = Environment::parse(&get_or("ENVIRONMENT", "development"))?;

        let database_url = get("DATABASE_URL").context("DATABASE_URL is required")?;

        let jwt_secret = get("JWT_SECRET").context("JWT_SECRET is required")?;
        if jwt_secret.len() < 32 {
            bail!("JWT_SECRET must be at least 32 bytes");
        }
        // Known placeholders (e.g. the one shipped in `.env.example`) are public
        // and would let anyone forge access tokens. Never allow them in prod.
        const WEAK_SECRETS: &[&str] = &[
            "change-me-to-a-long-random-secret-value-please",
            "changeme",
            "secret",
        ];
        if environment.is_production() && WEAK_SECRETS.iter().any(|weak| jwt_secret.contains(weak))
        {
            bail!(
                "JWT_SECRET is a known placeholder value; set a strong random secret in production"
            );
        }

        let provider = ProviderKind::parse(&get_or("PROVIDER", "ollama"))?;
        let openai_api_key = get("OPENAI_API_KEY");
        let anthropic_api_key = get("ANTHROPIC_API_KEY");
        match provider {
            ProviderKind::OpenAi if openai_api_key.is_none() => {
                bail!("OPENAI_API_KEY is required when PROVIDER=openai")
            }
            ProviderKind::Anthropic if anthropic_api_key.is_none() => {
                bail!("ANTHROPIC_API_KEY is required when PROVIDER=anthropic")
            }
            _ => {}
        }

        let parse_u64 = |key: &str, default: u64| -> Result<u64> {
            match get(key) {
                Some(v) => v
                    .parse::<u64>()
                    .with_context(|| format!("{key} must be an integer")),
                None => Ok(default),
            }
        };
        // Parse directly into the target width so oversized values are rejected
        // rather than silently truncated by an `as` cast.
        let parse_u32 = |key: &str, default: u32| -> Result<u32> {
            match get(key) {
                Some(v) => v
                    .parse::<u32>()
                    .with_context(|| format!("{key} must be a 32-bit integer")),
                None => Ok(default),
            }
        };
        let parse_usize = |key: &str, default: usize| -> Result<usize> {
            match get(key) {
                Some(v) => v
                    .parse::<usize>()
                    .with_context(|| format!("{key} must be a non-negative integer")),
                None => Ok(default),
            }
        };
        let parse_bool = |key: &str, default: bool| -> bool {
            get(key)
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(default)
        };

        let tls_cert_path = get("TLS_CERT_PATH");
        let tls_key_path = get("TLS_KEY_PATH");
        if tls_cert_path.is_some() != tls_key_path.is_some() {
            bail!("TLS_CERT_PATH and TLS_KEY_PATH must be set together");
        }

        let cors_allowed_origins = get_or("CORS_ALLOWED_ORIGINS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let default_model = match provider {
            ProviderKind::OpenAi => "gpt-4o-mini",
            ProviderKind::Anthropic => "claude-sonnet-5",
            ProviderKind::Ollama => "llama3.2",
        };

        Ok(Self {
            environment,
            bind_addr: get_or("BIND_ADDR", "0.0.0.0:8080"),
            database_url,
            database_max_connections: parse_u32("DATABASE_MAX_CONNECTIONS", 10)?,
            jwt_secret,
            access_token_ttl: Duration::from_secs(parse_u64("ACCESS_TOKEN_TTL_SECS", 900)?),
            refresh_token_ttl: Duration::from_secs(parse_u64(
                "REFRESH_TOKEN_TTL_SECS",
                30 * 24 * 3600,
            )?),
            provider,
            provider_default_model: get_or("PROVIDER_DEFAULT_MODEL", default_model),
            openai_api_key,
            openai_base_url: get_or("OPENAI_BASE_URL", "https://api.openai.com"),
            anthropic_api_key,
            anthropic_base_url: get_or("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
            ollama_base_url: get_or("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            rate_limit_requests: parse_u32("RATE_LIMIT_REQUESTS", 120)?,
            rate_limit_window: Duration::from_secs(parse_u64("RATE_LIMIT_WINDOW_SECS", 60)?),
            auth_rate_limit_requests: parse_u32("AUTH_RATE_LIMIT_REQUESTS", 10)?,
            cors_allowed_origins,
            request_body_limit_bytes: parse_usize("REQUEST_BODY_LIMIT_BYTES", 1024 * 1024)?,
            trust_proxy_headers: parse_bool("TRUST_PROXY_HEADERS", false),
            request_timeout: Duration::from_secs(parse_u64("REQUEST_TIMEOUT_SECS", 30)?),
            tls_cert_path,
            tls_key_path,
            log_json: get_or(
                "LOG_JSON",
                if environment.is_production() {
                    "true"
                } else {
                    "false"
                },
            ) == "true",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_vars() -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert(
            "DATABASE_URL".into(),
            "postgres://encryptr:encryptr@localhost/encryptr".into(),
        );
        vars.insert(
            "JWT_SECRET".into(),
            "0123456789abcdef0123456789abcdef".into(),
        );
        vars
    }

    #[test]
    fn loads_defaults() {
        let config = Config::from_map(&base_vars()).unwrap();
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.provider, ProviderKind::Ollama);
        assert_eq!(config.access_token_ttl, Duration::from_secs(900));
        assert!(!config.log_json);
    }

    #[test]
    fn requires_database_url() {
        let mut vars = base_vars();
        vars.remove("DATABASE_URL");
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let mut vars = base_vars();
        vars.insert("JWT_SECRET".into(), "short".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn openai_requires_api_key() {
        let mut vars = base_vars();
        vars.insert("PROVIDER".into(), "openai".into());
        assert!(Config::from_map(&vars).is_err());
        vars.insert("OPENAI_API_KEY".into(), "sk-test".into());
        let config = Config::from_map(&vars).unwrap();
        assert_eq!(config.provider, ProviderKind::OpenAi);
    }

    #[test]
    fn tls_paths_must_be_paired() {
        let mut vars = base_vars();
        vars.insert("TLS_CERT_PATH".into(), "/certs/cert.pem".into());
        assert!(Config::from_map(&vars).is_err());
        vars.insert("TLS_KEY_PATH".into(), "/certs/key.pem".into());
        assert!(Config::from_map(&vars).is_ok());
    }

    #[test]
    fn production_rejects_placeholder_jwt_secret() {
        let mut vars = base_vars();
        vars.insert("ENVIRONMENT".into(), "production".into());
        vars.insert(
            "JWT_SECRET".into(),
            "change-me-to-a-long-random-secret-value-please".into(),
        );
        assert!(Config::from_map(&vars).is_err());
        // A strong secret of the same length is accepted.
        vars.insert(
            "JWT_SECRET".into(),
            "F7kQ2pVm9zX1aL4nR8sT0wJ6cB3dH5gK".into(),
        );
        assert!(Config::from_map(&vars).is_ok());
    }

    #[test]
    fn rejects_non_integer_numeric_config() {
        let mut vars = base_vars();
        vars.insert("RATE_LIMIT_REQUESTS".into(), "not-a-number".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn production_defaults_to_json_logs() {
        let mut vars = base_vars();
        vars.insert("ENVIRONMENT".into(), "production".into());
        let config = Config::from_map(&vars).unwrap();
        assert!(config.log_json);
    }
}
