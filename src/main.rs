use std::net::SocketAddr;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use encryptr_server::providers::build_provider;
use encryptr_server::{build_router, AppState, Config, MIGRATOR};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env().context("failed to load configuration")?;
    init_tracing(&config);

    tracing::info!(
        environment = ?config.environment,
        bind_addr = %config.bind_addr,
        "starting encryptr-server"
    );

    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&config.database_url)
        .await
        .context("failed to connect to PostgreSQL")?;

    MIGRATOR
        .run(&pool)
        .await
        .context("failed to run database migrations")?;
    tracing::info!("database migrations applied");

    let provider = build_provider(&config);
    tracing::info!(provider = provider.name(), "AI provider configured");

    let bind_addr: SocketAddr = config
        .bind_addr
        .parse()
        .context("BIND_ADDR must be host:port")?;
    let tls = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
        _ => None,
    };

    let state = AppState::new(pool, config, provider);

    // Periodically evict expired rate-limit windows.
    {
        let general = state.rate_limiter.clone();
        let auth = state.auth_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                general.sweep();
                auth.sweep();
            }
        });
    }

    let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some((cert, key)) => {
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .context("failed to load TLS certificate/key")?;
            tracing::info!(%bind_addr, "listening with TLS (rustls)");
            let handle = axum_server::Handle::new();
            tokio::spawn(shutdown_signal(handle.clone()));
            axum_server::bind_rustls(bind_addr, tls_config)
                .handle(handle)
                .serve(app)
                .await
                .context("server error")?;
        }
        None => {
            tracing::info!(%bind_addr, "listening (plaintext; terminate TLS upstream)");
            let listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .context("failed to bind listener")?;
            axum::serve(listener, app)
                .with_graceful_shutdown(wait_for_shutdown())
                .await
                .context("server error")?;
        }
    }

    tracing::info!("shutdown complete");
    Ok(())
}

fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info"));
    if config.log_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install ctrl-c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}

async fn shutdown_signal(handle: axum_server::Handle) {
    wait_for_shutdown().await;
    handle.graceful_shutdown(Some(std::time::Duration::from_secs(20)));
}
