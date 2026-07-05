//! Encryptr Server — encrypted AI conversation backend.
//!
//! Layering (each module independently testable):
//!
//! ```text
//! api (HTTP/WS) → middleware → services → repositories → database
//!                                    ↘ providers (LLMs)
//!                                    ↘ crypto
//! ```

pub mod api;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod middleware;
pub mod providers;
pub mod repositories;
pub mod services;
pub mod state;

pub use api::router::build_router;
pub use config::Config;
pub use state::AppState;

/// Embedded database migrations, applied on startup.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
