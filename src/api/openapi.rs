//! Code-first OpenAPI document.
//!
//! The spec is derived from the `#[utoipa::path]` annotations on the handlers
//! and the `ToSchema` derives on the DTOs, so it cannot drift from the code.
//! `docs/openapi.yaml` / `docs/openapi.json` are generated from this by the
//! `gen-openapi` binary and checked in CI; the running server also serves the
//! live spec at `/openapi.json` with browsable docs at `/docs`.

use axum::response::{Html, IntoResponse, Json};
use serde::Serialize;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

/// The error envelope returned by every endpoint on failure. Mirrors
/// `crate::error::AppError`'s HTTP body (defined here so it can carry a
/// `ToSchema` derive without leaking into the error type).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorDetail {
    /// Stable machine-readable code, e.g. `validation_error`, `unauthorized`,
    /// `not_found`, `conflict`, `rate_limited`, `provider_error`,
    /// `internal_error`.
    pub code: String,
    /// Human-readable, safe-to-display message.
    pub message: String,
}

/// Registers the `bearerAuth` (JWT) security scheme referenced by protected
/// routes.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                Http::builder()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("JWT access token from `POST /login`."))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Encryptr Server API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Encrypted AI conversation backend. Message content is always \
                       client-side AEAD ciphertext; the server stores ciphertext, nonce, \
                       and auth tag but can never decrypt it. The `/chat/stream` WebSocket \
                       provides end-to-end encrypted streaming inference.",
        license(name = "MIT"),
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development"),
    ),
    paths(
        crate::api::auth::register,
        crate::api::auth::login,
        crate::api::auth::refresh,
        crate::api::auth::logout,
        crate::api::auth::me,
        crate::api::conversations::list,
        crate::api::conversations::create,
        crate::api::conversations::update,
        crate::api::conversations::delete,
        crate::api::messages::list,
        crate::api::messages::create,
        crate::api::messages::delete,
        crate::api::keys::list,
        crate::api::keys::create,
        crate::api::chat_stream::chat_stream,
        crate::api::health::health,
        crate::api::health::metrics,
    ),
    components(schemas(ApiError, ApiErrorDetail)),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Registration, login, token rotation, sessions"),
        (name = "conversations", description = "Conversation metadata (server-readable)"),
        (name = "messages", description = "Client-encrypted message storage"),
        (name = "keys", description = "Device public keys"),
        (name = "chat", description = "Encrypted streaming inference (WebSocket)"),
        (name = "system", description = "Health and metrics"),
    ),
)]
pub struct ApiDoc;

impl ApiDoc {
    /// The spec as pretty JSON.
    pub fn as_json() -> String {
        ApiDoc::openapi()
            .to_pretty_json()
            .expect("serialize OpenAPI to JSON")
    }

    /// The spec as YAML.
    pub fn as_yaml() -> String {
        ApiDoc::openapi()
            .to_yaml()
            .expect("serialize OpenAPI to YAML")
    }
}

/// Serve the live spec as JSON (`GET /openapi.json`).
pub async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

/// Serve a self-contained Redoc documentation page (`GET /docs`).
pub async fn docs_ui() -> Html<&'static str> {
    Html(REDOC_HTML)
}

const REDOC_HTML: &str = r#"<!DOCTYPE html>
<html>
  <head>
    <title>Encryptr Server API</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <style>body { margin: 0; padding: 0; }</style>
  </head>
  <body>
    <redoc spec-url="/openapi.json"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_builds_and_covers_all_routes() {
        let doc = ApiDoc::openapi();
        // Every mounted route should be present in the generated paths.
        for path in [
            "/register",
            "/login",
            "/refresh",
            "/logout",
            "/me",
            "/conversations",
            "/conversations/{id}",
            "/messages",
            "/messages/{id}",
            "/keys",
            "/chat/stream",
            "/health",
            "/metrics",
        ] {
            assert!(doc.paths.paths.contains_key(path), "missing path: {path}");
        }
        // Security scheme is registered.
        assert!(doc
            .components
            .as_ref()
            .unwrap()
            .security_schemes
            .contains_key("bearerAuth"));
    }

    #[test]
    fn renders_json_and_yaml() {
        assert!(ApiDoc::as_json().contains("Encryptr Server API"));
        assert!(ApiDoc::as_yaml().contains("Encryptr Server API"));
    }
}
