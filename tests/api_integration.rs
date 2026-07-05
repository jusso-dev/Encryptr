//! End-to-end API tests against a real PostgreSQL database.
//!
//! These run when `TEST_DATABASE_URL` is set (CI provides a postgres service;
//! locally: `docker compose up -d postgres` and
//! `export TEST_DATABASE_URL=postgres://encryptr:encryptr@localhost:5432/encryptr`).
//! Without it, each test exits early as a no-op so `cargo test` stays green.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use encryptr_server::config::Config;
use encryptr_server::crypto::stream_session::StreamSession;
use encryptr_server::providers::{
    ChatProvider, ChatRequest, EventStream, ProviderError, StreamEvent,
};
use encryptr_server::{build_router, AppState, MIGRATOR};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Deterministic provider so streaming tests need no network or API keys.
struct MockProvider;

#[async_trait]
impl ChatProvider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn stream_chat(&self, _request: ChatRequest) -> Result<EventStream, ProviderError> {
        let events = vec![
            Ok(StreamEvent::Delta("Hello".to_string())),
            Ok(StreamEvent::Delta(", world".to_string())),
            Ok(StreamEvent::Done),
        ];
        Ok(Box::pin(futures::stream::iter(events)))
    }
}

/// Spin up the full app on an ephemeral port. Returns None (skip) when no
/// test database is configured.
async fn spawn_app() -> Option<String> {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping integration test");
        return None;
    };

    let mut vars = std::collections::HashMap::new();
    vars.insert("DATABASE_URL".to_string(), database_url.clone());
    vars.insert(
        "JWT_SECRET".to_string(),
        "integration-test-secret-0123456789abcdef".to_string(),
    );
    vars.insert("ENVIRONMENT".to_string(), "testing".to_string());
    // Generous limits so parallel tests don't trip the auth limiter.
    vars.insert("RATE_LIMIT_REQUESTS".to_string(), "10000".to_string());
    vars.insert("AUTH_RATE_LIMIT_REQUESTS".to_string(), "10000".to_string());
    let config = Config::from_map(&vars).expect("test config");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let state = AppState::new(pool, config, Arc::new(MockProvider));
    let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Some(format!("http://{addr}"))
}

fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.com", uuid::Uuid::new_v4())
}

async fn register_and_login(base: &str, client: &reqwest::Client) -> (String, String) {
    let email = unique_email("user");
    let password = "a-strong-password-123";

    let response = client
        .post(format!("{base}/register"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let response = client
        .post(format!("{base}/login"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn health_endpoint_reports_ok() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let body: Value = reqwest::get(format!("{base}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["database"], "ok");
}

#[tokio::test]
async fn register_login_me_flow() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let email = unique_email("flow");
    let password = "a-strong-password-123";

    // Weak password rejected.
    let response = client
        .post(format!("{base}/register"))
        .json(&json!({ "email": email, "password": "short" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // Register, then duplicate registration conflicts.
    let response = client
        .post(format!("{base}/register"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let response = client
        .post(format!("{base}/register"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);

    // Wrong password rejected.
    let response = client
        .post(format!("{base}/login"))
        .json(&json!({ "email": email, "password": "wrong-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // Correct login → /me works.
    let response = client
        .post(format!("{base}/login"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let tokens: Value = response.json().await.unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(tokens["token_type"], "Bearer");

    let me: Value = client
        .get(format!("{base}/me"))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["email"], email);

    // No token → 401.
    let response = client.get(format!("{base}/me")).send().await.unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let (_access, refresh) = register_and_login(&base, &client).await;

    // First refresh succeeds and rotates.
    let response = client
        .post(format!("{base}/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let rotated: Value = response.json().await.unwrap();
    let new_refresh = rotated["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, refresh);

    // Reusing the consumed token is treated as theft → 401 and the session
    // is revoked, killing the rotated token too.
    let response = client
        .post(format!("{base}/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let response = client
        .post(format!("{base}/refresh"))
        .json(&json!({ "refresh_token": new_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn logout_revokes_session() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let (access, _refresh) = register_and_login(&base, &client).await;

    let response = client
        .post(format!("{base}/logout"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    // The access token is now dead even though its JWT hasn't expired.
    let response = client
        .get(format!("{base}/me"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn conversation_and_message_crud() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let (access, _) = register_and_login(&base, &client).await;

    // Create a conversation.
    let conversation: Value = client
        .post(format!("{base}/conversations"))
        .bearer_auth(&access)
        .json(&json!({ "title": "Project ideas" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conversation_id = conversation["id"].as_str().unwrap().to_string();

    // Store a client-encrypted message (opaque bytes to the server).
    let ciphertext = B64.encode(b"pretend-this-is-aead-ciphertext-with-tag");
    let nonce = B64.encode([7u8; 12]);
    let response = client
        .post(format!("{base}/messages"))
        .bearer_auth(&access)
        .json(&json!({
            "conversation_id": conversation_id,
            "role": "user",
            "ciphertext": ciphertext,
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let message: Value = response.json().await.unwrap();
    assert_eq!(message["ciphertext"], ciphertext);

    // Bad nonce length is rejected.
    let response = client
        .post(format!("{base}/messages"))
        .bearer_auth(&access)
        .json(&json!({
            "conversation_id": conversation_id,
            "role": "user",
            "ciphertext": ciphertext,
            "nonce": B64.encode([1u8; 4]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // List messages.
    let messages: Value = client
        .get(format!("{base}/messages?conversation_id={conversation_id}"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.as_array().unwrap().len(), 1);

    // Another user cannot see or write into this conversation.
    let (other_access, _) = register_and_login(&base, &client).await;
    let response = client
        .get(format!("{base}/messages?conversation_id={conversation_id}"))
        .bearer_auth(&other_access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    // Rename, then delete the conversation.
    let renamed: Value = client
        .put(format!("{base}/conversations/{conversation_id}"))
        .bearer_auth(&access)
        .json(&json!({ "title": "Renamed" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(renamed["title"], "Renamed");

    let response = client
        .delete(format!("{base}/conversations/{conversation_id}"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let conversations: Value = client
        .get(format!("{base}/conversations"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(conversations.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn public_key_upload_and_validation() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let (access, _) = register_and_login(&base, &client).await;

    let signing = ed25519_dalek_test_key();
    let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

    let response = client
        .post(format!("{base}/keys"))
        .bearer_auth(&access)
        .json(&json!({
            "ed25519_public_key": B64.encode(signing),
            "x25519_public_key": B64.encode(x25519_public.as_bytes()),
            "label": "laptop",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Garbage keys are rejected.
    let response = client
        .post(format!("{base}/keys"))
        .bearer_auth(&access)
        .json(&json!({
            "ed25519_public_key": B64.encode([0u8; 32]),
            "x25519_public_key": B64.encode([0u8; 32]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let keys: Value = client
        .get(format!("{base}/keys"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(keys.as_array().unwrap().len(), 1);
    assert_eq!(keys[0]["label"], "laptop");
}

fn ed25519_dalek_test_key() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
}

/// Full encrypted streaming round trip over the real WebSocket endpoint:
/// handshake, encrypted prompt up, encrypted chunks down, plaintext verified
/// client-side only.
#[tokio::test]
async fn websocket_encrypted_streaming() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let client = reqwest::Client::new();
    let (access, _) = register_and_login(&base, &client).await;

    let ws_url = format!(
        "{}/chat/stream?token={access}",
        base.replace("http://", "ws://")
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("websocket connect");

    // 1. server_hello
    let hello: Value = next_json(&mut socket).await;
    assert_eq!(hello["type"], "server_hello");
    let server_public = B64.decode(hello["public_key"].as_str().unwrap()).unwrap();

    // 2. client_hello + key agreement
    let client_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);
    socket
        .send(WsMessage::Text(
            json!({ "type": "client_hello", "public_key": B64.encode(client_public.as_bytes()) })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let mut session =
        StreamSession::client_side(client_secret, &client_public, &server_public).unwrap();

    // 3. encrypted prompt
    let prompt = json!({ "messages": [{ "role": "user", "content": "Say hello" }] });
    let (ciphertext, nonce) = session
        .encrypt_client(prompt.to_string().as_bytes())
        .unwrap();
    socket
        .send(WsMessage::Text(
            json!({
                "type": "prompt",
                "ciphertext": B64.encode(ciphertext),
                "nonce": B64.encode(nonce),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    // 4. encrypted chunks until done
    let mut transcript = String::new();
    loop {
        let frame: Value = next_json(&mut socket).await;
        match frame["type"].as_str().unwrap() {
            "chunk" => {
                let ciphertext = B64.decode(frame["ciphertext"].as_str().unwrap()).unwrap();
                let nonce_bytes = B64.decode(frame["nonce"].as_str().unwrap()).unwrap();
                let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().unwrap();
                let plaintext = session.decrypt_client(&ciphertext, &nonce).unwrap();
                transcript.push_str(std::str::from_utf8(&plaintext).unwrap());
            }
            "done" => break,
            other => panic!("unexpected frame type: {other}"),
        }
    }
    assert_eq!(transcript, "Hello, world");

    socket
        .send(WsMessage::Text(
            json!({ "type": "close" }).to_string().into(),
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn websocket_rejects_missing_token() {
    let Some(base) = spawn_app().await else {
        return;
    };
    let ws_url = format!(
        "{}/chat/stream?token=not-a-valid-jwt",
        base.replace("http://", "ws://")
    );
    let result = tokio_tungstenite::connect_async(&ws_url).await;
    assert!(result.is_err(), "invalid token must not upgrade");
}

async fn next_json<S>(socket: &mut S) -> Value
where
    S: futures::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match socket.next().await.expect("socket closed").unwrap() {
            WsMessage::Text(text) => return serde_json::from_str(text.as_str()).unwrap(),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
