//! Encrypted WebSocket chat streaming: `/chat/stream`.
//!
//! Protocol (JSON text frames):
//!
//! 1. Client connects with `?token=<access JWT>`.
//! 2. Server → `server_hello { public_key }` — ephemeral X25519 key, base64.
//! 3. Client → `client_hello { public_key }` — client's ephemeral key.
//!    Both sides derive direction-separated AES-256-GCM keys (HKDF-SHA256).
//! 4. Client → `prompt { ciphertext, nonce }` — an encrypted JSON payload
//!    `{ "messages": [{"role","content"}...], "model"?, "max_tokens"?,
//!    "temperature"? }`.
//! 5. Server decrypts in memory, forwards to the configured LLM provider and
//!    streams back `chunk { ciphertext, nonce }` frames, closing the turn
//!    with `done`. Plaintext buffers are zeroized as soon as each frame has
//!    been handled; nothing is persisted or logged.
//!
//! Nonces are strict counters per direction, so replayed or reordered frames
//! fail authentication (see `crypto::stream_session`).

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

use crate::crypto::aead::NONCE_LEN;
use crate::crypto::stream_session::{Handshake, StreamSession};
use crate::error::AppResult;
use crate::middleware::auth::{authenticate, AuthUser};
use crate::providers::{ChatMessage, ChatRequest, StreamEvent};
use crate::repositories::sessions;
use crate::state::AppState;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Hard limits on a single prompt payload.
const MAX_PROMPT_MESSAGES: usize = 100;
const MAX_PROMPT_BYTES: usize = 512 * 1024;
/// Cap on an inbound WebSocket frame. `RequestBodyLimitLayer` does not apply to
/// WS frames, so bound them here to keep a client from forcing a huge
/// allocation before the payload is even decoded. Generous vs. the base64
/// expansion of `MAX_PROMPT_BYTES`.
const MAX_WS_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_TOKENS: u32 = 1024;
const MAX_MAX_TOKENS: u32 = 8192;

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StreamQuery {
    /// Access JWT — passed as a query parameter because browsers cannot set
    /// the `Authorization` header on a WebSocket upgrade.
    token: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    ServerHello { public_key: String },
    Chunk { ciphertext: String, nonce: String },
    Done,
    Error { code: &'static str, message: String },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    ClientHello { public_key: String },
    Prompt { ciphertext: String, nonce: String },
    Close,
}

/// The decrypted prompt payload. Content strings are zeroized after use.
#[derive(Deserialize)]
struct PromptPayload {
    messages: Vec<ChatMessage>,
    model: Option<String>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
}

impl Drop for PromptPayload {
    fn drop(&mut self) {
        for message in &mut self.messages {
            message.content.zeroize();
        }
    }
}

/// Establish the end-to-end encrypted streaming chat WebSocket.
///
/// This is a WebSocket upgrade, not a normal request/response. After upgrade the
/// client and server perform an X25519 handshake, then exchange AES-256-GCM
/// encrypted JSON frames (`prompt` → `chunk*` → `done`). See the module docs for
/// the frame protocol. OpenAPI cannot model the frame exchange itself.
#[utoipa::path(
    get, path = "/chat/stream", tag = "chat",
    params(StreamQuery),
    responses(
        (status = 101, description = "Switching Protocols — WebSocket upgrade"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ApiError),
    ),
)]
pub async fn chat_stream(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    ws: WebSocketUpgrade,
) -> AppResult<Response> {
    // Browsers cannot set Authorization headers on WebSocket upgrades, so the
    // access token arrives as a query parameter and is validated up front.
    let user = authenticate(&state, &query.token).await?;
    let ws = ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES);
    Ok(ws.on_upgrade(move |socket| async move {
        state
            .metrics
            .ws_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .ws_sessions_active
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = handle_socket(socket, &state, user).await {
            // Log the category only; never any conversation content.
            tracing::debug!(?error, "chat stream closed with error");
        }
        state
            .metrics
            .ws_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
    }))
}

async fn send_frame(socket: &mut WebSocket, frame: &ServerFrame) -> anyhow::Result<()> {
    let text = serde_json::to_string(frame)?;
    socket.send(Message::Text(text.into())).await?;
    Ok(())
}

async fn next_client_frame(socket: &mut WebSocket) -> anyhow::Result<Option<ClientFrame>> {
    while let Some(message) = socket.recv().await {
        match message? {
            Message::Text(text) => {
                let frame = serde_json::from_str::<ClientFrame>(text.as_str())?;
                return Ok(Some(frame));
            }
            Message::Close(_) => return Ok(None),
            // Ping/pong are handled by the protocol layer; ignore binary.
            _ => continue,
        }
    }
    Ok(None)
}

async fn handle_socket(
    mut socket: WebSocket,
    state: &AppState,
    user: AuthUser,
) -> anyhow::Result<()> {
    // --- Handshake ---
    let handshake = Handshake::new();
    send_frame(
        &mut socket,
        &ServerFrame::ServerHello {
            public_key: B64.encode(handshake.public_key_bytes()),
        },
    )
    .await?;

    let client_public = match next_client_frame(&mut socket).await? {
        Some(ClientFrame::ClientHello { public_key }) => public_key,
        Some(_) => {
            send_frame(
                &mut socket,
                &ServerFrame::Error {
                    code: "protocol_error",
                    message: "expected client_hello".into(),
                },
            )
            .await?;
            return Ok(());
        }
        None => return Ok(()),
    };

    let client_public_bytes = B64
        .decode(&client_public)
        .map_err(|_| anyhow::anyhow!("client_hello public_key is not valid base64"))?;
    let mut session = match handshake.complete(&client_public_bytes) {
        Ok(session) => session,
        Err(_) => {
            send_frame(
                &mut socket,
                &ServerFrame::Error {
                    code: "handshake_failed",
                    message: "invalid client public key".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    tracing::info!(user_id = %user.user_id, "chat stream established");

    // The access token's expiry is a hard ceiling on the connection: auth is
    // checked once at upgrade, so without this a socket would outlive the token.
    let now = Utc::now().timestamp();
    let ttl_secs = user.expires_at.saturating_sub(now);
    if ttl_secs <= 0 {
        let _ = socket.send(Message::Close(None)).await;
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(ttl_secs as u64);
    let sleep = tokio::time::sleep_until(deadline);
    tokio::pin!(sleep);

    // --- Prompt / response loop ---
    loop {
        let frame = tokio::select! {
            _ = &mut sleep => {
                let _ = send_frame(
                    &mut socket,
                    &ServerFrame::Error {
                        code: "session_expired",
                        message: "access token expired; reconnect".into(),
                    },
                )
                .await;
                break;
            }
            frame = next_client_frame(&mut socket) => frame?,
        };
        let Some(frame) = frame else { break };

        match frame {
            ClientFrame::Prompt { ciphertext, nonce } => {
                // Re-validate the session on every prompt so a logout/revocation
                // takes effect on an already-open socket.
                if !sessions::is_active(&state.pool, user.session_id)
                    .await
                    .unwrap_or(false)
                {
                    let _ = send_frame(
                        &mut socket,
                        &ServerFrame::Error {
                            code: "session_revoked",
                            message: "session is no longer active".into(),
                        },
                    )
                    .await;
                    break;
                }
                // Per-user cap on prompts: the HTTP rate limiter only guards the
                // one-time upgrade, so meter individual prompts here to bound
                // upstream provider cost/abuse on a single connection.
                if !state
                    .rate_limiter
                    .check(&format!("ws-prompt:{}", user.user_id))
                {
                    state
                        .metrics
                        .rate_limited_total
                        .fetch_add(1, Ordering::Relaxed);
                    send_frame(
                        &mut socket,
                        &ServerFrame::Error {
                            code: "rate_limited",
                            message: "too many prompts, slow down".into(),
                        },
                    )
                    .await?;
                    continue;
                }
                if let Err(error) =
                    handle_prompt(&mut socket, state, &mut session, &ciphertext, &nonce).await
                {
                    state
                        .metrics
                        .provider_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(?error, "prompt handling failed");
                    send_frame(
                        &mut socket,
                        &ServerFrame::Error {
                            code: "stream_error",
                            message: "failed to process the prompt".into(),
                        },
                    )
                    .await?;
                }
            }
            ClientFrame::Close => break,
            ClientFrame::ClientHello { .. } => {
                send_frame(
                    &mut socket,
                    &ServerFrame::Error {
                        code: "protocol_error",
                        message: "handshake already completed".into(),
                    },
                )
                .await?;
            }
        }
    }

    let _ = socket.send(Message::Close(None)).await;
    Ok(())
}

async fn handle_prompt(
    socket: &mut WebSocket,
    state: &AppState,
    session: &mut StreamSession,
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> anyhow::Result<()> {
    use futures::StreamExt;

    let ciphertext = B64.decode(ciphertext_b64)?;
    let nonce_bytes = B64.decode(nonce_b64)?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be {NONCE_LEN} bytes"))?;

    // Plaintext lives in a Zeroizing buffer: wiped when it goes out of scope.
    let plaintext = session.decrypt(&ciphertext, &nonce)?;
    if plaintext.len() > MAX_PROMPT_BYTES {
        anyhow::bail!("prompt payload too large");
    }
    let payload: PromptPayload = serde_json::from_slice(&plaintext)?;
    drop(plaintext);

    if payload.messages.is_empty() || payload.messages.len() > MAX_PROMPT_MESSAGES {
        anyhow::bail!("prompt must contain 1..={MAX_PROMPT_MESSAGES} messages");
    }
    for message in &payload.messages {
        if !matches!(message.role.as_str(), "user" | "assistant" | "system") {
            anyhow::bail!("invalid message role");
        }
    }

    let request = ChatRequest {
        model: payload
            .model
            .clone()
            .unwrap_or_else(|| state.config.provider_default_model.clone()),
        messages: payload.messages.clone(),
        max_tokens: payload
            .max_tokens
            .unwrap_or(DEFAULT_MAX_TOKENS)
            .min(MAX_MAX_TOKENS),
        temperature: payload.temperature,
    };
    // `payload` still owns plaintext copies; it zeroizes them on drop.
    drop(payload);

    state
        .metrics
        .provider_requests_total
        .fetch_add(1, Ordering::Relaxed);
    let mut events = state.provider.stream_chat(request).await?;

    while let Some(event) = events.next().await {
        match event? {
            StreamEvent::Delta(mut delta) => {
                state
                    .metrics
                    .provider_chunks_total
                    .fetch_add(1, Ordering::Relaxed);
                let (chunk_ciphertext, chunk_nonce) = session.encrypt(delta.as_bytes())?;
                delta.zeroize();
                send_frame(
                    socket,
                    &ServerFrame::Chunk {
                        ciphertext: B64.encode(chunk_ciphertext),
                        nonce: B64.encode(chunk_nonce),
                    },
                )
                .await?;
            }
            StreamEvent::Done => break,
        }
    }

    send_frame(socket, &ServerFrame::Done).await?;
    Ok(())
}
