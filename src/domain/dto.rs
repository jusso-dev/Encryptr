//! Request/response DTOs for the HTTP API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use zeroize::Zeroize;

use super::models::{Conversation, EncryptedMessage, PublicKeyRecord, User};

// ---------- Auth ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

/// Wipe the plaintext password from memory once the request is done with.
impl Drop for RegisterRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl Drop for RefreshRequest {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for MeResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            created_at: user.created_at,
        }
    }
}

// ---------- Conversations ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConversationRequest {
    pub title: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConversationRequest {
    pub title: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConversationResponse {
    pub id: Uuid,
    pub title: String,
    pub model: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Conversation> for ConversationResponse {
    fn from(c: Conversation) -> Self {
        Self {
            id: c.id,
            title: c.title,
            model: c.model,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

// ---------- Messages ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMessageRequest {
    pub conversation_id: Uuid,
    pub role: String,
    /// Base64-encoded AEAD ciphertext (tag appended), produced client-side.
    pub ciphertext: String,
    /// Base64-encoded 96-bit nonce.
    pub nonce: String,
    pub algorithm: Option<String>,
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListMessagesQuery {
    /// Conversation whose messages to return.
    pub conversation_id: Uuid,
    /// Page size, clamped server-side to 1..=200 (default 50).
    pub limit: Option<i64>,
    /// Return messages created strictly before this timestamp (pagination).
    pub before: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub role: String,
    pub ciphertext: String,
    pub nonce: String,
    pub algorithm: String,
    pub key_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl From<EncryptedMessage> for MessageResponse {
    fn from(m: EncryptedMessage) -> Self {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            id: m.id,
            conversation_id: m.conversation_id,
            role: m.role,
            ciphertext: b64.encode(&m.ciphertext),
            nonce: b64.encode(&m.nonce),
            algorithm: m.algorithm,
            key_id: m.key_id,
            created_at: m.created_at,
        }
    }
}

// ---------- Keys ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateKeyRequest {
    /// Base64-encoded 32-byte Ed25519 public key.
    pub ed25519_public_key: String,
    /// Base64-encoded 32-byte X25519 public key.
    pub x25519_public_key: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyResponse {
    pub id: Uuid,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
}

impl From<PublicKeyRecord> for KeyResponse {
    fn from(k: PublicKeyRecord) -> Self {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            id: k.id,
            ed25519_public_key: b64.encode(&k.ed25519_public_key),
            x25519_public_key: b64.encode(&k.x25519_public_key),
            label: k.label,
            created_at: k.created_at,
        }
    }
}

// ---------- Health ----------

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub database: &'static str,
}
