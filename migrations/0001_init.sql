-- Encryptr Server initial schema.
--
-- Design notes:
--  * Conversation metadata (titles, timestamps, model hints) is readable by the
--    server so it can render conversation lists.
--  * Message content is ALWAYS stored as client-side ciphertext. The server
--    never persists plaintext prompts or responses.
--  * Refresh tokens and API keys are stored as SHA-256 hashes only.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    user_agent TEXT,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 hex digest of the opaque token; the raw token never touches disk.
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when this token has been exchanged during rotation. A second use of
    -- a rotated token indicates replay and revokes the whole session.
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX refresh_tokens_session_id_idx ON refresh_tokens (session_id);

CREATE TABLE public_keys (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key  BYTEA NOT NULL,
    label              TEXT NOT NULL DEFAULT 'default',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at         TIMESTAMPTZ,
    UNIQUE (user_id, label)
);

CREATE TABLE conversations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT NOT NULL DEFAULT 'New conversation',
    model      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX conversations_user_id_idx ON conversations (user_id) WHERE deleted_at IS NULL;

CREATE TABLE encrypted_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    -- AEAD ciphertext with the 16-byte authentication tag appended (AES-GCM
    -- convention). Encrypted client-side; opaque to the server.
    ciphertext      BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'AES-256-GCM',
    -- Client key identifier so multi-device clients know which key decrypts.
    key_id          UUID REFERENCES public_keys (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX encrypted_messages_conversation_idx
    ON encrypted_messages (conversation_id, created_at);

CREATE TABLE audit_events (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users (id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    -- Structured, content-free metadata (never prompts/responses/secrets).
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_user_id_idx ON audit_events (user_id, created_at);

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    -- SHA-256 hex digest of the API key; only the prefix is stored readable.
    key_hash     TEXT NOT NULL UNIQUE,
    key_prefix   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
