# Architecture

## Layering

Every layer depends only on the layer(s) below it and is independently
testable.

```
┌────────────────────────────────────────────────────────────┐
│  HTTP API (axum)                                           │
│  src/api — handlers, router, WebSocket streaming           │
├────────────────────────────────────────────────────────────┤
│  Middleware                                                │
│  src/middleware — AuthUser extractor (JWT + session check),│
│  rate limiting, security headers, metrics, request IDs     │
├────────────────────────────────────────────────────────────┤
│  Application services                                      │
│  src/services — auth, conversations, messages, keys, audit │
├──────────────────────────────┬─────────────────────────────┤
│  Repositories                │  Providers                  │
│  src/repositories — SQLx,    │  src/providers — ChatProvider│
│  prepared statements only    │  trait; openai/anthropic/    │
│                              │  ollama impls, SSE/NDJSON    │
├──────────────────────────────┤  parsers                    │
│  PostgreSQL                  ├─────────────────────────────┤
│  migrations/ (embedded,      │  Crypto services            │
│  run at startup)             │  src/crypto — argon2id, JWT,│
│                              │  AES-256-GCM, X25519+HKDF,  │
│                              │  key validation, tokens     │
└──────────────────────────────┴─────────────────────────────┘
```

Shared state (`src/state.rs`) carries the connection pool, config, JWT
service, the active provider as `Arc<dyn ChatProvider>`, rate limiters, and
the metrics registry.

## Request lifecycle (REST)

```
Client                    Server
  │  POST /messages         │
  ├─────────────────────────▶ SetRequestId → TraceLayer → body limit → CORS
  │                          → metrics → security headers → rate limit
  │                          → handler:
  │                              AuthUser extractor
  │                                ├─ verify JWT (HS256, issuer, expiry)
  │                                └─ session revoked? (DB)
  │                              service: validate shape (base64, nonce len,
  │                                       role whitelist, ownership check)
  │                              repository: INSERT prepared statement
  │  201 {message}           │
  ◀──────────────────────────┤
```

## Authentication model

- **Access token**: HS256 JWT, 15 min TTL by default. Claims: `sub` (user),
  `sid` (session), `jti`, `iat/exp/iss`. Every authenticated request also
  checks that `sid` has not been revoked, so logout is immediate.
- **Refresh token**: 256-bit opaque random value; only its SHA-256 digest is
  stored. `POST /refresh` marks the presented token rotated and issues a new
  pair. Presenting an *already rotated* token is treated as theft: the whole
  session (and all its tokens) is revoked and an audit event is written.
- **Passwords**: Argon2id with per-hash random salts. Login runs a dummy
  verification when the account does not exist so timing does not reveal
  account existence.

## Encrypted streaming sequence (`/chat/stream`)

```
Client                                Server                        LLM Provider
  │ WS connect ?token=JWT               │
  ├─────────────────────────────────────▶ authenticate (JWT + session)
  │        server_hello {X25519 pub}    │
  ◀─────────────────────────────────────┤  (fresh ephemeral key per connection)
  │ client_hello {X25519 pub}           │
  ├─────────────────────────────────────▶ ECDH → HKDF-SHA256 → two AES-256-GCM
  │                                     │ keys (c2s / s2c), counter nonces
  │ prompt {ciphertext, nonce=ctr0}     │
  ├─────────────────────────────────────▶ decrypt in memory (Zeroizing buffer)
  │                                     ├──────── stream request ─────────────▶
  │                                     │            SSE / NDJSON chunks
  │                                     ◀──────────────────────────────────────┤
  │ chunk {ciphertext, nonce=ctr0}      │ encrypt each delta, zeroize plaintext
  ◀─────────────────────────────────────┤
  │ chunk {ciphertext, nonce=ctr1} ...  │
  ◀─────────────────────────────────────┤
  │ done                                │
  ◀─────────────────────────────────────┤
```

Design points:

- Handshake keys are ephemeral per connection → forward secrecy for the
  transport layer on top of TLS.
- Nonces are strict per-direction counters. A replayed, reordered, or
  tampered frame fails AEAD authentication (AAD also binds direction).
- The server never persists anything on this path. Storing the exchanged
  messages is the *client's* job via `POST /messages`, using its own storage
  keys — so the server cannot read what it stores.
- Provider identity is hidden behind `Arc<dyn ChatProvider>`; the streaming
  handler is provider-agnostic.

## Data model

```
users ─┬─< sessions ──< refresh_tokens
       ├─< public_keys           (Ed25519 + X25519, validated, public only)
       ├─< conversations ──< encrypted_messages   (ciphertext/nonce/tag only)
       ├─< audit_events          (structured, content-free)
       └─< api_keys              (hash + prefix only; programmatic access, future)
```

Readable by the server: emails, conversation titles/timestamps/model hints,
audit metadata. Opaque to the server: all message content.

## Error handling

`AppError` (src/error.rs) is the single error type crossing layer
boundaries. It maps to stable machine-readable codes
(`validation_error`, `unauthorized`, `rate_limited`, …) and safe messages;
5xx detail is logged server-side and never leaked to clients.

## Observability

- `tracing` spans per request, request IDs generated/propagated via
  `x-request-id`, JSON logs in production (`LOG_JSON`).
- `/metrics` renders a hand-rolled, dependency-free Prometheus exposition:
  request/response counters, latency sum, WS session gauge, provider
  counters. OpenTelemetry can be layered on via `tracing` subscribers
  without touching application code.

## Performance notes

- Fully async (tokio); SQLx pool with prepared statements; streaming
  responses end-to-end (provider chunk → encrypt → WS frame, no buffering of
  the full completion).
- Backpressure: provider chunks flow through a bounded `mpsc` channel (32);
  a slow WebSocket consumer naturally slows the provider read loop.
- Graceful shutdown on SIGINT/SIGTERM drains connections (20 s cap under
  TLS).
