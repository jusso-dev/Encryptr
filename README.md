# Encryptr Server

A production-grade Rust backend for encrypted AI conversations. The server
authenticates users, stores conversation history as client-side ciphertext,
proxies prompts to pluggable LLM providers, and streams responses back over an
end-to-end-encrypted WebSocket — **without ever persisting plaintext
conversation content**.

[![CI](https://github.com/jusso-dev/Encryptr/actions/workflows/ci.yml/badge.svg)](https://github.com/jusso-dev/Encryptr/actions/workflows/ci.yml)

## What it does

- **Authentication** — Argon2id password hashing, short-lived JWT access
  tokens, opaque rotating refresh tokens with reuse (theft) detection, and
  session revocation enforced on every request.
- **Encrypted storage** — message content arrives as AEAD ciphertext produced
  client-side (ciphertext + nonce + auth tag). The server validates shape and
  stores opaque bytes; conversation *metadata* (titles, timestamps) stays
  readable so lists render server-side.
- **Public key management** — clients upload Ed25519 (signing) and X25519
  (key agreement) public keys; both are validated, including small-order
  point rejection. The server never holds private keys.
- **Streaming AI proxy** — `/chat/stream` performs an ephemeral X25519
  handshake per connection, decrypts prompts *in memory only*, streams the
  provider's response back as encrypted chunks with counter-based nonces
  (replay-proof), and zeroizes plaintext buffers as it goes.
- **Provider abstraction** — one `ChatProvider` trait; OpenAI, Anthropic, and
  Ollama implementations included. The application never knows which is
  active; adding a vendor is one new impl.
- **Observability** — structured tracing (JSON in production), request IDs,
  `/health`, and Prometheus-format `/metrics`. Prompts, responses, and
  secrets are never logged.

## Architecture

```
HTTP API (axum) ─ WebSocket streaming
      │
Middleware  (auth extractor · rate limiting · security headers · metrics · request IDs)
      │
Services    (auth · conversations · messages · keys · audit)
      │
Repositories (SQLx, prepared statements)          Providers (OpenAI · Anthropic · Ollama)
      │                                                 │
PostgreSQL                                         Crypto (Argon2id · JWT · AES-256-GCM ·
                                                          X25519+HKDF · Ed25519 validation)
```

Each layer is independently testable — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for diagrams and the request/streaming sequences, and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what the server can and
cannot see.

## Quick start

### Docker Compose

```bash
cp .env.example .env         # set JWT_SECRET at minimum
docker compose up --build
curl http://localhost:8080/health
```

### Local development

```bash
docker compose up -d postgres
export DATABASE_URL=postgres://encryptr:encryptr@localhost:5432/encryptr
export JWT_SECRET=$(openssl rand -base64 48)
export PROVIDER=ollama       # or openai / anthropic (+ API key)
cargo run
```

Migrations are embedded and applied automatically on startup.

### Try it

```bash
# Register + login
curl -s localhost:8080/register -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a-strong-password"}'
TOKEN=$(curl -s localhost:8080/login -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a-strong-password"}' | jq -r .access_token)

# Create a conversation and store an (already encrypted) message
curl -s localhost:8080/conversations -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"title":"First chat"}'
```

The streaming protocol for `/chat/stream` is documented in
[docs/openapi.yaml](docs/openapi.yaml) and in `src/api/chat_stream.rs`; the
integration test `websocket_encrypted_streaming` in
`tests/api_integration.rs` is a complete reference client.

## API surface

| Area | Endpoints |
|---|---|
| Auth | `POST /register` · `POST /login` · `POST /refresh` · `POST /logout` · `GET /me` |
| Conversations | `GET/POST /conversations` · `PUT/DELETE /conversations/{id}` |
| Messages | `GET/POST /messages` · `DELETE /messages/{id}` |
| Keys | `GET/POST /keys` |
| Streaming | `GET /chat/stream` (WebSocket) |
| Ops | `GET /health` · `GET /metrics` |

Full schemas: [docs/openapi.yaml](docs/openapi.yaml).

## Configuration

Environment variables only — see [.env.example](.env.example) for the full
list with defaults. Highlights: `DATABASE_URL`, `JWT_SECRET` (≥32 bytes),
`PROVIDER` (`openai` | `anthropic` | `ollama`), rate-limit knobs, optional
`TLS_CERT_PATH`/`TLS_KEY_PATH` for native rustls termination.

## Testing

```bash
cargo test                       # unit + property tests (no DB needed)

# Integration tests (full HTTP + WebSocket, real Postgres):
docker compose up -d postgres
TEST_DATABASE_URL=postgres://encryptr:encryptr@localhost:5432/encryptr cargo test
```

The suite covers crypto round-trips and tamper detection (including
proptest-driven bit-flip properties), refresh-token rotation and reuse
detection, cross-user access isolation, and the complete encrypted WebSocket
streaming flow against a mock provider.

## CI

GitHub Actions runs `cargo fmt --check`, `clippy -D warnings`, the full test
suite against a Postgres service, `cargo audit`, a Docker build, and uploads
a release binary on `main`.

## Security posture (summary)

- Server stores: ciphertext, nonces, auth tags, metadata, password hashes,
  token digests, public keys.
- Server never stores: plaintext prompts/responses, private keys,
  conversation keys, prompt logs.
- Transport plaintext exists only transiently in memory on the streaming
  path and is zeroized after use (see the threat model for residual-copy
  caveats).

Details, assumptions, and known limitations: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Roadmap

Multi-device key sync · shared encrypted conversations · HSM-backed keys ·
confidential computing · encrypted search · attachments · federation ·
self-hosting mode. (Password reset and email verification are stubbed in the
schema and planned next.)

## Documentation

- [Architecture & sequence diagrams](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [OpenAPI specification](docs/openapi.yaml)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Developer & contributing guide](docs/DEVELOPMENT.md)

## License

MIT
