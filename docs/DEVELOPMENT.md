# Developer Guide

## Prerequisites

- Rust stable (1.80+; CI uses latest stable)
- Docker (for PostgreSQL) or a local PostgreSQL 14+

## Setup

```bash
git clone https://github.com/jusso-dev/Encryptr && cd Encryptr
docker compose up -d postgres
export DATABASE_URL=postgres://encryptr:encryptr@localhost:5432/encryptr
export JWT_SECRET=$(openssl rand -base64 48)
cargo run
```

Migrations in `migrations/` are embedded via `sqlx::migrate!` and applied at
startup — no CLI needed. Add a new migration as
`migrations/000N_description.sql`.

## Project layout

```
src/
  api/            HTTP + WebSocket handlers, router
  middleware/     auth extractor, rate limiting, headers, metrics
  services/       business logic (auth flows, ownership rules, audit)
  repositories/   all SQL, prepared statements
  providers/      ChatProvider trait + openai/anthropic/ollama + SSE parsing
  crypto/         argon2id, JWT, AES-GCM, X25519 stream sessions, validation
  domain/         row models, DTOs, request validation
  config.rs       env-only configuration
  error.rs        AppError → HTTP mapping
  state.rs        shared AppState
tests/
  api_integration.rs   full-stack tests incl. encrypted WebSocket round trip
  crypto_properties.rs proptest properties for the crypto layer
```

## Tests

```bash
cargo test                          # unit + property tests, no DB required
TEST_DATABASE_URL=postgres://encryptr:encryptr@localhost:5432/encryptr \
  cargo test                        # + full integration suite
```

Integration tests spin the real router on an ephemeral port with a mock
provider, so they need no network or API keys. Each test uses fresh
UUID-based emails, so a shared database is fine.

## Quality gates (same as CI)

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit          # cargo install cargo-audit
```

## Adding an AI provider

1. Create `src/providers/yourvendor.rs` implementing `ChatProvider`
   (see `ollama.rs` for the smallest example). Keep the line parser a pure
   function so it unit-tests without network.
2. Add a `ProviderKind` variant + env parsing in `src/config.rs`.
3. Register it in `build_provider()` in `src/providers/mod.rs`.

Nothing else changes — handlers and services are provider-agnostic.

## Contributing

- Branch from `main`; keep PRs focused.
- All CI gates must pass (`fmt`, `clippy -D warnings`, tests, audit).
- Security-sensitive changes (anything under `src/crypto/` or the auth
  flows) should update `docs/THREAT_MODEL.md` in the same PR.
- Never log message content or secrets; follow `AppError` conventions so
  internals don't leak to clients.
