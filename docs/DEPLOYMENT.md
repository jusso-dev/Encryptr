# Deployment Guide

## Requirements

- PostgreSQL 14+ (16 recommended)
- An LLM provider: an OpenAI or Anthropic API key, or a reachable Ollama
  instance
- 64-bit Linux (release binary or Docker)

## Docker Compose (single host)

```bash
cp .env.example .env
# Required: JWT_SECRET (openssl rand -base64 48), PROVIDER + credentials
docker compose up --build -d
curl http://localhost:8080/health
```

The image is a two-stage build (rust:slim → debian:bookworm-slim), runs as a
non-root user, and contains only the binary and CA certificates. Migrations
run automatically at startup.

## Bare binary

```bash
cargo build --release
DATABASE_URL=postgres://... JWT_SECRET=... PROVIDER=anthropic \
  ANTHROPIC_API_KEY=... BIND_ADDR=0.0.0.0:8080 ./target/release/encryptr-server
```

## TLS

Two supported modes:

1. **Native rustls** — set `TLS_CERT_PATH` and `TLS_KEY_PATH` (PEM). The
   server binds HTTPS directly and drains connections for up to 20 s on
   shutdown.
2. **Terminating proxy** (nginx/caddy/ALB) — leave the TLS vars unset and
   run plaintext on a private network. Forward `X-Forwarded-For` so rate
   limiting keys on the real client IP, and proxy WebSocket upgrades for
   `/chat/stream` (`Upgrade`/`Connection` headers, read timeout off).

Note that chat content has its own end-to-end encryption layer inside the
WebSocket, so a TLS-terminating proxy still cannot read prompts/responses.

## Environment matrix

| Variable | Production guidance |
|---|---|
| `ENVIRONMENT` | `production` (turns on JSON logs by default) |
| `JWT_SECRET` | ≥32 bytes, from a secret manager, rotated on schedule |
| `ACCESS_TOKEN_TTL_SECS` | Keep short (900) |
| `DATABASE_MAX_CONNECTIONS` | ≈ 2–4 × CPU cores of the DB, split across replicas |
| `RATE_LIMIT_*` | The in-memory limiter is per-instance; add an edge limiter when horizontally scaled |
| `CORS_ALLOWED_ORIGINS` | Exact origins only; empty means browsers are denied cross-origin |

## Observability

- `GET /health` — liveness + DB reachability (503 when degraded); wire into
  your orchestrator's probes.
- `GET /metrics` — Prometheus text format. Consider protecting it at the
  network layer.
- Logs are structured `tracing` output; `RUST_LOG` controls verbosity. By
  policy no prompt/response content or secrets are ever logged.

## Scaling notes

- The server is stateless apart from in-memory rate-limit windows: scale
  horizontally behind a load balancer. WebSocket sessions are sticky by
  nature of the connection but share no cross-instance state.
- Postgres is the single stateful dependency; use a managed instance with
  PITR backups. All content in it is ciphertext, but treat it as sensitive
  anyway (metadata, hashes).
- Run migrations by deploying one instance first (startup applies them) or
  gate rollout on the `/health` check.

## Hardening checklist

- [ ] `JWT_SECRET` from a secret manager, not the compose file
- [ ] TLS everywhere (native or proxy)
- [ ] Edge rate limiting / WAF for DDoS (the app limiter is per-IP, per-instance)
- [ ] `/metrics` not publicly reachable
- [ ] Database network-isolated; TLS to Postgres (`?sslmode=require` in `DATABASE_URL`)
- [ ] Provider chosen with an appropriate data-retention agreement
- [ ] Log pipeline treats logs as sensitive (they contain emails/IPs, never content)
