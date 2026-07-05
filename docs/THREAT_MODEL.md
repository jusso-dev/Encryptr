# Threat Model

## Security goal

The server must be able to operate the service (auth, storage, AI proxying)
while being **unable to read stored conversation history**, and while holding
plaintext prompts/responses only transiently in memory during streaming.

## Assets

| Asset | Sensitivity |
|---|---|
| Message plaintext (prompts, responses) | Highest — must never be persisted or logged server-side |
| Client private keys / conversation keys | Never reach the server |
| Password hashes, refresh-token digests | High — breach enables offline attack attempts |
| JWT signing secret | High — forgery of access tokens |
| Provider API keys | High — financial abuse |
| Conversation metadata (titles, timestamps) | Medium — readable by design |
| Audit events | Medium — content-free by policy |

## Trust boundaries

1. **Client ↔ Server**: TLS (native rustls or terminating proxy). The
   streaming path adds an ephemeral X25519/AES-GCM layer on top, so chat
   plaintext is protected even from TLS-terminating middleboxes.
2. **Server ↔ PostgreSQL**: the database is treated as *untrusted for
   confidentiality of content* — everything content-bearing is ciphertext
   produced client-side.
3. **Server ↔ LLM provider**: plaintext necessarily crosses this boundary
   (the model must read the prompt). Provider choice and its data-retention
   policy are a deployment decision.

## What the server stores vs. never stores

Stores: AEAD ciphertext (tag appended), nonces, algorithm labels, key IDs,
conversation metadata, Argon2id password hashes, SHA-256 refresh-token/API-key
digests, Ed25519/X25519 **public** keys, structured audit events.

Never stores: plaintext prompts/responses, private keys, conversation keys,
prompt logs. Logging policy: errors log categories and identifiers, never
content; `tracing` fields are explicitly chosen, and provider errors are
stringified without URLs (`without_url()`) to avoid leaking keys embedded in
query strings.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Database breach | Content is client-side ciphertext; passwords Argon2id; tokens stored as digests; private keys absent |
| Stolen access token | 15-minute TTL; session revocation checked per request; logout kills the session immediately |
| Stolen refresh token | Single-use rotation; reuse of a rotated token revokes the entire session and is audited (theft detection) |
| Credential stuffing / brute force | Strict per-IP rate limit on `/register`, `/login`, `/refresh` (default 10/min) plus a global limiter; Argon2id cost |
| Account-existence oracle | Login performs a dummy Argon2 verification when the user is unknown (uniform timing); uniform 401 |
| Replay/reorder of streaming frames | Strict counter nonces per direction; AAD binds direction; any deviation fails AEAD authentication |
| MITM key substitution on WS handshake | TLS authenticates the server; handshake transcript (both public keys) is bound into HKDF salt. Client-side key pinning is future work |
| Small-order / invalid public keys | Ed25519 keys must be valid non-weak points; X25519 keys checked against the RFC 7748 low-order blocklist; non-contributory ECDH rejected |
| SQL injection | SQLx bound parameters only; no string-interpolated values (only compile-time constant column lists) |
| XSS/clickjacking on API responses | `nosniff`, `DENY` framing, no-referrer, restrictive CORS (deny-by-default origins), `cache-control: no-store` |
| Oversized payloads / DoS | Global body limit (1 MiB default), 256 KiB ciphertext cap per message, 512 KiB prompt cap, bounded channels, connection pool caps. Distributed DoS is out of scope — deploy behind an edge/WAF |
| Secret leakage via logs | No content logging by policy; internal errors return generic messages; secrets only via env |
| Token forgery | HS256 with ≥32-byte secret enforced at startup; issuer + expiry validated; 5 s leeway only |

## Residual risks / accepted limitations

- **Plaintext at the provider**: unavoidable — the LLM must read the prompt.
  Mitigate by choosing providers with no-retention agreements or self-hosted
  Ollama.
- **Zeroization is best-effort**: decrypted prompts live in `Zeroizing`
  buffers and are wiped after use, but transient copies exist during JSON
  serialization into the provider HTTP body and inside TLS buffers. A
  compromised host OS/hypervisor can read process memory regardless; HSM /
  confidential-computing support is on the roadmap for that class of
  attacker.
- **Metadata is visible**: titles, timing, message sizes and cadence are
  observable by the server and could be minimized further (padded/encrypted
  titles) at a UX cost.
- **In-memory rate limiting** is per-instance; multi-replica deployments
  should rate-limit at the edge as well.
- **Client integrity**: a malicious or compromised client can obviously leak
  its own plaintext; this model protects against a curious/compromised
  *server datastore*, not compromised endpoints.

## Auditing

Security-relevant events (`user.registered`, `auth.login`,
`auth.login_failed`, `auth.token_refreshed`,
`auth.refresh_token_reuse_detected`, `auth.logout`, `conversation.*`,
`key.uploaded`) are written to `audit_events` with identifiers and outcomes
only — never content.
