# S5M Agent WebSocket migration plan

## Status

Implementation is on `fix/websocket-control-plane`; PR #178 is closed pending follow-up fixes and target-device validation. The Agent now uses one persistent authenticated WebSocket session for runtime status, configuration synchronization, command delivery, and command acknowledgements. HTTP is limited to initial registration and controller reachability probing; there is no HTTP fallback for runtime data. Do not merge until CI passes and staging/target-device validation is complete.

## Goal

Replace the Agent's 30-second command/config polling with an Agent-initiated, authenticated WebSocket connection. Keep HTTP only for initial registration and a lightweight controller reachability probe; the new Agent must never use HTTP for runtime status, configuration, commands, or ACK fallback.

## Compatibility guardrails

- Do not merge this branch into `main` unless explicitly requested.
- Do not restore Docker/RouterOS remote container-management APIs, UI, or task polling.
- Keep the existing registration flow, machine-code binding, per-Agent token, heartbeat telemetry schema, Mihomo config validation/reload/rollback, and kernel update SHA-256 verification.
- The Agent initiates outbound connections; no inbound RouterOS port is required.
- Use `wss://` in production. If the configured controller URL is `https://host/base`, derive `wss://host/base/api/v1/agent/ws`; for local development only, `http://` maps to `ws://`.
- Do not expose Mihomo's controller API beyond loopback `127.0.0.1:8088`.

## Proposed protocol

Endpoint: `GET /api/v1/agent/ws` (WebSocket upgrade).

Authentication: use the existing Agent bearer token in the HTTP Upgrade request's `Authorization: Bearer <token>` header. Validate it using the same machine-bound Agent credential logic as existing Agent endpoints before upgrading. Do not put credentials in the URL query string. Restrict Origin policy deliberately; Agent clients are not browsers and should not need an arbitrary Origin.

Messages are UTF-8 JSON envelopes with a versioned schema:

- Server -> Agent: `{"type":"welcome","protocol":1,"heartbeat_interval_sec":30}`
- Agent -> Server: `{"type":"heartbeat","id":"...","sent_at":"RFC3339","status":{...}}`
- Server -> Agent: `{"type":"config.changed","id":"...","sha256":"..."}`
- Server -> Agent: `{"type":"command","id":"...","command":{"id":"...","type":"update_mihomo","version":"vX.Y.Z","sha256":"..."}}`
- Agent -> Server: `{"type":"command.ack","id":"...","status":"success|failed","message":"..."}`
- Agent -> Server: `{"type":"config.sync.request","id":"...","local_sha256":"..."}`
- Server -> Agent: `{"type":"config.sync","id":"...","sha256":"...","yaml":"..."}`
- Either direction may send protocol-level ping/pong control frames; JSON ping messages are not a substitute for WebSocket control frames.

The config payload must pass the same validation and safe-apply/rollback path as the current HTTP config response. The server must only send config for the authenticated machine code.

## Delivery and reconnection semantics

- Each application message has a bounded size and an ID. Reject unknown message types, invalid JSON, oversized payloads, and unexpected fields where practical.
- Commands are acknowledged only after execution finishes. The server persists the command/result before clearing pending work; reconnecting Agents can request pending work again.
- Command handlers must remain idempotent. A lost ACK must not cause an unsafe repeated kernel replacement.
- One goroutine owns WebSocket writes and one owns reads. Apply write deadlines, read limits, heartbeat deadlines, bounded outbound queues, and connection cleanup.
- Reconnect with exponential backoff capped at 60 seconds plus up to 50% jitter. Reset backoff after a connection session remains stable for at least two minutes.
- The refactored Agent must not use HTTP config/heartbeat/command fallback. Legacy HTTP endpoints may remain temporarily for older Agent versions, but the new Agent must never call them. Do not run two command consumers for the same machine code.
- On a WebSocket disconnect, the UI should mark the transport disconnected after a freshness timeout; a successful heartbeat still does not prove all proxy routes are healthy.

## Implementation phases

1. Add contract tests and this protocol document.
2. Implement the server WebSocket endpoint, shared Agent-token authentication, per-machine connection registry, lifecycle cleanup, heartbeat persistence, and config/command delivery without changing the Agent's default transport.
3. Implement the Agent WebSocket client with reconnect/backoff, ping/pong, message limits, command ACK, and existing config/kernel safety functions.
4. Add integration tests for unauthorized handshake, duplicate machine connections, disconnect cleanup, reconnect/resync, stale config hash, duplicate command/ACK, and oversized/malformed messages.
5. Validate the WebSocket-only runtime path in CI/staging. Legacy HTTP runtime endpoints may remain server-side temporarily for older Agent releases, but this Agent must not call them.
6. Test on actual RouterOS 7.21.5 AMD64/ARM64 hardware or verified target devices: outbound WSS, DNS/TLS, long idle connection, reboot, temporary WAN loss, CGNAT, config sync, kernel update and rollback.
7. After successful verification, merge the PR into `dev` first. Do not merge into `main` or publish a stable release automatically.

## Acceptance criteria

- The refactored Agent performs registration over HTTP, then uses HTTP only for reachability probes; all runtime status/config/commands/ACKs use WebSocket. Legacy HTTP endpoints remain server-side only for compatibility during rollout.
- An authorized Agent can establish WSS and only receives messages for its own machine code.
- Unauthorized or revoked tokens are rejected before upgrade.
- Heartbeat/online state becomes stale when the connection is lost and recovers after reconnect.
- Config change delivery applies atomically through the existing validation/reload/rollback path.
- Kernel update commands retain official download URL validation, SHA-256 verification, health checks, and rollback.
- No container-management endpoints, UI, or tasks are reintroduced.
- Go tests, vet, builds, static checks, and RouterOS image smoke tests pass.
