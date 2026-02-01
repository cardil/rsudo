# rsudo Implementation Plan

> Implementation roadmap for [SPEC.md](./SPEC.md). See spec for detailed requirements.

## Phase Summary

| Phase | Dependencies | Effort | Deliverable |
|-------|--------------|--------|-------------|
| 1. Setup | - | S | Rust workspace, CI, project structure |
| 2. Core lib | Phase 1 | M | Crypto, types, SSR format, config parsing |
| 3. CLI | Phase 2 | M | `rsudo` binary with all commands |
| 4. Server | Phase 2 | L | Approval server with REST + WebSocket |
| 5. Approver UI | Phase 4 | M | Web dashboard for approve/reject |
| 6. Integration | All | S | E2E tests, docs, packaging |

---

## Phase 1: Setup

- [ ] Initialize Cargo workspace with `rsudo-core`, `rsudo-cli`, `rsudo-server` crates
- [ ] Configure CI (GitHub Actions): lint, test, build matrix (Linux x86_64/aarch64)
- [ ] Add dependencies from spec §7: tokio, reqwest, ring, clap, serde
- [ ] Setup logging with tracing crate

**Deliverable**: `cargo build` succeeds on all crates

---

## Phase 2: Core Library (`rsudo-core`)

- [ ] Ed25519 key generation, signing, verification (ring)
- [ ] Request/response types per spec §5 (serde)
- [ ] SSR token format: encode/decode/sign/verify
- [ ] Nonce generation (UUID v4) and timestamp validation
- [ ] Config parsing (TOML) per spec §6
- [ ] Error types for all failure modes (spec §8)

**Deliverable**: Core lib with unit tests, no I/O dependencies

---

## Phase 3: CLI (`rsudo-cli`)

- [ ] Command parsing with clap per spec §4
- [ ] `rsudo init` - generate client keypair
- [ ] `rsudo register <server>` - POST public key to server
- [ ] `rsudo <command>` - hanging mode: request → poll → execute
- [ ] `rsudo --ssr <command>` - output SSR token, exit
- [ ] `rsudo --signed <token>` - verify and execute
- [ ] Exit codes per spec §4 table
- [ ] User feedback (emoji output per spec §8)

**Deliverable**: Functional CLI, works with mock server

---

## Phase 4: Server (`rsudo-server`)

- [ ] HTTP server with axum, bind per spec §6
- [ ] `POST /requests` - accept request, store pending
- [ ] `POST /requests/:id/approve` - mark approved, store signature
- [ ] `GET /requests/:id` - poll status (for hanging mode)
- [ ] WebSocket `/ws` - push new requests to connected approvers
- [ ] Nonce cache (24h expiry) for replay prevention
- [ ] Client/approver public key registry
- [ ] TLS configuration
- [ ] Audit logging to file

**Deliverable**: Server accepting requests, pushing to WebSocket

---

## Phase 5: Approver UI

- [ ] Web dashboard (single HTML + JS, served by rsudo-server)
- [ ] WebSocket client for real-time request push
- [ ] Request list: command, host, user, timestamp
- [ ] Approve/Reject buttons with signature
- [ ] Session auth (token-based, pre-authenticated)

**Deliverable**: Browser-based approval workflow

---

## Phase 6: Integration

- [ ] E2E test: CLI → Server → UI → approve → execute
- [ ] E2E test: SSR flow (offline signing)
- [ ] E2E test: timeout and rejection paths
- [ ] README with quickstart
- [ ] Binary release workflow (tar.gz)
- [ ] Docker image for server

**Deliverable**: Release-ready v0.1.0
