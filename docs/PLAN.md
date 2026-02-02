# rsudo Implementation Plan

> Implementation roadmap for [SPEC.md](./SPEC.md). See spec for detailed requirements.

## Phase Summary

| Phase | Dependencies | Effort | Deliverable |
|-------|--------------|--------|-------------|
| 1. Setup | - | S | Rust workspace, CI, project structure |
| 2. Core lib | Phase 1 | M | Crypto, types, SSR format, config parsing |
| 3. CLI | Phase 2 | M | `rsudo` binary with all commands |
| 4. Server | Phase 2 | L | Approval server with REST + WebSocket + DB |
| 5. Distribution | Phase 3,4 | M | deb, rpm, AUR, Homebrew, containers + CI |
| 6. Approver UIs | Phase 4 | L | Web dashboard + desktop apps + IDE plugins |
| 7. Integration | All | S | E2E tests, docs, final release |

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
- [ ] Database backend (SQLite default, PostgreSQL optional)
- [ ] TLS configuration
- [ ] Audit logging to file

**Deliverable**: Server accepting requests, pushing to WebSocket

---

## Phase 5: Distribution Packages

### `rsudo` package (CLI)

- [ ] deb package (cargo-deb or debian/ directory)
- [ ] rpm package (cargo-rpm or spec file)
- [ ] AUR PKGBUILD (Arch Linux)
- [ ] Homebrew formula (macOS)
- [ ] Optional: Nix derivation, Alpine apk

### `rsudo-server` package

- [ ] deb/rpm packages (same tooling as CLI)
- [ ] Docker image (multi-stage build, distroless base)
- [ ] Docker Compose example with PostgreSQL

### `rsudo-approver` package (Desktop App)

- [ ] Flatpak (Flathub)

### IDE Plugins

- [ ] VS Code extension: publish to VS Code Marketplace
- [ ] JetBrains plugin: publish to JetBrains Marketplace

### Package contents

| Component | Path |
|-----------|------|
| CLI binary | `/usr/bin/rsudo` |
| Server binary | `/usr/bin/rsudo-server` |
| sudoers config | `/etc/sudoers.d/rsudo` |
| Config directory | `/etc/rsudo/` |
| Drop-in directory | `/etc/rsudo.d/` |
| Default config | `/etc/rsudo/config.toml` |
| Log directory | `/var/log/rsudo/` |

### CI/CD automation

- [ ] GitHub Actions workflow: build packages on release tag
- [ ] Cross-compilation: x86_64, aarch64
- [ ] Package signing (GPG for deb/rpm)
- [ ] Container registry push (ghcr.io)

### Install scripts

- [ ] `install.sh` for manual binary installation
- [ ] Post-install hooks: create directories, set permissions

**Deliverable**: Installable packages for major Linux distros + container images

---

## Phase 6: Approver UIs

Per spec §5, approvers need multiple interfaces for real-time approval.

### Web Dashboard (served by rsudo-server)

- [ ] Single HTML + JS bundle, embedded in server binary
- [ ] WebSocket client for real-time request push
- [ ] Web Push Notifications (browser popup when tab not focused)
- [ ] Request list: command, host, user, timestamp
- [ ] Approve/Reject buttons with signature
- [ ] OAuth login flow for approver authentication

### Desktop App (`rsudo-approver`)

- [ ] GTK4 tray app for Linux (libadwaita for GNOME integration)
- [ ] System notifications with approve/reject actions
- [ ] WebSocket connection to server for push notifications
- [ ] Approver enrollment via OAuth device flow

### IDE Plugins

- [ ] VS Code extension: popup notifications, approve/reject commands
- [ ] JetBrains plugin: same functionality

### Common approver features

- [ ] Approver keypair generation and storage
- [ ] Request signing on approval
- [ ] Session management (auto-reconnect, token refresh)
- [ ] Notification channel priority (see spec §5)

**Deliverable**: Web UI + desktop notification apps for quick approvals

---

## Phase 7: Integration

- [ ] E2E test: CLI → Server → UI → approve → execute
- [ ] E2E test: SSR flow (offline signing)
- [ ] E2E test: timeout and rejection paths
- [ ] README with quickstart
- [ ] Binary release workflow (tar.gz)

**Deliverable**: Release-ready v0.1.0
