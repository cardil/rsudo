# rsudo Specification

> Remote sudo for secure command elevation with human-in-the-loop approval.

**Version**: 0.1.0 (Draft) | **Status**: Specification

---

## 1. Overview & Goals

### Core Concept

`rsudo` enables AI agents and automated systems to execute privileged commands with remote human approval. Unlike traditional `sudo`, authorization is delegated to a remote approver who can evaluate requests in real-time.

### Target Users

- **AI Agents**: LLM-based agents needing system privileges
- **Remote Administrators**: DevOps managing headless systems
- **Automated Workflows**: CI/CD requiring privileged operations

### Two Operating Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Hanging** | Wait for approval with timeout | Interactive agent sessions |
| **SSR** | Print sign request and exit | Long async workflows, offline signing |

### Workflow Overview

```
Hanging Mode:                          SSR Mode:
Agent → rsudo reboot                   Agent → rsudo --ssr reboot
      → Server → Approver                    → Print SSR token
      ← Approval ←                           ... time passes ...
      → Execute                        Agent → rsudo --signed <token>
                                             → Execute
```

---

## 2. Architecture

### Components

```
┌───────────────┐     ┌──────────────────┐     ┌────────────────┐
│  rsudo CLI    │────▶│  Approval Server │◀────│ Approver UI    │
│  (on host)    │     │  (external)      │     │ (IDE/GTK/Web)  │
└───────────────┘     └──────────────────┘     └────────────────┘
```

| Component | Purpose |
|-----------|---------|
| **rsudo CLI** | Client on target host, requests approval, executes commands |
| **Approval Server** | Central server, routes requests, stores approvals |
| **Approver UI** | IDE plugin, GTK tray, or web dashboard for quick approve/reject |

### Communication

- **MVP Transport**: HTTP/REST (client ↔ server)
- **Approver Connection**: WebSocket for real-time push (server ↔ UI)
- **Future Transports**: gRPC, Unix socket (pluggable design)

### Data Flow - Hanging Mode

```mermaid
sequenceDiagram
    participant A as rsudo CLI
    participant S as Approval Server
    participant U as Approver UI
    
    A->>S: POST /requests - command, nonce, sig
    S->>U: WebSocket push - new request
    U->>S: POST /approve - request_id, signature
    S->>A: Response - approved, exec signature
    A->>A: Verify signature, execute command
```

---

## 3. Security Model

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Unauthorized requests | Client onboarding + key registration |
| Replay attacks | Nonce + timestamp + expiration |
| MITM | TLS + message-level signatures |
| Privilege escalation | Respect local sudoers config |
| Environment injection | Sanitize env vars when running as root |
| Forged privileged invocation | Transaction ID binding between phases |

### Privilege Execution

rsudo uses `sudo` with `NOPASSWD` for privilege escalation. The binary runs unprivileged for approval, then re-invokes itself with elevated privileges to execute the approved command.

**Two-Phase Execution:**

```
Phase 1 (unprivileged):          Phase 2 (privileged):
rsudo reboot                     RSUDO_TXN=<id> sudo rsudo reboot
  → Request approval               → Detect RSUDO_TXN env var
  → Receive signed approval        → Lookup transaction by RSUDO_TXN
  → Store approval + transaction   → Verify command matches approval
  → Exec with RSUDO_TXN env var    → Re-validate approval signature
                                   → Execute target command as root
```

**Re-invocation rationale**: The unprivileged phase handles network I/O and cryptographic validation without root access. Only after approval is verified does rsudo escalate privileges via sudo for actual command execution.

**Command in re-invocation**: The actual command is passed to the privileged phase for audit visibility (appears in logs, `ps`, etc.). rsudo verifies the command matches the approved transaction before execution.

**Phase detection**: Presence of `RSUDO_TXN` env var indicates privileged phase. Transaction details (including original user) are retrieved from stored approval data.

**Transaction ID**: A cryptographically random ID passed via `RSUDO_TXN` env var binds the two phases. The unprivileged phase stores the approval with this ID; the privileged phase retrieves and re-validates it. This prevents attackers from forging privileged invocations.

**Sudoers configuration** (`/etc/sudoers.d/rsudo`):

```bash
# RHEL/Fedora/CentOS (wheel group)
%wheel ALL=(ALL) NOPASSWD: /usr/bin/rsudo

# Debian/Ubuntu (sudo group)
%sudo ALL=(ALL) NOPASSWD: /usr/bin/rsudo
```

**Security guarantees:**
- Approval signature re-validated in privileged phase (prevents TOCTOU attacks)
- Environment variables sanitized before executing target command
- Audit logging to `/var/log/rsudo/audit.log` and syslog

### Cryptography

- **Algorithm**: Ed25519 (primary)
- **Keys**: Client keypair, Approver keypair, Server keypair

### Key Management

```bash
# Client onboarding (one-time)
rsudo init                    # Generate client keypair
rsudo register <server-url>   # Register public key with server

# Approver setup
rsudo-server approver add <pubkey>
```

### Client Onboarding

Each rsudo instance must be registered with the approval server before use. This binds:
- Client public key
- Hostname
- Allowed sudoers permissions (optional sync)

### Replay Prevention

```
Request = {command, nonce, timestamp, client_sig}
- Nonce: UUID v4 (unique per request)  
- Timestamp: Must be within ±5 min of server time
- Server caches seen nonces for 24h
```

### Sudoers Respect

rsudo must not grant more permissions than the user's local sudoers config allows. Options:
1. Execute via actual `sudo` after approval
2. Sync sudoers rules to server during onboarding

---

## 4. CLI Interface

### Primary Commands

```bash
# Execute with approval (hanging mode)
rsudo <command>
rsudo reboot
rsudo apt install nginx

# SSR mode (async)
rsudo --ssr <command>          # Output: SSR token to stdout
rsudo --signed <token>         # Execute with signed token

# Output to file
rsudo --ssr --output req.ssr <command>
```

### Management Commands

```bash
rsudo init                     # Generate client keys
rsudo register <server>        # Register with approval server
rsudo status                   # Show pending requests
rsudo config show              # Display configuration
rsudo config set <key> <val>   # Update config
```

### Options

```
-t, --timeout <SEC>    Approval timeout (default: 300)
-v, --verbose          Verbose output
-q, --quiet            Suppress output
--ssr                  SSR mode (exit with token)
--signed <TOKEN>       Execute signed request
--output <FILE>        Write SSR token to file
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command executed successfully |
| 1 | Command returned non-zero |
| 2 | Request rejected |
| 3 | Timeout |
| 4-7 | Config/network/auth errors |

---

## 5. Approval Workflow

### Request Payload

```json
{
  "request_id": "uuid",
  "command": "reboot",
  "arguments": [],
  "hostname": "server-01",
  "username": "agent",
  "timestamp": "2025-12-13T00:20:00Z",
  "expires_at": "2025-12-13T00:25:00Z",
  "nonce": "base64...",
  "client_signature": "base64..."
}
```

### Approver Interfaces (Priority Order)

1. **IDE Plugin** (VS Code, JetBrains) - Popup notification, one-click approve
2. **GTK Tray App** - System tray notifications, quick action
3. **Web Dashboard** - Fallback, full request details
4. **API** - For custom integrations

### Approver Pre-Authentication

Approver authenticates once with the server (session/token). When requests arrive:
- Push notification appears instantly
- Single click to approve/reject
- No re-authentication required

### Approval Response

```json
{
  "request_id": "uuid",
  "decision": "approved",
  "approver_pubkey": "base64...",
  "approver_signature": "base64...",
  "timestamp": "2025-12-13T00:21:00Z"
}
```

### SSR Token Format

```
-----BEGIN RSUDO REQUEST-----
Version: 1
Command: reboot
Hostname: server-01
Expires: 2025-12-14T00:00:00Z
Nonce: abc123...
Signature: def456...
-----END RSUDO REQUEST-----
```

When signed:
```
-----BEGIN RSUDO SIGNED REQUEST-----
...original fields...
Approver: ghi789...
ApproverSig: jkl012...
-----END RSUDO SIGNED REQUEST-----
```

### Timeout Handling

| Event | Time | Action |
|-------|------|--------|
| Request submitted | T+0 | Push to approver |
| Timeout | T+5min | Return error to client |

---

## 6. Configuration

### Configuration Model

rsudo uses layered configuration with three sources:

| Config | Location | Purpose | Permissions |
|--------|----------|---------|-------------|
| **System** | `/etc/rsudo/config.toml` | Server URL, CA certs, policy, audit | `root:root 644` |
| **Drop-in** | `/etc/rsudo.d/*.toml` | Additional system config (automation-friendly) | `root:root 644` |
| **User** | `~/.config/rsudo/config.toml` | Client keys, personal preferences | User-owned |

**Merging order** (later overrides earlier):
1. `/etc/rsudo/config.toml` (base)
2. `/etc/rsudo.d/*.toml` (alphabetical order)
3. `~/.config/rsudo/config.toml` (user)

**Merging rules:**
- System config provides defaults
- Drop-in configs extend/override system settings (useful for config management tools)
- User config can override non-security settings
- **Security-critical fields** (server URL, policy, CA certs) cannot be overridden by user config

### System Config (`/etc/rsudo/config.toml`)

```toml
[server]
url = "https://rsudo.example.com"    # Cannot be overridden
ca_cert = "/etc/rsudo/ca.crt"

[policy]
allowed_commands = ["*"]             # Cannot be overridden
require_tty = false

[audit]
log_file = "/var/log/rsudo/audit.log"
syslog = true
```

### User Config (`~/.config/rsudo/config.toml`)

```toml
[client]
key_file = "~/.config/rsudo/client.key"

[request]
default_timeout = 300
```

### Server Config (`/etc/rsudo-server/config.toml`)

```toml
[server]
bind = "0.0.0.0:8443"

[tls]
cert = "/etc/rsudo/server.crt"
key = "/etc/rsudo/server.key"

[requests]
default_timeout = 300
max_timeout = 3600

[audit]
log_file = "/var/log/rsudo/audit.log"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `RSUDO_SERVER` | Server URL |
| `RSUDO_TIMEOUT` | Request timeout |
| `RSUDO_KEY_FILE` | Client key path |

---

## 7. Platform & Deployment

### Target Platforms

| Platform | Support |
|----------|---------|
| Linux x86_64 | Primary |
| Linux aarch64 | Primary |
| macOS | Secondary |

### Dependencies

```toml
# Key Rust dependencies
tokio = "1"           # Async runtime
reqwest = "0.11"      # HTTP client
ring = "0.17"         # Cryptography
clap = "4"            # CLI parsing
serde = "1"           # Serialization
```

### Installation

```bash
# From source
cargo install rsudo

# Debian/Ubuntu
sudo apt install ./rsudo_*.deb

# RHEL/Fedora/CentOS
sudo dnf install ./rsudo-*.rpm

# Alpine Linux
sudo apk add ./rsudo-*.apk

# Arch Linux (AUR)
yay -S rsudo

# Nix
nix profile install nixpkgs#rsudo

# macOS (Homebrew)
brew install rsudo/tap/rsudo
```

Packages handle:
- Binary installation to `/usr/bin/rsudo` (Linux) or package-specific prefix with correct ownership
- Sudoers configuration in `/etc/sudoers.d/rsudo`
- System config directory `/etc/rsudo/` and drop-in `/etc/rsudo.d/`
- Audit log directory `/var/log/rsudo/`

### Server Deployment

```yaml
# docker-compose.yml
services:
  rsudo-server:
    image: rsudo/server:latest
    ports:
      - "8443:8443"
    volumes:
      - ./config:/etc/rsudo-server
```

---

## 8. Error Handling

### Failure Modes

| Failure | Recovery |
|---------|----------|
| Network timeout | Retry with backoff (3 attempts) |
| Server unavailable | Clear error, suggest --ssr mode |
| Signature invalid | Re-register client |
| Request expired | User must retry |

### User Feedback

```
$ rsudo reboot

🔐 Requesting approval...
   Request: abc123
   Command: reboot
   Host: server-01

⏳ Waiting for approval (5m timeout)...

✅ Approved by: user@example.com
   Executing...
```

### Error Output

```
$ rsudo dangerous-command

❌ Request rejected
   Reason: Command not in allowed list
```

### Logging

| Level | Use |
|-------|-----|
| error | Failures only |
| info | Request lifecycle |
| debug | Protocol details |

### Audit Events

All requests logged with: request_id, command, client, approver, decision, timestamp

---

## Future Considerations

- Multi-approver quorum
- Hardware key support (FIDO2)
- Policy engine for auto-approve rules
- gRPC transport option

---

*This specification will evolve as implementation progresses.*