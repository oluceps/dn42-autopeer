# Nyaw DN42 Autopeer

A high-performance, highly-engineered, and strictly declarative automated peering system for the DN42 network, built with Rust. This project abandons traditional script-gluing approaches in favor of strong type safety, kernel-level Netlink communication, and stateless authentication. It perfectly aligns with the NixOS declarative philosophy.

## Architecture & Technology Stack

- **Core**: Rust (Axum + Tokio)
- **L3 Tunneling (WireGuard)**: Completely bypasses `wg-quick` and bash scripts. Interacts directly with the Linux kernel via `rtnetlink` / `wireguard-control` for millisecond-level, memory-only interface creation and seamless roaming.
- **L4 Routing (BIRD)**: Utilizes an isolated `dn42_v6` routing table to guarantee the absolute security of the internal network (HORTUS). Dynamically generates configuration fragments and applies them via `birdc configure soft`.
- **Persistence**: Built on PostgreSQL (via `sqlx`), seamlessly integrated with NixOS services.
- **API Documentation**: Code-first OpenAPI specification generation using `utoipa`, serving a fully interactive Swagger UI.

## Core Design Principles

### 1. Stateless Cryptographic Authentication (SSH-SIG)
No passwords, API tokens, or secrets are stored in the database. Authentication is cryptographically bound to the public DN42 Registry in a completely stateless manner.
- **Anti-Replay Signatures**: Users must sign a deterministic payload declaring their exact intent (e.g., `ASN:<asn>|PUBKEY:<wg_pubkey>` or `ASN:<asn>|DELETE`) using their `ssh-ed25519` private key via standard `ssh-keygen -Y sign`.
- **Registry Integration**: Upon receiving a request, the backend cryptographically verifies the SSH signature, then dynamically fetches the user's `mntner` object from the DN42 Registry API (`explorer.burble.com`). If the provided SSH public key exactly matches the `auth` attribute of the ASN's maintainer, the request is authorized.
- **Benefit**: Absolute mathematical security and zero-setup authentication. The DN42 Whois Registry acts as the Single Source of Truth (SSoT).

### 2. Config Generation: Strong Typing & Anti-Injection
Abandons error-prone string concatenation (`format!`). Employs the **Askama** template engine with precompiled BIRD configuration fragments.
- **Defense-in-Depth**: Implements a custom `Escaper` specifically designed for BIRD syntax (intercepting `\n`, `"`, `\`, etc.). This systematically prevents malicious users from executing BGP routing policy injection attacks via fields like `description`.

### 3. "Parse, Don't Validate"
Embraces the Newtype pattern (e.g., `WgPubKey`). Combined with `serde` deserialization, invalid data (such as malformed 44-character Base64 WireGuard keys) is intercepted at the edge by the Axum framework (returning HTTP 400). Dirty data is cryptographically guaranteed to never enter the memory state (`DashMap`) or the database.

### 4. Deterministic Port Mapping
Local listening ports deterministically default to `20000 + (ASN % 10000)` following community conventions.
- **Robustness**: Enforces strict dual-layer (DB-level and OS-level) conflict detection to prevent port collisions or duplicate tunnels for the same ASN. On conflict, it gracefully increments and persists the finalized port.

## Workflows

- **Crash-Loop Resilient Cold Start**: On startup, the daemon connects to PostgreSQL, retrieves all `Active` peers, and synchronously rebuilds the environment: recreates WG interfaces via Netlink, re-renders all BIRD configs, and issues a single `birdc configure soft`.
- **Create Peer (`POST /api/peers`)**: Validates the request -> Calculates link-local IPs and ports -> Provisions Netlink -> Renders Askama template -> Hot-reloads BIRD -> Persists to PG -> Updates DashMap cache. Returns easily copyable `wg_config` and `bgp_config` JSON payloads.
- **Zero-Downtime Roaming (`PATCH /api/peers/{asn}`)**: When a user's public endpoint changes, the backend directly calls `DeviceUpdate` via Netlink to update the endpoint IP in the kernel. **It does not touch the interface state or the BIRD configuration.** BGP sessions roam flawlessly without dropping a single Keepalive packet.

## NixOS Deployment Paradigm

In a Nix declarative environment, permissions and dependencies are minimized to the absolute limit:

- **Passwordless Database**: Utilizes PostgreSQL Unix Domain Sockets + **Peer Authentication**. The backend process connects using its OS-level identity, requiring zero password environment variables.
- **Rootless Execution**: Deployed as a standard Systemd Service (`User = "dn42-bot"`). It only requires `AmbientCapabilities = [ "CAP_NET_ADMIN" ]` to manipulate network interfaces.
- **Minimal Dependencies**: Thanks to direct Netlink integration, the host system does not need `wireguard-tools` or `iproute2`. The only requirements are a pure statically-linked Rust binary and the BIRD daemon.

## Environment Variables

The application is highly configurable via environment variables. This fits perfectly with NixOS `EnvironmentFile` or Docker `.env` patterns.

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `PORT` | The port the Axum web server listens on. | `8080` |
| `DATABASE_URL` | Connection string for PostgreSQL (supports Unix sockets). | `postgres://dummy:dummy@localhost/dummy` |
| `BIRD_CONF_DIR` | Directory where BIRD configuration fragments will be generated. | `/var/lib/autopeer` |
| `WG_PRIVATE_KEY` | Your server's WireGuard private key (Base64). Used for interface creation. | (Dummy Private Key) |
| `WG_PUBLIC_KEY` | Your server's WireGuard public key (Base64). Sent back to peers in the JSON response. | `dummy_pubkey_replace_me=` |
| `PUBLIC_ENDPOINT` | Your server's public IP or domain name. Sent back to peers in the JSON response (e.g., `dn42.nyaw.xyz`). | `dn42-node.example.com` |
| `LOCAL_ASN` | Your server's Autonomous System Number. | `4242420291` |
| `REGISTRY_API_URL` | The endpoint for DN42 Registry querying (to verify PGP/SSH keys). | `https://explorer.burble.com/api/registry` |

## Getting Started

Start the web server locally with:

```bash
# Example with inline environment variables
PORT=9341 DATABASE_URL="postgres://dn42:password@localhost/dn42" cargo run
```

Once running, access the interactive API documentation (Swagger UI) at:
http://localhost:9341/swagger-ui/
