# Nyaw DN42 Autopeer

An automated peering system for the DN42 network, built with Rust. This project uses strong type safety, kernel-level Netlink communication, and stateless authentication. It aligns with the NixOS declarative philosophy.

## Architecture and Technology Stack

- **Core**: Rust (Axum and Tokio).
- **L3 Tunneling (WireGuard)**: The system bypasses `wg-quick` and bash scripts. It speaks directly to the Linux kernel through `rtnetlink` and `wireguard-control`. This creates memory-only interfaces for fast roaming.
- **L4 Routing (BIRD)**: The system uses an isolated `dn42_v6` routing table to keep the internal network (HORTUS) secure. It generates configuration fragments and applies them through direct UNIX Domain Socket communication (`/run/bird/bird.ctl`). This removes the need for external binaries like `birdc`.
- **Persistence**: Built on PostgreSQL (with `sqlx`), integrated with NixOS services.
- **API Documentation**: Code-first OpenAPI specification generation with `utoipa`, which serves a Swagger UI.
- **Frontend Ready**: Built-in CORS support (`tower-http`) lets Single Page Applications (for example, SolidJS or React) make cross-origin requests.

## Core Design Principles

### 1. Stateless Cryptographic Authentication (SSH and PGP)
The database does not store passwords, API tokens, or secrets. Authentication connects cryptographically to the public DN42 Registry in a stateless way.
- **Anti-Replay Signatures**: A user must sign a deterministic payload to declare their intent (for example, `ASN:<asn>|PUBKEY:<wg_pubkey>` or `ASN:<asn>|DELETE`). They use their SSH private key (for example, `ssh-keygen -Y sign`) or PGP key (`gpg --clear-sign`).
- **Registry Integration**: When the backend receives a request, it cryptographically verifies the SSH or PGP signature. Then it fetches the user's `mntner` object from the DN42 Registry API (`explorer.burble.com`). If the public key matches the `auth` attribute of the ASN's maintainer, the system authorizes the request.
- **Benefit**: Mathematical security and zero-setup authentication. The DN42 Whois Registry acts as the Single Source of Truth (SSoT).

### 2. Config Generation: Strong Typing and Anti-Injection
The system does not use string concatenation (`format!`). It uses the **Askama** template engine with precompiled BIRD configuration fragments.
- **Defense-in-Depth**: A custom `Escaper` intercepts BIRD syntax (`\n`, `"`, `\`). This stops malicious users from executing BGP routing policy injection attacks through fields like `description`.

### 3. Parse, Do Not Validate
The system uses the Newtype pattern (for example, `WgPubKey`) with `serde` deserialization. The Axum framework intercepts invalid data (for example, malformed Base64 WireGuard keys) at the edge and returns HTTP 400. Dirty data does not enter the memory state (`DashMap`) or the database.

### 4. Deterministic Port Mapping
Local listening ports default to `20000 + (ASN % 10000)`.
- **Robustness**: The system enforces dual-layer conflict detection (DB-level and OS-level) to stop port collisions and duplicate tunnels for the same ASN. On conflict, it increments and saves the final port.

## Workflows

- **Crash-Loop Resilient Cold Start**: On startup, the daemon connects to PostgreSQL and retrieves all active peers. It rebuilds the environment: it recreates WireGuard interfaces through Netlink, it renders all BIRD configs, and it pushes a soft reconfiguration through the BIRD UNIX socket.
- **Create Peer (`POST /api/peers`)**: The system validates the request, calculates link-local IPs and ports, provisions Netlink, renders the Askama template, hot-reloads BIRD, saves to PG, and updates the DashMap cache. It returns `wg_config` and `bgp_config` JSON payloads.
- **Zero-Downtime Roaming (`PATCH /api/peers/{asn}`)**: When a user's public endpoint changes, the backend calls `DeviceUpdate` through Netlink to update the endpoint IP in the kernel. It does not touch the interface state or the BIRD configuration. BGP sessions roam without dropping a Keepalive packet.

## NixOS Deployment

In a Nix declarative environment, the system keeps permissions and dependencies to a minimum:

- **Passwordless Database**: The system uses PostgreSQL Unix Domain Sockets and peer authentication. The backend process connects with its OS-level identity, requiring zero password environment variables.
- **Rootless Execution**: The system runs as a standard Systemd Service (`User = "dn42-bot"`). It only requires `AmbientCapabilities = [ "CAP_NET_ADMIN" ]` to change network interfaces.
- **Minimal Dependencies**: With direct Netlink integration and raw UNIX socket communication, the host system does not need `wireguard-tools`, `iproute2`, or `birdc`. The only requirements are a pure statically-linked Rust binary and access to the BIRD control socket.

## Environment Variables

The application reads these environment variables.

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `PORT` | The port the Axum web server listens on. | `8080` |
| `DATABASE_URL` | Connection string for PostgreSQL (supports Unix sockets). | `postgres://dummy:dummy@localhost/dummy` |
| `BIRD_CONF_DIR` | Directory where the system generates BIRD configuration fragments. | `/var/lib/autopeer` |
| `BIRD_SOCKET` | Path to the BIRD daemon's UNIX control socket. | `/run/bird/bird.ctl` |
| `WG_PRIVATE_KEY` | Your server's WireGuard private key (Base64). Used for interface creation. | (Dummy Private Key) |
| `WG_PUBLIC_KEY` | Your server's WireGuard public key (Base64). Sent back to peers in the JSON response. | `dummy_pubkey_replace_me=` |
| `PUBLIC_ENDPOINT` | Your server's public IP or domain name. Sent back to peers in the JSON response (for example, `dn42.nyaw.xyz`). | `dn42-node.example.com` |
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
