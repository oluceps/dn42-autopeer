# Nyaw DN42 Autopeer

Nyaw DN42 Autopeer creates WireGuard interfaces and BIRD peer configurations through an HTTP API.
It uses PostgreSQL as the durable source of peer state.

## Components

- Axum and Tokio serve the API.
- `rtnetlink` creates interfaces, assigns link-local addresses, and sets interfaces up.
- `wireguard-control` applies WireGuard keys, endpoints, listen ports, and peers.
- Askama renders BIRD configuration files.
- PostgreSQL stores desired peer state, operation state, listen ports, and authentication nonces.
- nftables admits the UDP listen ports that PostgreSQL assigns to active peers.
- `utoipa` publishes the OpenAPI specification at `/api-docs/openapi.json`.

## Agent-native peering

Install the bundled [`nyaw-dn42-autopeer` skill](skills/nyaw-dn42-autopeer/SKILL.md) from GitHub:

```bash
npx skills add oluceps/dn42-autopeer
```

Select your coding agent and installation scope when the CLI asks.
The skill reads the live [OpenAPI specification](https://dn42.nyaw.xyz/api-docs/openapi.json), gets a single-use challenge, and prepares the signed request.
Supply your ASN, peer name, public endpoint, and the path to a registered maintainer signing key.
The agent can generate a WireGuard key pair locally and return the exact WireGuard and BGP settings from the API.
Private keys stay on your system.

Example prompt:

```text
Use $nyaw-dn42-autopeer to peer AS4242421234 with Nyaw.
Use peer name fra1 for this machine.
My endpoint is 198.51.100.1:51820, and my registered SSH key is ~/.ssh/id_ed25519.
Save the new WireGuard key pair under ./secrets/nyaw-peer/.
```

## Authentication

Each mutation needs a short-lived, single-use challenge.
The server stores each nonce in PostgreSQL.
It atomically deletes the nonce after signature verification and before the registry lookup.
A second request with the same nonce fails.

The signature covers the operation, ASN, peer name, all mutable request fields, nonce, and expiration time.
SSH signatures use the `dn42` namespace.
The service also accepts detached PGP signatures.

The service checks the signing key against a maintainer `auth` attribute in the DN42 Registry.
Registry requests use one shared HTTP client.
They also have a total timeout and a concurrency limit.

### Get a challenge

```bash
curl --request POST \
  --header 'content-type: application/json' \
  --data '{"asn":4242421234}' \
  http://127.0.0.1:8080/api/challenges
```

The response contains `nonce` and `expires_at`.
The expiration value is a Unix timestamp in seconds.
The challenge expires after five minutes.

### Build the signed message

Use these exact UTF-8 formats without a final newline.
The V3 signature covers the endpoint, link-local mode, link-local addresses, and MTU.

An endpoint uses `HOST:PORT`.
The host can be a hostname, an IPv4 address, or a bracketed IPv6 address.
The server converts hostnames to lowercase and writes IPv6 addresses in bracketed form before it builds the signing message.

Create:

```text
DN42-AUTOPEER-V3
operation:create
asn:<asn>
peer_name:<peer-name>
pubkey:<wireguard-public-key>
endpoint:<normalized-HOST:PORT-or-none>
link_local:<auto-or-manual:nyaw-ip:user-ip>
mtu:<default-or-number>
nonce:<nonce>
expires_at:<unix-timestamp>
```

Update:

```text
DN42-AUTOPEER-V3
operation:update
asn:<asn>
peer_name:<peer-name>
pubkey:<wireguard-public-key>
endpoint:<unchanged-or-clear-or-set:normalized-HOST:PORT>
link_local:<auto-or-manual:nyaw-ip:user-ip>
mtu:<unchanged-or-default-or-set:number>
nonce:<nonce>
expires_at:<unix-timestamp>
```

For an update, use `endpoint:unchanged` when the JSON field is absent.
Use `endpoint:clear` when the JSON field is `null`.
Use `endpoint:set:<normalized-HOST:PORT>` when the field contains a value.

Automatic link-local addressing uses `link_local:auto`.
The server assigns `fe80::fcde:3243` to the Nyaw interface.
It assigns `fe80::(ASN >> 16):(ASN & 0xffff)` to the user's interface.

Set `manual_lla` to `true` to choose both addresses.
Then set `local_ll_ip` to the Nyaw address and `remote_ll_ip` to the user's address.
Both values must be distinct IPv6 link-local addresses.
The signing message uses `link_local:manual:<local_ll_ip>:<remote_ll_ip>`.
An update with `manual_lla=false` selects automatic addresses.
It does not retain custom addresses.

For create, an omitted or null MTU selects 1420 and signs `mtu:default`.
For update, an omitted MTU keeps the current value and signs `mtu:unchanged`.
A null MTU resets it to 1420 and signs `mtu:default`.
A numeric MTU replaces it and signs `mtu:set:<value>`.

Delete:

```text
DN42-AUTOPEER-V3
operation:delete
asn:<asn>
peer_name:<peer-name>
nonce:<nonce>
expires_at:<unix-timestamp>
```

Save the message to `request.txt`, then create an SSH signature:

```bash
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n dn42 request.txt
```

Put the complete `request.txt.sig` value in `challenge.signature`.
Also put the registered public key, nonce, and expiration value in `challenge`.

```json
{
  "asn": 4242421234,
  "peer_name": "fra1",
  "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "endpoint": "peer.example.net:51820",
  "manual_lla": false,
  "mtu": 1420,
  "challenge": {
    "auth": "ssh-ed25519 registered-maintainer-key",
    "signature": "-----BEGIN SSH SIGNATURE-----\n...",
    "nonce": "challenge-nonce",
    "expires_at": 1789372800
  }
}
```

## API behavior

### Create a peer

`POST /api/peers` returns HTTP `201 Created`.
The response contains the peer ID, peer name, allocated listen port, link-local addresses, and local public key.

Use a different peer name for each machine under one ASN.
The name must match `[a-z0-9][a-z0-9-]{0,31}`.
Create, update, and delete requests use the ASN and peer name as the public identity.

The preferred listen port is `20000 + (ASN % 10000)`.
The service checks PostgreSQL and existing WireGuard interfaces for conflicts.
It increments the port until it finds an available value, then stores that value.
The endpoint is optional and can contain an IP address or hostname.
The default MTU is 1420.
Automatic link-local addresses follow the mapping above.

### Update a peer

`PATCH /api/peers` can replace the WireGuard public key, endpoint, link-local addresses, and MTU.
The service replaces the complete kernel peer list, so an old public key stops working.
The ASN and peer name select the machine to update.

An absent `endpoint` field keeps the current endpoint.
An `endpoint` value of `null` clears it.
An absent `mtu` field keeps the current MTU.
An `mtu` value of `null` resets it to 1420.
Set `manual_lla=true` and supply both address fields to use custom addresses.
Otherwise, the update selects the automatic addresses.

### Delete a peer

`DELETE /api/peers` removes the BIRD configuration and WireGuard interface.
The ASN and peer name select the machine to delete.
The service only ignores a missing configuration file or interface.
Other removal errors stop the operation.

### Check peer status

`GET /api/peers/{asn}` returns HTTP `200 OK` and a list of all peers under the specified ASN.
The response includes each peer's name, public key, endpoint, link-local addresses, listen port, MTU, status, and creation/update timestamps.
This endpoint does not require authentication and is intended to be used as a public looking glass.

## BIRD policy hooks

Each generated BGP protocol passes the remote ASN and peer ID to two functions in the main BIRD configuration:

```bird
function dn42_import_from_peer(int peer_asn; int peer_id) -> bool {
  # Add machine-specific branches before this default.
  return false;
}

function dn42_export_to_peer(int peer_asn; int peer_id) -> bool {
  # Add machine-specific branches before this default.
  return false;
}

import where dn42_import_from_peer(<remote-asn>, <peer-id>);
export where dn42_export_to_peer(<remote-asn>, <peer-id>);
```

Define both functions before the main configuration includes the generated peer fragments.
Each function must return a Boolean value.
Use the peer ID for machine-specific branches.
Keep a final default branch for new machines.

## State recovery

Each `(ASN, peer name)` pair has one in-process mutation lock.
This lock serializes changes for one machine without blocking another machine under the same ASN.

The database records `provisioning` before an external create or update.
It records `deleting` before an external delete.
On startup, the service completes these operations before it opens the HTTP listener.
It also recreates every active interface and BIRD configuration from PostgreSQL.

The NixOS module enables the nftables firewall backend.
It adds the `autopeer-ports` set to the NixOS input table.
The service rebuilds this set from PostgreSQL after each create or delete.
It also rebuilds the set during startup and every 30 seconds.
This periodic sync repairs the set after an nftables reload.

The systemd service starts after `nftables.service`.
Its executable path includes `pkgs.nftables`, and it retains `CAP_NET_ADMIN` for netlink and nftables changes.

The service writes each BIRD configuration to a temporary file in the target directory.
It flushes and syncs the file before an atomic rename.
If BIRD rejects a reload, the service restores the prior file.

The service configures the local `/64` link-local address on each WireGuard interface.
It also sets an existing interface up during every repair attempt.

## WireGuard AllowedIPs

The generated peer uses `0.0.0.0/0`, `::/0`, and `fe80::/64` as WireGuard `AllowedIPs`.
This setting controls WireGuard address selection.
The service does not install kernel routes for these prefixes.

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `PORT` | HTTP listen port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://dn42-bot@localhost/dn42` |
| `BIRD_CONF_DIR` | BIRD fragment directory | `/var/lib/autopeer` |
| `BIRD_SOCKET` | BIRD control socket | `/run/bird/bird.ctl` |
| `WG_PRIVATE_KEY` | Local WireGuard private key | Required |
| `WG_PUBLIC_KEY` | Matching local WireGuard public key | Required |
| `PUBLIC_ENDPOINT` | Public IP address or host name | `dn42-node.example.com` |
| `LOCAL_ASN` | Local ASN | `4242420291` |
| `REGISTRY_API_URL` | DN42 Registry API base URL | `https://explorer.burble.com/api/registry` |
| `REGISTRY_TIMEOUT_SECS` | Registry connect, read, and total timeout | `10` |
| `REGISTRY_MAX_CONCURRENT` | Maximum concurrent registry checks | `16` |

Startup fails if either WireGuard key is absent or invalid.
Startup also fails if the public key does not match the private key.
The service does not write `DATABASE_URL` to its logs.

## Run locally

Create a WireGuard key pair first:

```bash
wg genkey | tee server.key | wg pubkey > server.pub
```

Export the required values and start the service:

```bash
export DATABASE_URL='postgres://dn42:password@localhost/dn42'
export WG_PRIVATE_KEY="$(<server.key)"
export WG_PUBLIC_KEY="$(<server.pub)"
cargo run
```

Open `http://127.0.0.1:8080/api-docs/openapi.json` for the OpenAPI specification.

