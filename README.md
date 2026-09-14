# Nyaw DN42 Autopeer

Nyaw DN42 Autopeer creates WireGuard interfaces and BIRD peer configurations through an HTTP API.
It uses PostgreSQL as the durable source of peer state.

## Components

- Axum and Tokio serve the API.
- `rtnetlink` creates interfaces, assigns link-local addresses, and sets interfaces up.
- `wireguard-control` applies WireGuard keys, endpoints, listen ports, and peers.
- Askama renders BIRD configuration files.
- PostgreSQL stores desired peer state, operation state, listen ports, and authentication nonces.
- `utoipa` publishes OpenAPI documentation through Swagger UI.

## Authentication

Each mutation needs a short-lived, single-use challenge.
The server stores each nonce in PostgreSQL.
It atomically deletes the nonce after signature verification and before the registry lookup.
A second request with the same nonce fails.

The signature covers the operation, ASN, all mutable request fields, nonce, and expiration time.
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
The server normalizes each endpoint through `SocketAddr` before it builds the message.

Create:

```text
DN42-AUTOPEER-V1
operation:create
asn:<asn>
pubkey:<wireguard-public-key>
endpoint:<normalized-IP:PORT-or-none>
nonce:<nonce>
expires_at:<unix-timestamp>
```

Update with a new endpoint:

```text
DN42-AUTOPEER-V1
operation:update
asn:<asn>
pubkey:<wireguard-public-key>
endpoint:set:<normalized-IP:PORT>
nonce:<nonce>
expires_at:<unix-timestamp>
```

For an update, use `endpoint:unchanged` when the JSON field is absent.
Use `endpoint:clear` when the JSON field is `null`.

Delete:

```text
DN42-AUTOPEER-V1
operation:delete
asn:<asn>
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
  "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "endpoint": "198.51.100.1:51820",
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
The response contains the allocated listen port, link-local addresses, and local public key.

The preferred listen port is `20000 + (ASN % 10000)`.
The service checks PostgreSQL and existing WireGuard interfaces for conflicts.
It increments the port until it finds an available value, then stores that value.

### Update a peer

`PATCH /api/peers` can replace the WireGuard public key and endpoint.
The service replaces the complete kernel peer list, so an old public key stops working.

An absent `endpoint` field keeps the current endpoint.
An `endpoint` value of `null` clears it.

### Delete a peer

`DELETE /api/peers` removes the BIRD configuration and WireGuard interface.
The service only ignores a missing configuration file or interface.
Other removal errors stop the operation.

## State recovery

Each ASN has one in-process mutation lock.
This lock serializes create, update, and delete operations for that ASN.

The database records `provisioning` before an external create or update.
It records `deleting` before an external delete.
On startup, the service completes these operations before it opens the HTTP listener.
It also recreates every active interface and BIRD configuration from PostgreSQL.

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

Open `http://127.0.0.1:8080/swagger-ui/` for the interactive API documentation.
