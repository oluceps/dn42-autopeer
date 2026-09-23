---
name: nyaw-dn42-autopeer
description: Manage DN42 peering through the Nyaw service at dn42.nyaw.xyz. Use only for create, update, or delete requests to the Nyaw API. Do not use for other DN42 autopeer services.
---

# Nyaw DN42 Autopeer

This skill works only with the Nyaw service at `https://dn42.nyaw.xyz`.
Do not use its request formats with another autopeer service.

## Protect keys

- Never ask the user to paste a private SSH, PGP, or WireGuard key.
- Accept a signing-key path or use the local key agent.
- If you generate a WireGuard key pair, save the private key with mode `0600`.
- Never put private key material in a request, log, or chat reply.

## Collect inputs

Get the operation, ASN, peer name, and registered maintainer authentication method.
Use a different peer name for each machine under one ASN.
Use the same peer name for later update or delete requests.
The peer name must match `[a-z0-9][a-z0-9-]{0,31}`.
For create or update, also get a WireGuard public key, endpoint choice, link-local mode, and MTU choice.
If the user has no WireGuard key pair, generate and save one locally.
An endpoint must use `HOST:PORT`.
The host can be a hostname, an IPv4 address, or a bracketed IPv6 address.
Convert a hostname to lowercase before signing it.

Automatic link-local addressing assigns `fe80::fcde:3243` to Nyaw.
It assigns `fe80::(ASN >> 16):(ASN & 0xffff)` to the user.
For manual addressing, get two distinct IPv6 link-local addresses.
The API fields use the server viewpoint: `local_ll_ip` is Nyaw and `remote_ll_ip` is the user.

The default MTU is 1420.
For update, distinguish an omitted MTU from a JSON `null` and a numeric value.

## Run the workflow

1. Read `https://dn42.nyaw.xyz/api-docs/openapi.json` for the current request and response schemas.
2. Prepare and normalize all mutation fields, including the peer name, before you request a challenge.
3. Send `POST /api/challenges` with the ASN.
4. Build the exact signing message below without a final newline.
5. Sign the message with a key from the ASN maintainer's DN42 Registry `auth` attribute.
6. Send the mutation before `expires_at`, with the public authentication key and complete signature.
7. Apply or report the returned WireGuard and BGP settings according to the user's requested scope.

For an SSH key, use the `dn42` signature namespace:

```bash
printf %s "$MESSAGE" > dn42-autopeer-request.txt
ssh-keygen -Y sign -f <registered-key-path> -n dn42 dn42-autopeer-request.txt
```

For PGP, create an armored detached signature and send the complete armored public key as `challenge.auth`.
Use a JSON serializer when you add the multiline public key and signature to the request.

## Build the signing message

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

For create, omit the JSON `endpoint` field to use `endpoint:none`.
Use `manual_lla=false` and omit both address fields to use `link_local:auto`.
Use `manual_lla=true` with both address fields to use the manual form.
An omitted or null MTU selects 1420 and uses `mtu:default`.

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

Omit the JSON `endpoint` field to keep it unchanged.
Set that field to `null` to clear it.
Supply a value to use `endpoint:set:<normalized-HOST:PORT>`.

Use `manual_lla=false` to select automatic addresses during an update.
This does not retain prior custom addresses.
Use `manual_lla=true` with both address fields to replace them.

Omit the JSON `mtu` field to keep it unchanged.
Set that field to `null` to reset it to 1420.
Supply a number to use `mtu:set:<value>`.

Delete:

```text
DN42-AUTOPEER-V3
operation:delete
asn:<asn>
peer_name:<peer-name>
nonce:<nonce>
expires_at:<unix-timestamp>
```

Check:

No authentication or signing message is required. Simply issue a `GET /api/peers/{asn}` request to fetch a list of peers and their detailed status for the given ASN.

## Handle the result

Treat each challenge as single-use, including after a failed mutation.
If a challenge expires or fails, request a new challenge and create a new signature.
After create, preserve the generated WireGuard private key and show its path.
After each mutation, report the returned peer ID and peer name.
Use the server response as the source for its endpoint, public key, link address, and BGP neighbor.
Do not perform local network changes unless the user includes that system or configuration repository in scope.
