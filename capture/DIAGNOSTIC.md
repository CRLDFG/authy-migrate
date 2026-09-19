# Local iPhone diagnostic before migration

This user-run diagnostic addresses the missing Authy 28.6.1 protocol evidence.
It is not a migration, a successful sync, or proof of complete compatibility.
Development tests use synthetic loopback TLS only. Do not run real traffic in
Codex or CI. The proxy engine can see plaintext within the allowed TLS connection.

The diagnostic permits only `api.authy.com:443`, matching CONNECT, SNI, and Host,
and only HTTPS form POSTs to `/json/users/<numeric-id>/authenticator_tokens/update`.
Unlike capture, it can recognize this route before the account identifier is
known and notice a query string. It never forwards HTTP requests upstream.
Matching requests receive HTTP 409; other requests receive HTTP 403. Authy may
show a network error until the proxy is removed. Opening Authy normally may not
produce an update request; no observation is an inconclusive result.

## Run from your own local terminal

Keep Authy backups enabled. Do not sign out, reinstall the app, delete entries,
or toggle backups to force a sync. Keep the Mac and iPhone on a trusted private
Wi-Fi network. Read their current Wi-Fi IPv4 addresses; replace both placeholders.
The destination must be a new directory outside the repository. The command
creates it with mode 0700 and files with mode 0600. Use a new directory per run.

```sh
cd /Users/cyrildufoing/Documents/ChatGPT/authy-to-proton
.venv/bin/python -I -B capture/diagnose.py \
  --capture-python .capture-venv/bin/python \
  --mac-ip MAC_WIFI_IPV4 --iphone-ip IPHONE_WIFI_IPV4 \
  "$HOME/Authy-diagnostic-01"
```

1. Enter a temporary proxy password at the hidden prompt. No Authy or Proton
   password is requested.
2. The terminal displays a random proxy port and the public certificate path.
   Transfer only `session-public.pem` locally to the iPhone, for example using
   AirDrop. Approve the profile under Settings > General > VPN & Device
   Management; enable its trust under General > About > Certificate Trust
   Settings. Do not transfer anything from the private worker directory.
3. In Wi-Fi > the network's information button > Configure Proxy, choose Manual,
   use the printed Mac IP/port, enable authentication, and use username
   `authy-migrate` with the temporary password.
4. Open Authy normally, then return to the Mac terminal and press Enter to stop.
   Setup and observation together are limited to five minutes. Ctrl+C cancels.
   A timeout produces failure automatically, without requiring Enter, not a
   successful diagnostic.
5. Immediately set the Wi-Fi proxy to Off and remove the session certificate
   profile/trust. Reopen Authy and verify normal operation. The Mac cannot
   verify iPhone cleanup.

## Results and next action

The terminal also prints fixed connection counters and failure flags, including
on a normal worker timeout or protocol error. These contain no hostnames, paths,
request contents, or account identifiers:

- `client_connections`: accepted connections from the configured iPhone IP.
- `authy_tunnels`: CONNECT requests accepted for the permitted Authy endpoint.
- `tls_requests`: HTTP request headers seen inside those matching TLS tunnels.
- `matching_requests`: complete requests matching the diagnostic route/filter.
- `timed_out` and `network_error`: whether the deadline or a flow error occurred.

Zero client connections means the configured client was not observed. Connections
without tunnels can indicate a proxy authentication or host mismatch. Tunnels
without TLS requests can indicate a TLS/trust problem or simply no HTTP request.
TLS requests without matches mean traffic was seen but did not match the route,
method, or content-type filter. These are diagnostic clues, not definitive causes.
Both the counters and flags may be shared. Timeout or errors still prevent
publishing an observation file; counters do not prove a successful sync.

After worker shutdown and private CA cleanup, the command writes
`observation.private.json`. It contains the first matching account-specific path
and seven booleans. Do not share this file: its path contains an account ID.
No body, query value, account label, seed, IV, salt, or authentication value is
exported. Unknown field names are not exported either.

The terminal displays only these fixed boolean facts:

- `form_valid`: bounded URL-encoded form parsing succeeded.
- `has_query`: a query was present; its value is discarded.
- `has_iv` and `has_kdf`: the expected field names were present, not necessarily valid.
- `duplicate_fields` and `unknown_fields`: schema mismatches were detected.
- `record_accepted`: the current strict parser accepted the first form and no
  query was present. This is structural validation only; it does not validate
  decryption, all accounts, or the server's acceptance of a sync.

Only the seven boolean values may be shared for troubleshooting. If no request
is observed, report that outcome only. Do not send raw logs or expand the proxy
scope. A missing sync trigger remains unresolved; this diagnostic deliberately
does not supply an unverified backup-toggle procedure. Subsequent capture still
requires review of the local exact profile and a validated sync operation.

The public certificate and private observation remain in the chosen directory.
Remove them locally when no longer needed. Private CA cleanup is logical deletion,
not physical erasure; crashes or forced termination can leave files. Dependency
limitations in [README.md](README.md) still apply.
