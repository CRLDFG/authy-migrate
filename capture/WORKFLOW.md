# Experimental local iPhone workflow

For the current device preparation, see [Authy 28.6.1 readiness](IPHONE-28.6.1.md).

Only synthetic TLS and public records have been tested. This is not a validated
Authy iPhone release/profile. Do not use a real account in Codex, CI, or a hosted
environment. A user may evaluate real compatibility locally after reviewing the
code and identifying the actual application version and endpoint independently.

## Before capture

Use the separate environments described in `README.md`. Capture currently requires
macOS arm64. The offline converter remains independent and supports its tested
Windows/Linux/macOS platforms.

Prepare a profile from reviewed source information. No real host, version, or
full path is supplied by default. This example is deliberately nonfunctional:

```json
{
  "version": 1,
  "host": "verified-host.example.invalid",
  "port": 443,
  "path": "/REPLACE_WITH_VERIFIED_PATH",
  "app_version": "REPLACE_WITH_IDENTIFIED_VERSION",
  "source_reference": "REPLACE_WITH_REVIEWED_SOURCE_REFERENCE"
}
```

The only accepted operation is POST with URL-encoded form data. CONNECT authority,
TLS SNI, and HTTP Host must match the profile. Other hosts and plaintext HTTP are
rejected before an upstream connection; other paths on the allowed host are
rejected after TLS decryption. The engine necessarily sees the allowed TLS
connection, not just the extracted fields. The profile is a user declaration,
not authentication or independent proof of provenance.

Determine the exact local Mac and iPhone IP addresses and expected token count.
Use a trusted private network; Basic proxy authentication does not encrypt its
credentials on the network. The listener binds only the specified local address,
and the addon accepts only the specified client IP, with eight concurrent clients
at most. This is application enforcement, not an OS firewall or CA name constraint.
Existing firewall rules may need user review; this application does not alter them.

Choose three new paths in a private directory outside the repository. Existing
paths are never overwritten. Example addresses below must be replaced with the
actual local addresses; the directory must already exist:

Create the chosen output directory with owner-only permissions (`mkdir -m 700`),
or select an existing directory with those permissions. First append `--check`
to the command below. This checks the local profile, addresses, capture Python
executable, output collisions, and directory permissions without starting a
proxy, creating files, or requesting passwords. A passing check does not verify
the endpoint against Authy, dependency integrity, or network reachability.
Remove `--check` only when ready for the reviewed local session.

```sh
.venv/bin/python -I -B capture/cli.py \
  --profile /your/private/directory/profile.json \
  --capture-python .capture-venv/bin/python \
  --listen-ip 192.168.50.10 --client-ip 192.168.50.20 \
  --expected-records 4 --timeout 180 \
  --certificate /your/private/directory/session-public.pem \
  --parameters /your/private/directory/parameters.json \
  /your/private/directory/migration.proton.json
```

## During and after capture

1. Enter a strong, temporary proxy password at the hidden prompt. It is neither
   the Authy backup password nor a Proton password. The proxy username is
   `authy-migrate`; the application prints its address and randomly assigned port.
2. Transfer only the exported public certificate to the iPhone through a locally
   chosen method. Never transfer files from the private session configuration
   directory. Manually approve the profile and certificate trust, and configure
   the HTTP proxy with the displayed address/port and chosen credentials.
   The application does not install certificates, open a certificate web server,
   change device settings, or require Proton cloud sync.
3. Perform only a reviewed sync operation for the identified Authy version.
   This project does not recommend blindly disabling backups. Press Enter when
   the expected records have arrived. The window is bounded to 1–300 seconds;
   timeout is failure, not successful completion. Ctrl+C cancels.
4. Capture stops and is reaped before conversion. A count mismatch, failed
   in-scope request, invalid record, repeated source identifier, or failed cleanup
   blocks conversion. A repeated sync is not counted as another account; distinct
   account identifiers may still share labels or seeds. Remove the
   iPhone proxy setting, certificate profile, and trust manually. The Mac cannot
   verify those changes on an unmanaged iPhone.
5. The interactive terminal displays account labels for local row review only.
   Do not share this terminal output or raw application logs. Complete the
   generated parameter template using established source information. It contains
   no seeds or account names and binds the exact captured bytes and profile.
   Explicitly choose TOTP and Base32/hex/raw encoding; supply missing OTP settings.
   Changing the captured records or provenance invalidates that binding.
6. After the parameters validate, enter the Authy backup password and a separate
   strong Proton archive passphrase (and confirmation). Passwords preserve exact
   whitespace/Unicode. The offline worker receives them over stdin after capture
   is reaped; no password is passed in process arguments or environment variables.
   It returns only the encrypted Proton archive. No capture record archive or
   decrypted seed file is deliberately created.
7. Import the archive explicitly in the official Proton application, compare
   codes locally, and verify important sign-ins. CBC structural validation,
   matching counts, and an accepted import do not prove the seeds are correct.
   Keep Authy and recovery methods until verification is complete. Importing does
   not revoke old copies; suspected exposure requires seed rotation at the service.

The public certificate, parameter file, and encrypted archive remain at the chosen
paths. The parent removes only its newly created private session directory. It
does not claim physical erasure, delete unrelated files, or verify iPhone cleanup.
If the parent is killed, the machine crashes, or cleanup fails, CA files may
remain. Python memory copies, swap, dumps, administrators, and compromised hosts
are outside the application's deliberate-write guarantee. No RAM volume is used.
