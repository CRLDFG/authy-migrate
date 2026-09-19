# Preparing an iPhone running Authy 28.6.1

Prepared on September 19, 2026. The user reports Authy 28.6.1 installed on
their iPhone with an existing account, running iOS 27.0. The user confirms
backups are enabled and the backup password is known; the password was not
requested or supplied. These are user-reported facts, not device observations.
This is a preparation record, not a successful compatibility result.

The user does not have an independent test account. Live compatibility remains
a user-run local trial with real account data, not a synthetic-only test. The
automated development tests continue to use public synthetic data exclusively.

## Current readiness

- The offline converter and synthetic capture workflow are implemented.
- Proton Authenticator 1.4.3 (build 6) on the Mac has passed the documented
  public synthetic import test.
- The capture environment exists separately from the offline environment.
- No Authy 28.6.1 request schema, sync trigger, or TLS behavior has been verified.
- No live profile is provided and no certificate or proxy needs installing yet.

Adding a synthetic token to an existing Authy account does not isolate its
traffic. A sync may send other entries. A second device signed into the same
account is not a synthetic-only test environment either. Keep the existing
account intact; do not sign out, reinstall Authy, or disable backups to prepare
this experiment. Synthetic-only app validation requires an independently
isolated test account containing only public test entries. Otherwise the next
app trial is a real-data trial, to be performed by the user locally after review.

## Information needed before an app trial

Record the following locally. Share only non-sensitive readiness answers:

1. iOS version and confirmation of the Authy version.
2. Whether Authy backups are already enabled, and whether the backup password
   is known. Never put that password in chat, a profile, or a command argument.
3. Whether an independent synthetic-only Authy test account is available.
4. A trusted private Wi-Fi network shared by the Mac and iPhone. Obtain both
   current local IP addresses immediately before the eventual session.
5. The expected count of supported TOTP entries; verify each intended entry
   locally. Do not send account labels, QR codes, or recovery codes.

## Compatibility work still required

A [user-run diagnostic](DIAGNOSTIC.md) can now observe the first matching update
route and report fixed schema booleans, without forwarding it or exporting its
body. It has synthetic tests only. It does not force a sync or establish full
compatibility; opening the app may produce no matching request.

Public evidence provides a candidate route, not a verified 28.6.1 profile:

- [The author's Authy protocol investigation (2023)](https://velvetcache.org/2023/05/12/the-authy-backup-system/)
  describes `api.authy.com` and the account-specific path
  `/json/users/<account-id>/authenticator_tokens/update` for the desktop client.
  Its example has transport/metadata fields such as `api_key` and `locale`.
- [The pinned iOS acquisition script](https://github.com/valentin-dirken/authy-export/blob/074d46069f827264b58c0ee0737bdb9fe0d07da5/authy_export.py)
  matches a path substring; that does not prove the complete endpoint or this
  app version's behavior.
- [The App Store listing](https://apps.apple.com/au/app/twilio-authy/id494168017)
  lists version 28.6.1, but does not document its wire protocol.

Before producing a runnable live profile, establish the exact endpoint, query
handling, form schema (including IV and KDF rounds), and a non-destructive sync
trigger for this version. The current policy rejects query strings and unknown
form fields. It accepts bounded historical `api_key`, `locale`,
`password_timestamp`, and `logo` metadata, forwarding the original request
unchanged upstream while excluding those fields from record IPC. This does not
make historical request examples drop-in compatible: IV and KDF rounds remain
mandatory and the current iPhone schema remains unverified.
Do not relax these checks, guess cryptographic parameters, or copy an example
account identifier into a live profile. Any schema change needs a reviewed
allowlist and synthetic regression tests; authentication fields must not enter
the record IPC payload or logs. Keep the real account-specific path local.

## Eventual local session, after compatibility review

Follow [WORKFLOW.md](WORKFLOW.md) only once its explicit profile is established.
The sequence is:

1. Create fresh output paths in a private directory outside the repository.
   Run the command from WORKFLOW.md with `--check` first. This only checks local
   configuration and does not establish compatibility with Authy 28.6.1.
2. Start the bounded session in a local interactive terminal. Enter a separate
   temporary proxy password. The session prints its random port and exports
   only its public certificate.
3. Transfer that public certificate locally to the iPhone. Install the profile
   and explicitly enable certificate trust. Configure the Wi-Fi HTTP proxy using
   the displayed Mac address, port, username, and temporary password.
4. Perform the reviewed sync operation and stop capture within the session
   deadline. If setup consumes the deadline, cancel, remove the old profile,
   and begin a fresh session; do not reuse the old certificate.
5. Remove the proxy and certificate. The worker must stop and its private
   session directory must be cleaned before the password/conversion phase.
6. Review captured entries and fill in known OTP parameters locally. Enter the
   Authy backup password and a different archive passphrase at hidden prompts.
7. Import the encrypted archive from inside Proton Authenticator's import flow.
   Double-clicking the JSON file in Finder is not an import.
8. Compare codes across multiple intervals and verify sign-ins. Keep Authy and
   recovery methods until every intended account is verified.

Apple documents certificate trust under Settings > General > About > Certificate
Trust Settings in [its certificate-trust guide](https://support.apple.com/en-ug/102390).
Installed profiles are managed under Settings > General > VPN & Device Management
in [its iPhone profile guide](https://support.apple.com/guide/iphone/install-or-remove-configuration-profiles-iph6c493b19/ios).
After the session, set the Wi-Fi HTTP proxy to Off, remove the session profile,
and confirm its trust entry is gone. The Mac cannot verify this cleanup.

The capture engine remains an unreleased pinned revision; see
[dependency limitations](README.md#dependency-selection-september-19-2026).
No real capture, device configuration change, or backup setting change was
performed while preparing this document.
