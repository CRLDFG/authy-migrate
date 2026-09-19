# authy-migrate — Revised project brief

Architecture review date: September 19, 2026. English translation of the supplied
French brief, following the user's repository-language preference.

This document replaces the previous prompt and does not certify any previously
generated prototype. It distinguishes source inspection, proposed design, and
required validation. No real Authy account or real Proton import was tested during
the original architecture review.

## Mission

Create the open-source `authy-migrate` project to migrate user-owned TOTP secrets.
Proton Authenticator is the first destination, but the core must not depend
structurally on Proton.

Do not perform real capture, install a certificate, or process real credentials in
Codex, GitHub Actions, or hosted environments. Development, tests, and PRs must use
synthetic data exclusively. The user performs real tests locally after review.

This project is a local converter, optionally with a separate acquisition module,
not a new proxy or password manager.

## Main decisions

1. Build the offline core first, independently of proxies, iOS, and RAM volumes.
2. Plan two inputs: encrypted Twilio exports and voluntary Authy iOS sync capture.
   Capture remains optional and experimental until validated.
3. Demonstrate native encrypted Proton Authenticator output imported through the
   official UI first. Do not require plaintext Ente/TOTP files.
4. Never deliberately write decrypted secrets to files, logs, command arguments,
   or environment variables in the default workflow.
5. Do not promise absence of physical traces in memory, swap, hibernation, caches,
   or crash dumps. Define exactly what the application controls.
6. Distinguish conversion performed, import accepted, codes verified, and cleanup
   confirmed. None proves the next state.

## Findings from the original review

### Proton

The official `protonpass/proton-pass-common` repository at revision
`26412c72370999843806cb7d4ec6a7a54a7a36a1` contains:

- `proton-authenticator/src/entry/password_exporter.rs`: password-protected export/import;
- `proton-authenticator/src/crypto.rs`: authenticated AES-256-GCM encryption;
- `proton-authenticator/src/entry/exporter.rs`: inner serialization/import validation.

Observed v1 envelope fields are `version`, `salt`, and `content`. It uses Argon2id
v0x13, 19 × 1024 KiB memory, two passes, parallelism one, a 32-byte key, a random
16-byte salt, a 12-byte nonce, and AAD `proton.authenticator.export.v1`. Use these
facts to verify interoperability, not invent a variant.

The official iOS importer calls `importFromProtonAuthenticatorWithPassword`.
Plaintext Ente import also exists but must not be the default output.

Source existence does not validate every distributed build. Record actual tested
Proton versions, inspect their published source mapping, and perform a synthetic
application import.

The common Proton repository is GPLv3. Do not copy/link its code and arbitrarily
label the entire project MIT. Record the licensing/reuse decision and preserve
applicable notices. Use standard cryptographic libraries for an interoperable
implementation and test against the reference importer; do not implement
cryptographic primitives yourself.

### Authy acquisition

`valentin-dirken/authy-export` observes sync requests from the official iOS app.
It is not a stable export API guaranteed by Twilio. Credit prior work without
claiming unverified exclusive discovery.

`serbbil/Authy-GDPR-Export-Decryption` and `nick22985/authy-decryptor` describe
processing Twilio data exports. Availability, timing, contents, and completeness
must be checked for each user. Do not claim that every token category must be
provided within a guaranteed deadline.

Do not copy the scripts blindly: the inspected serbbil script uses `input()` for
password entry, prints seeds, and guesses formats. The Valentin script strips
password whitespace, incompletely filters requests, and does not explicitly
preserve all OTP parameters.

### Proxy

The latest stable release returned during the original review was mitmproxy
12.2.3, published May 12, 2026. Recheck releases, security advisories, and the entire
resolved dependency graph before installation or publication.

`allow_hosts` restricts interception by connections/domains. It neither limits the
CA cryptographically nor acts as an egress firewall. Documentation identifies an
exception for explicit HTTP requests in regular/upstream modes.

HTTP path filtering happens after TLS decryption. Do not claim that the proxy
engine can see only the fields extracted by an addon.

## Target architecture

Input A: a Twilio data file whose seeds are still encrypted.

Optional input B: Authy on iPhone → isolated local capture → still-encrypted Authy
records.

Both feed structural validation → local decryption → OTP validation → in-memory
serialization → Proton encryption → atomic publication of the encrypted output
file only.

The file can be imported on a computer or transferred locally to an iPhone. Do not
require Proton on the Mac, a Proton account, or cloud sync. Final import is an
explicit user action in the official application, never direct database mutation.

Use typed objects:

- `EncryptedAuthyRecord`: origin/version, identifier, encryption parameters,
  ciphertext, and necessary metadata;
- `OtpEntry`: OTP type, seed, issuer, label, algorithm, digits, period, and
  validation status.

`otpauth://` URIs are an interoperability format, not the only internal model.
Avoid multiplying seed-bearing strings. Secret objects must not appear in repr,
logs, exceptions, or reports. Account metadata is private even when seeds remain
encrypted.

## First MVP: offline conversion

Develop the core/tests for macOS, Linux, and Windows from the start. Advertise a
platform only after running the corresponding tests.

The first PR must be a restricted compatibility prototype:

1. Inspect official Proton code and pin the inspected references.
2. Describe the format and select standard libraries.
3. Create synthetic TOTP entries, including supported non-default parameters.
4. Generate a native encrypted export without an intermediate plaintext file.
5. Check it with the official importer in a test environment, respecting licenses.
6. Prepare a manual test procedure for the actual Proton app.
7. Demonstrate rejection of incorrect passwords and altered files.
8. Document executed tests and remaining manual checks.

Do not develop the entire MITM module before confirming this compatibility.
Then add Authy CSV/JSON adapters with real parsing. Do not arbitrarily strip CSV
quotes, heuristically join broken seed lines, or silently accept ambiguous formats.

### Cryptography and validation

Use per-record parameters when available. Do not invent missing values. Defaults
are acceptable only when documented for an identified source version and tested.

The Authy backup password and Proton archive password are different secrets. The
archive password is not the Proton account password. Request a strong archive
passphrase without logging it. Do not strip or normalize it without a format rule.

Bound input size, record count, KDF costs, and field lengths. Validate Base64, IV
length, block length, PKCS#7, text encoding, and seed representation. Do not silently
guess Base32, hex, or raw bytes when ambiguous.

Valid CBC padding does not establish authenticity or the correct seed. Local code
checks and target-application confirmation remain essential.

Do not silently convert proprietary Authy, HOTP, or Steam tokens to standard TOTP.
The MVP may reject them with explicit diagnostics. Do not force SHA1/30 seconds
when source parameters are not established.

## Optional iOS module

Keep mitmproxy as the main acquisition candidate; do not reimplement TLS. Install
and run it separately from the offline core. Do not load proxy dependencies for
file-only conversion.

Requirements:

- `mitmdump` without a web UI; no HAR or flow archive;
- isolated configuration, without inherited personal scripts/options;
- sanitize environment variables that enable TLS key logging or code injection;
- interception list anchored to verified hosts and ports;
- consistent CONNECT/SNI/Host checks, rejecting lookalike substitution;
- exact parsed-path, method, and expected content-type checks;
- retain Authy server certificate verification; never `ssl_insecure`;
- strict data and size validation before IPC;
- no application request mutation, rereading, or replay by the addon;
- proxy authentication and network access restriction, without describing Basic
  authentication as network encryption;
- no backup password in the capture process;
- stop and reap the capture process before starting the decryption worker;
- bounded capture window and safe shutdown on errors.

Define the out-of-scope traffic policy explicitly: opaque HTTPS forwarding or a
stricter rejection mode. Such traffic must never be decrypted merely because only
saved fields were filtered. Test actual synthetic TLS connections, not just regexes.

Use a unique CA per session. Distribute only its public certificate to iPhone,
never a PEM containing its private key. The user manually approves and removes
the profile and trust. The Mac cannot verify removal on an unmanaged iPhone.

A verified RAM area can be macOS-specific CA hardening, not a core dependency.
Distinguish unmounting, detaching, and logical disappearance. Check return codes;
never claim complete destruction after failure. Do not resolve a volume solely by
a predictable name or remove/unmount a pre-existing user volume.

## System security and honest limits

Minimize exposure and deliberate plaintext writes. A compromised system,
administrator, screenshot tool, or destination application is outside this guarantee.

Modes 0600/0700 do not defeat every same-user process or administrator. Linux tmpfs
can use swap. Clearing a Python variable does not guarantee removal of bytes/str
copies. Document these limits instead of hiding them behind the word RAM.

Do not invent cryptographic primitives or complex cross-platform machinery solely
to claim zero traces. If stronger memory control becomes a requirement, evaluate
native secret types and controlled erasure; Rust and mlock are not absolute
protection from a compromised host.

## Security and integration tests

At minimum, include the applicable checks:

- independent decryption tests, not only our own encrypt/decrypt round-trip;
- synthetic import through the reference parser and actual identified app builds;
- incorrect passwords, significant whitespace, Unicode, and modified ciphertext;
- missing/excessive KDF parameters, invalid IVs, ambiguous Base32/hex;
- non-default OTP parameters, duplicates, partial failures, shared labels;
- no synthetic seeds in logs or exception messages;
- no deliberate plaintext writes or network connections by the core;
- atomic output, no overwrite without explicit choice, permissions/ACLs;
- capture: actual TLS to allowed/disallowed hosts, rejection of invalid server
  certificates, client restrictions, shutdown on SIGINT/exception/timeout;
- cleanup limitations under SIGKILL, crashes, and power loss;
- refusal to report migration complete while records are invalid or unverified.

Review the native Proton error path: inspected import errors can format whole
entries including their URI, and the iOS service may log error descriptions at
debug level. Do not claim an observed leak without a test. Investigate with
synthetic data, validate output before import, and never ask users for raw logs.

## UX and publication

Proposed workflow: choose source → inspect export → convert offline → create
encrypted file → import into Proton → compare codes → verify critical sign-ins →
finish.

Retain Authy and recovery methods until important accounts are verified. Importing
seeds does not revoke old copies. Suspected exposure requires rotating the seed
at the relevant service.

A request-data button may prepare a Twilio request template, but must not send
email or collect credentials without explicit authorization.

Initial deliverables: README, architecture, threat model, protocol and sources,
limitations, roadmap, tests, security policy, and attribution.

No centralized user-export collection, upload form, telemetry, or automatic crash
uploads. Pin and verify dependencies and maintain a security-update policy.
Hashes do not establish software safety. Use least-privilege CI, branches/PRs,
dependency and secret scanning, then traceable releases after tests and review.

Do not claim audited, risk-free, or compatible with all Authy data based solely on
an agent review.

## Roadmap

0. Documented and tested native encrypted Proton export compatibility.
1. macOS/Linux/Windows offline converter with Twilio export adapter.
2. Optional isolated iOS/macOS acquisition, tested on exact versions.
3. Other capture hosts after separate validation.
4. Additional destinations; Android acquisition only with a justified tested method.

Do not delay Windows/Linux conversion for temporary CA storage that file conversion
does not use.

## Starting sources to recheck

- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/password_exporter.rs
- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/crypto.rs
- https://github.com/protonpass/proton-pass-common/blob/26412c72370999843806cb7d4ec6a7a54a7a36a1/proton-authenticator/src/entry/exporter.rs
- https://github.com/protonpass/ios-authenticator/blob/main/LocalPackages/DataLayer/Sources/DataLayer/Services/ImportingService.swift
- https://github.com/protonpass/proton-pass-common/blob/main/LICENSE
- https://proton.me/support/import-2fa-codes
- https://github.com/valentin-dirken/authy-export/blob/074d46069f827264b58c0ee0737bdb9fe0d07da5/authy_export.py
- https://github.com/serbbil/Authy-GDPR-Export-Decryption
- https://github.com/nick22985/authy-decryptor
- https://www.twilio.com/en-us/legal/privacy
- https://github.com/mitmproxy/mitmproxy/releases/latest
- https://docs.mitmproxy.org/stable/howto/ignore-domains/
- https://docs.mitmproxy.org/stable/concepts/options/
- https://docs.mitmproxy.org/stable/concepts/certificates/
- https://docs.kernel.org/filesystems/tmpfs.html
- https://cryptography.io/en/latest/limitations/

## Requested next action

Start with a short ADR comparing encrypted Proton export and plaintext on a RAM
disk, followed by a minimal PR proving interoperability using synthetic data.
Present proven results, assumptions, and remaining manual validation clearly before
expanding scope. Do not start with the full proxy implementation.
