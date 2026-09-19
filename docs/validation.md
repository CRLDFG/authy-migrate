# Validation evidence — September 19, 2026

Local environment: macOS arm64, Python 3.14.2, cryptography 50.0.1, Rust/Cargo 1.92.0.
Proton importers: core 2.1.0 and 1.3.0, pinned in the two Cargo manifests.

Both `cargo build --locked` commands succeed. `python -m pytest -q`: **26 passed**,
including two independent official-importer harnesses.

The harness checks four complete entries: seed bytes, Unicode labels, issuers,
SHA1/SHA256/SHA512, 6/8 digits, 15/30/60-second periods, distinct UUIDs for duplicates
and shared labels, and zero partial-import errors. Official importers reject
incorrect passwords, removed password whitespace, and altered ciphertext.

Other tests cover randomness, absence of seeds in the outer envelope, NFC/NFD
password differences, validation before encryption, OTP limits, redacted messages,
blocked open/socket calls in the tested core path, mode 0600, atomic no-clobber
publication, symlink refusal, error cleanup, and noninteractive terminal refusal.
The open/socket checks are focused regression tests, not an exhaustive syscall
observation.

An initial reference-check failure exposed a typo in the expected SHA512 Base32
fixture. The expected value was corrected from the public seed bytes; the export
format was not changed to accommodate the test.

Python runtime/tooling audits reported no known vulnerabilities. Rust core 2.1.0
harness audit: 192 dependencies; core 1.3.0 harness audit: 187 dependencies; no
vulnerabilities reported against the inspected RustSec database of 1251 advisories.
Lockfiles record exact versions and available hashes.

The [code CI run at 405fc13](https://github.com/CRLDFG/authy-migrate/actions/runs/35438043845)
passed: macOS **26**, Linux **26**, Windows **23 passed / 3 POSIX tests skipped**.
Both official importers were compiled and tested. Installed CLI checks, audits,
and the limited accidental-secret hygiene check passed.

## Distributed application test

Proton Authenticator **1.4.3 (6)**, iPad application on macOS **26.6.2 arm64**.
The initially empty app received `demo.proton.json` through Import → Proton
Authenticator. No direct database access or real account data was used. The public
Unicode passphrase retained two leading and two trailing spaces. The application
confirmed **Successfully imported 4 items**.

UI screenshots were observed in the session, not exported. Codes were compared
against `scripts/synthetic_codes.py`, which checks three RFC 6238 vectors first:

| Calculation time UTC | SHA1, entries 1/4 | SHA256, entry 2 | SHA512, entry 3 | UI observation |
|---|---|---|---|---|
| 10:44:36 | 102129 | 63934933 | 13765148 | All match before the SHA256 boundary |
| 10:44:50 | 102129 | 75336974 | 13765148 | All match after the SHA256 rollover |

Unicode metadata, a duplicate, and a separate entry sharing the same label were
visible. The 15/30/60-second periods matched UI countdowns. Both Rust harnesses
also compare the complete internal parameters and seeds.

Negative UI tests: an incorrect password produced **Wrong password**. A copy with
one ciphertext bit flipped produced the same error despite the correct password.
After cancellation, only the original four demonstration entries remained. This
message does not establish that the password caused the failure: Proton groups
these authentication failures under the same error.

| State | Result |
|---|---|
| Synthetic conversion | Completed |
| Official application import, 1.4.3 (6) | Accepted, four entries |
| Synthetic codes | Verified across two intervals |
| Cleanup | Not performed: four test entries and two encrypted archives retained locally |
| Real Authy migration | Not implemented or tested |

Keeping the fixtures available for review is not a cleanup or erasure claim.
Archives are ignored by Git. No application security or synchronization setting
was changed.

Not established: iOS logging behavior, real Authy migration, Twilio export
compatibility, TLS capture safety, Windows output ACLs, cleanup after power loss,
physical erasure, or reproducible App Store binary/source identity. No real account
was processed. Application results do not establish compatibility with other builds.
