# authy-migrate

A **synthetic-data-only** compatibility prototype for encrypted Proton
Authenticator exports. It does not yet migrate real Authy exports.

The offline core creates four public demonstration TOTP entries in memory and
protects them using Proton's native format. No proxy, certificate, Proton account,
cloud service, upload, or telemetry is required. Never register these public seeds
on real accounts.

## Try it locally

Python 3.12+ with Argon2id support in cryptography; Rust 1.92+ for the independent
reference checks. Installation needs Internet access; conversion does not.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps .
.venv/bin/authy-migrate demo demo.proton.json
```

The command asks twice for an archive passphrase of at least 16 characters. Use a
long, unpredictable passphrase; length alone does not ensure strength. This is
**not** your Proton account password or Authy backup password. Whitespace and
Unicode are preserved exactly. Password arguments and environment variables are
not supported. An interactive terminal is required. Choose a new destination
inside a trusted private directory.

POSIX output uses an encrypted 0600 temporary file, fsync, and atomic hard-link
publication without overwriting an existing destination. Windows: the core is
testable, but file publication is refused until its ACL handling is implemented
and verified. This is not full Windows support. The core and both official
importers pass macOS/Linux/Windows CI. Application import was verified on this Mac
with Proton 1.4.3 (6). These results do not establish real Authy migration support.

## Verify

```sh
.venv/bin/python -m pip install -r requirements-dev.lock
cargo build --locked --manifest-path reference/Cargo.toml
cargo build --locked --manifest-path reference/legacy/Cargo.toml
.venv/bin/python -m pytest -q
```

A missing Rust binary explicitly skips its reference check locally and fails CI.
CI builds both binaries before testing. Each importer receives only the encrypted
archive through stdin and knows the public synthetic passphrase. The harness is
not suitable for real account data or raw user diagnostics.

Read the [validation evidence](docs/validation.md), [protocol and sources](docs/protocol.md),
[architecture decision](docs/ADR-001.md), [threat model](docs/threat-model.md),
[manual test procedure](docs/manual-test.md), [roadmap](docs/roadmap.md),
[project brief](docs/project-brief.md), [attribution](NOTICE.md), and
[security policy](SECURITY.md).

GPL-3.0-only. No independent security audit or universal compatibility is claimed.
