# authy-migrate

An **experimental offline converter** from encrypted Authy exports to Proton
Authenticator's native encrypted format. Development and CI use synthetic data
exclusively; no real Twilio export has been certified.

The CSV/JSON adapters reject missing or contradictory parameters. Proton output
has been verified with two official importers and Proton 1.4.3 (6) on a Mac.
No proxy, certificate, Proton account, or cloud service is required.

Read the [conversion workflow and supported formats](docs/authy-input.md).
The conversion path never deliberately writes decrypted seeds in plaintext.
Users must verify source parameters and resulting codes locally.

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

POSIX output publishes an encrypted 0600 file without overwriting an existing
file. The [Windows layer](docs/windows-output.md) creates a protected DACL before
writing, then publishes without replacement. Its dedicated Windows CI tests must
pass before this new layer is described as validated. Universal Authy export
compatibility is not claimed.

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
