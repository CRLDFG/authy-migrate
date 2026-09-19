# Security policy

Version 0.0.1 is experimental and tested with synthetic data only. No stable
version is supported. Never submit exports, seeds, passwords, or raw diagnostics
to issues, PRs, or hosted environments.

Use the repository's private GitHub vulnerability reporting channel if enabled.
Otherwise arrange a private channel with the maintainer before sending sensitive
details. Do not invent a contact address or publish an exploit report publicly.

Before merging or releasing: run Python and Rust audits, inspect results and
licenses, update lockfiles through PRs, and rerun independent compatibility checks.
Hashes pin artifacts; they do not prove software safety. CI uses only synthetic
data and read-only repository permissions. No automatic release publishing,
crash uploads, or telemetry.
