# Offline adapter validation

The source profiles are experimental and community-documented. No real Authy or
Twilio export was used. The separate application evidence in `validation.md`
establishes the Proton output format on the identified Mac application; it does
not establish compatibility with every source export.

## Local evidence, September 19, 2026

- macOS: 93 tests passed; three Windows-only tests skipped.
- Both CSV and JSON fixtures decrypt to all four expected public demo entries.
- Both resulting encrypted archives pass both pinned official Proton importers.
- Node's independent PBKDF2/AES-CBC fixture generator reproduces the committed
  source and parameter files byte for byte. Git attributes preserve those bytes
  across platforms because the parameter files bind the exact source hash.
- Installed version 0.1.0 from the built wheel; the CLI help lists `demo`,
  `inspect`, and `convert` successfully.
- Repository hygiene checks pass; no dependency changes were needed.

Negative tests cover malformed and missing fields, work limits, unsupported token
types, password whitespace and Unicode normalization differences, source-bound
parameter mismatches, ambiguous encodings, and failure after earlier records have
decrypted. The last case produces no partial archive.

A CBC malleability test changes the recovered seed while preserving valid
structure. This is an explicit demonstration that `structural-only` is not
authentication or code verification.

## Platform evidence

The first CI run found a Windows DACL comparison failure before any output bytes
were written. The runner's administrator SID can serialize as an SDDL alias; the
fix canonicalizes both descriptors through Windows while retaining the same
protected single-user grant. Independent PowerShell/.NET checks inspect the
published file's actual SID, rights, and inheritance status.

[CI run 35440226967](https://github.com/CRLDFG/authy-migrate/actions/runs/35440226967)
passed at code commit `2ef56696a9ffc1874222f9acfb9e15add4288790`:

| Platform | Passed | Skipped |
|---|---:|---:|
| macOS | 93 | 3 Windows-only tests |
| Ubuntu | 93 | 3 Windows-only tests |
| Windows | 94 | 2 POSIX-only tests |

The Windows run verifies the actual protected DACL, encrypted contents, no-clobber
publication, failure cleanup, and both CLI workflows. The independent ACL test
uses the runner's PowerShell 7; invoking legacy Windows PowerShell from that
environment failed to load the ACL check successfully.

The same run passed Python dependency auditing, both Rust lockfile audits
(192 and 187 dependencies), and repository hygiene. These checks found no known
dependency vulnerabilities at execution time; they are not an independent
security review. No physical erasure, real-export, or capture-host test is claimed.
