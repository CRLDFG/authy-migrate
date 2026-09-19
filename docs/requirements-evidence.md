# Requirements and evidence

Scope: the revised brief's offline MVP plus the optional capture module explicitly
requested with synthetic tests only. This is an experimental source/PR delivery,
not a stable release or a real-account migration. Future roadmap items do not
constitute advertised support.

Final implementation evidence: [CI run 35442151338](https://github.com/CRLDFG/authy-migrate/actions/runs/35442151338)
at `08063027362597bd37443622c7228f7a8ee974dd` passed all jobs. Offline tests:
macOS/Linux 106 passed with three Windows-only skips; Windows 107 passed with two
POSIX-only skips. The separate macOS capture suite passed 38 tests. Python
runtime/build/tooling and both Rust audits passed; capture auditing reported the
explicit unreleased-engine skip described below. Only documentation changes
follow that code commit.

| Requirement | Evidence and limits |
|---|---|
| ADR before proxy development; encrypted Proton default | ADR-001.md; PR #1 predates capture; no plaintext destination/export path |
| Standard crypto and pinned official format | protocol.md; cryptography; both pinned Rust importer harnesses |
| Actual identified Proton build, non-default fields, wrong password and tampering | validation.md records Proton 1.4.3 (6) import and independent code comparisons |
| Destination-independent typed model | core.py contains OTP model/validation; proton.py owns destination serialization |
| Authy CSV/JSON parsing, source parameters, no guesses | authy.py and authy-input.md; independent Node fixtures; malformed/ambiguous/missing-field tests |
| Bounds, exact passwords, CBC limitations, unsupported tokens | test_authy.py; explicit encoding/OTP choices; malleability test; fixed diagnostics; no partial archive |
| Windows/Linux/macOS offline conversion | adapter-validation.md and cross-platform CI; actual Windows DACL inspection and POSIX permission/no-clobber tests |
| Separate optional engine, no personal configuration or backup password | capture/session.py and worker.py; fresh private configuration; whitelisted environment; isolated interpreter |
| Exact CONNECT/SNI/Host, method/path/type; explicit out-of-scope policy | capture/policy.py and actual TLS tests; strict rejection; no implicit live endpoint |
| Upstream verification, authentication, client restrictions | Actual synthetic TLS rejects invalid certificates, bad proxy credentials, substituted SNI, disallowed clients/hosts |
| Strict encrypted IPC, no request mutation/replay | Worker parser before IPC, parent validation, body-equality tests, size/count/KDF bounds; no HAR/flow writer or replay configured |
| Stop/reap before decryption; timeout, signal, exception handling | Separate decrypt_worker.py; workflow tests assert capture exit before passwords; timeout/SIGINT/SIGTERM/SIGKILL/invalid-record/cleanup-failure tests |
| Unique CA, public-only distribution, honest cleanup | Distinct-CA and PEM-content tests; 0700/0600 checks; fresh-directory-only cleanup; WORKFLOW.md explicitly leaves iPhone approval/removal manual |
| No deliberate plaintext seed writes or logs | Pure offline path tests; session-file inspection; encrypted worker output; fixed error handling; no claim about all OS traces |
| Native Proton error path investigation | Both harnesses exercise a malformed public URI and detect its seed in returned errors without printing them; no iOS log leak claimed |
| Conversion/import/code/cleanup states kept separate | CLI messages, expected-count gate, structural-only model, manual-test.md and WORKFLOW.md; no “migration complete” success claim |
| User flow, private local review, recovery and rotation guidance | README, authy-input.md, manual-test.md, capture/WORKFLOW.md; no email, upload service, or telemetry |
| Open-source licensing, notices, security policy, update gates | LICENSE, NOTICE.md, SECURITY.md, roadmap.md; stable release requires further review |
| Pinned/audited dependencies and least-privilege CI | Runtime/build/dev hash locks, Cargo locks, capture archive/artifact locks; read-only CI; limited repository secret-pattern gate |
| English code and GitHub work | Repository prose, identifiers/comments, commits, and PR descriptions use English; Unicode interoperability fixture data is intentional |

The capture dependency audit has one explicit limitation: pip-audit cannot assess
the pinned unreleased mitmproxy version. Its resolved dependencies and bootstrap
tools are audited; upstream advisories were inspected separately. No independent
security audit, guaranteed source-schema coverage, stable binary release,
real-device capture compatibility, physical erasure, or verified iPhone cleanup
is claimed. Those limitations are not replaced by a green test count.
