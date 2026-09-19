# Architecture, threats, and limitations

Current path: explicitly selected encrypted CSV/JSON → EncryptedAuthyRecord →
explicit source-bound parameters → PBKDF2/AES-CBC → validated OtpEntry objects →
in-memory JSON → Argon2id/AES-GCM → encrypted archive → publication → manual import.
The `structural-only` status means neither verified codes nor completed migration.
Only public synthetic fixtures have exercised the source adapters. CBC provides
no authentication: modified inputs or wrong passwords can yield plausible seeds.
No URI-only model or format-detection heuristic substitutes for explicit metadata.

Assets include seeds, passwords, account labels, and issuers. OTP objects have
redacted repr output. The CLI suppresses exception details. A Python caller can
still inspect fields, traceback locals, and memory: this API is not an enclave.
No logger is registered for the Proton reference library.
The reference harness exercises a malformed public URI and confirms that both
pinned importers include its seed in a returned error string. That string is never
printed. This establishes native error contents, not an observed iOS log leak.

The application controls its deliberate writes and messages. It cannot control
swap, hibernation, crash dumps, internal bytes/str copies, screenshots, a compromised
host, administrators, or Proton's subsequent handling. Mode 0600 does not protect
against every same-user process; inherited ACLs may require review. Use a trusted
private directory without additional ACL grants. Windows publication creates and
verifies a protected current-user DACL before writing (see `windows-output.md`).
The tests are not an exhaustive
system-level proof of no network or file activity.

Publication rejects existing destinations, including symbolic links. Ordinary
failures remove the encrypted temporary file; SIGKILL or power loss can leave it.
fsync covers file contents; directory-entry durability after power loss is not
guaranteed. Cleanup failure is an overall failure even if the target exists. The
application never announces complete destruction. Existing user files are not
removed. Physical erasure of an exported file is not guaranteed.

Tests use public seeds only. The core contains no network code. Installation,
builds, and audits use public network sources separately from conversion. No
certificate installation or real traffic capture is performed.

## Optional capture boundary

The macOS arm64 workflow uses three processes: interactive coordinator, isolated
mitmdump engine, and a later offline decryption worker. Capture receives only its
endpoint/IP restrictions, temporary proxy credentials, deadline, and private
configuration path. The coordinator starts the decryption process only after
capture has exited, been reaped, and its private session directory removed.
Passwords go over stdin, never process arguments or environment variables.

The captured envelope retains a declared endpoint/app-version/source reference
and pinned engine revision. These fields are validated and fingerprinted, not
authenticated. A matching record count does not prove account completeness or
correct seeds. Repeated source identifiers cause failure rather than silent
deduplication; separate identifiers can legitimately share labels and seeds.

The policy rejects out-of-scope CONNECT and plaintext HTTP before upstream
connections. SNI must match before the client handshake; Host, path, method, and
content type are checked inside the allowed TLS connection. The engine can see
that connection's decrypted HTTP traffic. This is neither a cryptographically
restricted CA nor an OS egress firewall. Upstream certificate verification stays
enabled. Basic proxy authentication requires a trusted network; it is not network
encryption. Only an explicit client IP is accepted and concurrent clients are
bounded. See `../capture/WORKFLOW.md` for the user-operated flow.

The coordinator deliberately writes a public certificate, a seed-free parameter
template, and the encrypted result. The engine writes its private CA configuration
under a fresh private directory. No HAR, flow archive, decrypted seed file, replay,
or web UI is enabled. Account labels appear only for local interactive row review;
users must not publish the terminal output. Worker stderr and traffic logs are
suppressed. Tests inspect bounded session files and process outputs, not every OS
cache or memory copy. The iPhone's manual trust removal cannot be verified by the
Mac. Parent SIGKILL, crashes, or cleanup failure can leave private CA material.
