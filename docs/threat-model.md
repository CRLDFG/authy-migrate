# Architecture, threats, and limitations

Current path: public synthetic fixtures → validated OtpEntry objects → in-memory
JSON → Argon2id/AES-GCM → encrypted archive → atomic publication → manual import.
The `structural-only` status means neither verified codes nor completed migration.
EncryptedAuthyRecord and source adapters follow the compatibility gate; they must
not be replaced by URI-only models or format-detection heuristics.

Assets include seeds, passwords, account labels, and issuers. OTP objects have
redacted repr output. The CLI suppresses exception details. A Python caller can
still inspect fields, traceback locals, and memory: this API is not an enclave.
No logger is registered for the Proton reference library.

The application controls its deliberate writes and messages. It cannot control
swap, hibernation, crash dumps, internal bytes/str copies, screenshots, a compromised
host, administrators, or Proton's subsequent handling. Mode 0600 does not protect
against every same-user process; inherited ACLs may require review. Use a trusted
private directory without additional ACL grants. The tests are not an exhaustive
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
