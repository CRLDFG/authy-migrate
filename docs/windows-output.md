# Windows file publication

The conversion core imports no Windows-specific module. Only Windows file
publication loads the Win32 APIs. This layer receives no decrypted seeds.

`CreateFileW` creates a random temporary filename in the destination directory,
using `CREATE_NEW` and a protected security descriptor with one FullControl grant
for the current user's SID, no inherited DACL entries, and no inheritable handle.
`GetSecurityInfo` reads the persisted DACL back before the first byte is written.
Publication fails if the filesystem cannot enforce that ACL. UNC paths and
alternate data streams are rejected.

Both requested and persisted descriptors use Windows' SDDL serializer for
comparison, including its [SID aliases](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings).
The comparison requires the protected DACL and the same single grant; only the
automatic-inheritance bookkeeping flag may differ.

After `WriteFile` and `FlushFileBuffers`, the handle is closed. `MoveFileExW`
renames within the same directory using `MOVEFILE_WRITE_THROUGH`, without
`MOVEFILE_REPLACE_EXISTING` or cross-volume copy fallback. An existing destination
is never overwritten. Ordinary failures remove only the temporary file created
by this call. Crashes or forced termination can leave an encrypted temporary file.

Windows CI independently checks the DACL using `Get-Acl`/.NET: inheritance is
blocked, exactly one explicit rule grants FullControl to the current user. Tests
also verify file contents, refusal to overwrite, and cleanup after failed ACL
verification. These checks passed on an actual Windows runner; see
[the recorded CI evidence](adapter-validation.md).

This does not protect against the current user, an administrator taking ownership,
backup privileges, or a compromised host. Use a trusted private local directory.
Filesystems without usable DACLs are unsupported. No physical erasure or absolute
power-loss resilience is promised.

Inspected Microsoft sources:
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [File security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [Access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
