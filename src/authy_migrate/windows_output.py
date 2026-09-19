"""Windows-only publication with a protected current-user DACL at creation.

No dependency or DLL is loaded by non-Windows conversion. This is access control,
not protection from administrators, the current user, or a compromised machine.
"""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import secrets
from .core import ValidationError


class SecurityAttributes(C.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


class SidAndAttributes(C.Structure):
    _fields_ = [("sid", W.LPVOID), ("attributes", W.DWORD)]


class WindowsAPI:
    def __init__(self):
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.security = C.WinDLL("advapi32", use_last_error=True)
        specs = [
            (self.kernel, "GetCurrentProcess", [], W.HANDLE),
            (self.kernel, "CloseHandle", [W.HANDLE], W.BOOL),
            (self.kernel, "LocalFree", [W.LPVOID], W.LPVOID),
            (self.kernel, "CreateFileW", [W.LPCWSTR, W.DWORD, W.DWORD, C.POINTER(SecurityAttributes), W.DWORD, W.DWORD, W.HANDLE], W.HANDLE),
            (self.kernel, "WriteFile", [W.HANDLE, W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID], W.BOOL),
            (self.kernel, "FlushFileBuffers", [W.HANDLE], W.BOOL),
            (self.kernel, "MoveFileExW", [W.LPCWSTR, W.LPCWSTR, W.DWORD], W.BOOL),
            (self.security, "OpenProcessToken", [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL),
            (self.security, "GetTokenInformation", [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
            (self.security, "ConvertSidToStringSidW", [W.LPVOID, C.POINTER(W.LPWSTR)], W.BOOL),
            (self.security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [W.LPCWSTR, W.DWORD, C.POINTER(W.LPVOID), C.POINTER(W.DWORD)], W.BOOL),
            (self.security, "GetSecurityInfo", [W.HANDLE, C.c_int, W.DWORD, W.LPVOID, W.LPVOID, W.LPVOID, W.LPVOID, C.POINTER(W.LPVOID)], W.DWORD),
            (self.security, "ConvertSecurityDescriptorToStringSecurityDescriptorW", [W.LPVOID, W.DWORD, W.DWORD, C.POINTER(W.LPWSTR), C.POINTER(W.DWORD)], W.BOOL),
        ]
        for library, name, arguments, result in specs:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result

    def check(self, success):
        if not success:
            # Windows system strings can contain paths; return a fixed diagnostic.
            raise OSError("Windows secure output operation failed.")

    def user_sid(self):
        token = W.HANDLE()
        self.check(self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8, C.byref(token)))  # TOKEN_QUERY
        try:
            size = W.DWORD()
            self.security.GetTokenInformation(token, 1, None, 0, C.byref(size))  # TokenUser
            if not 1 <= size.value <= 65536:
                raise OSError("Unable to determine current Windows user.")
            buffer = C.create_string_buffer(size.value)
            self.check(self.security.GetTokenInformation(token, 1, buffer, size, C.byref(size)))
            sid = C.cast(buffer, C.POINTER(SidAndAttributes)).contents.sid
            string = W.LPWSTR()
            self.check(self.security.ConvertSidToStringSidW(sid, C.byref(string)))
            try:
                return string.value
            finally:
                self.kernel.LocalFree(C.cast(string, W.LPVOID))
        finally:
            self.kernel.CloseHandle(token)

    def dacl_string(self, descriptor):
        string = W.LPWSTR()
        self.check(self.security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 4, C.byref(string), None))
        try:
            return string.value
        finally:
            self.kernel.LocalFree(C.cast(string, W.LPVOID))

    def check_dacl(self, handle, expected_descriptor):
        descriptor = W.LPVOID()
        # SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4. Read back before writing.
        if self.security.GetSecurityInfo(handle, 1, 4, None, None, None, None, C.byref(descriptor)):
            raise OSError("Filesystem cannot verify the required Windows ACL.")
        try:
            # Windows may serialize a SID using an alias (e.g. LA for RID 500).
            # Canonicalize both descriptors with the same OS serializer.
            expected = self.dacl_string(expected_descriptor)
            actual = self.dacl_string(descriptor)
            if (not expected.startswith("D:P(")
                    or actual not in (expected, "D:PAI" + expected[3:])):
                raise OSError("Windows ACL is not restricted to the current user.")
        finally:
            self.kernel.LocalFree(descriptor)


def write_windows(path: Path, archive: bytes):
    if os.name != "nt":
        raise ValidationError("Windows output requires Windows.")
    path = path.absolute()
    if path.anchor.startswith('\\\\') or ':' in str(path)[2:]:
        raise ValidationError("Select a local Windows file, without alternate data streams.")
    api = WindowsAPI()
    sid = api.user_sid()
    descriptor = W.LPVOID()
    api.check(api.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:P(A;;FA;;;{sid})", 1, C.byref(descriptor), None))
    temporary = path.parent / (".authy-migrate-" + secrets.token_hex(16))
    created = False
    handle = None
    try:
        attributes = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
        # GENERIC_WRITE | READ_CONTROL, no sharing, CREATE_NEW, NORMAL | WRITE_THROUGH.
        handle = api.kernel.CreateFileW(str(temporary), 0x40020000, 0, C.byref(attributes), 1, 0x80000080, None)
        if handle == C.c_void_p(-1).value:
            handle = None
            raise OSError("Cannot create secure temporary output.")
        created = True
        api.check_dacl(handle, descriptor)
        buffer = C.create_string_buffer(archive)
        position = 0
        while position < len(archive):
            count = W.DWORD()
            api.check(api.kernel.WriteFile(handle, C.byref(buffer, position), len(archive) - position, C.byref(count), None))
            if not count.value:
                raise OSError("Windows output write made no progress.")
            position += count.value
        api.check(api.kernel.FlushFileBuffers(handle))
        api.check(api.kernel.CloseHandle(handle))
        handle = None
        # Same-directory move, no REPLACE_EXISTING and no cross-volume copy fallback.
        if not api.kernel.MoveFileExW(str(temporary), str(path), 0x8):
            if C.get_last_error() in (80, 183):
                raise FileExistsError("Destination exists; nothing overwritten.")
            raise OSError("Windows output publication failed.")
        created = False  # Published; never remove the destination in cleanup.
    finally:
        api.kernel.LocalFree(descriptor)
        if handle is not None:
            api.kernel.CloseHandle(handle)
        if created:
            temporary.unlink()
