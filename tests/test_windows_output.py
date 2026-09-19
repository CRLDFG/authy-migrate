import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import pytest
from authy_migrate.output import write_encrypted

pytestmark = pytest.mark.skipif(os.name != 'nt',reason='Requires actual Windows ACL and filesystem APIs')


def test_protected_dacl_and_atomic_no_clobber(tmp_path):
    target = tmp_path / 'archive.json'
    payload = b'{"public":"synthetic encrypted bytes"}'
    write_encrypted(target,payload)
    assert target.read_bytes() == payload
    # Independent .NET ACL inspection, not our serializer/parser or chmod emulation.
    script = '''
$a = Get-Acl -LiteralPath $env:AUTHY_MIGRATE_TEST_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rules = $a.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if (-not $a.AreAccessRulesProtected -or $rules.Count -ne 1) { exit 1 }
$r = $rules[0]
if ($r.IdentityReference.Value -ne $sid -or $r.IsInherited -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl') { exit 2 }
'''
    result = subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],
                            env=dict(os.environ,AUTHY_MIGRATE_TEST_PATH=str(target)),capture_output=True)
    assert result.returncode == 0, 'Independent Windows ACL verification failed'
    with pytest.raises(FileExistsError):
        write_encrypted(target,b'other')
    assert target.read_bytes() == payload
    assert list(tmp_path.iterdir()) == [target]


def test_acl_verification_failure_removes_only_created_temp(tmp_path):
    from authy_migrate.windows_output import WindowsAPI
    with patch.object(WindowsAPI,'check_dacl',side_effect=OSError('synthetic')):
        with pytest.raises(OSError):
            write_encrypted(tmp_path/'archive.json',b'ciphertext')
    assert not list(tmp_path.iterdir())


def test_reject_windows_network_and_stream_paths():
    from authy_migrate.core import ValidationError
    for name in [r'\\localhost\share\export.json', r'C:\output.json:secret']:
        with pytest.raises(ValidationError):
            write_encrypted(Path(name),b'ciphertext')
