import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from authy_migrate.core import AAD, OtpEntry, ValidationError, encrypt_export
from authy_migrate.synthetic import entries, PASSWORD
from authy_migrate.output import write_encrypted


def decode(blob, password=PASSWORD):
    doc = json.loads(blob)
    salt = base64.b64decode(doc['salt'], validate=True)
    content = base64.b64decode(doc['content'], validate=True)
    key = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19456).derive(password.encode())
    return json.loads(AESGCM(key).decrypt(content[:12], content[12:], AAD))


def test_structure_and_randomness():
    first, second = encrypt_export(entries(), PASSWORD), encrypt_export(entries(), PASSWORD)
    assert first != second
    payload = decode(first)
    assert payload['version'] == 1
    assert len(payload['entries']) == 4
    assert len({e['id'] for e in payload['entries']}) == 4
    assert 'algorithm=SHA256&digits=8&period=15' in payload['entries'][1]['content']['uri']
    assert 'algorithm=SHA512&digits=8&period=60' in payload['entries'][2]['content']['uri']
    for e in entries():
        assert e.label.encode() not in first
        assert base64.b32encode(e.secret).rstrip(b'=') not in first


@pytest.mark.parametrize('password', ['wrong password', PASSWORD.strip(), PASSWORD.replace('é', 'e\u0301')])
def test_password_preserved(password):
    with pytest.raises(InvalidTag):
        decode(encrypt_export(entries(), PASSWORD), password)


def test_tampering():
    doc = json.loads(encrypt_export(entries(), PASSWORD))
    content = bytearray(base64.b64decode(doc['content']))
    content[15] ^= 1
    doc['content'] = base64.b64encode(content).decode()
    with pytest.raises(InvalidTag):
        decode(json.dumps(doc))


@pytest.mark.parametrize('changes', [dict(otp_type='HOTP'), dict(otp_type='Steam'), dict(secret=b'x'),
    dict(algorithm='SHA3'), dict(digits=7), dict(digits=True), dict(period=0), dict(period=65536),
    dict(label=' leading'), dict(issuer='\nprivate'), dict(label='x'*257), dict(label='\ud800')])
def test_reject_invalid_without_details(changes):
    e = replace(entries()[0], **changes)
    with pytest.raises(ValidationError) as error:
        encrypt_export([e], PASSWORD)
    assert entries()[0].secret.decode() not in str(error.value)
    assert 'example.invalid' not in repr(e)


def test_all_or_nothing():
    with pytest.raises(ValidationError):
        encrypt_export(entries() + [replace(entries()[0], period=0)], PASSWORD)
    for invalid in ([], entries()*251):
        with pytest.raises(ValidationError):
            encrypt_export(invalid, PASSWORD)


def test_core_no_io(capsys, caplog):
    with patch('builtins.open', side_effect=AssertionError('file access')), patch('socket.socket', side_effect=AssertionError('network')):
        encrypt_export(entries(), PASSWORD)
    assert not caplog.text
    assert capsys.readouterr() == ('', '')


@pytest.mark.skipif(os.name != 'posix', reason='POSIX publication; Windows explicitly rejected')
def test_atomic_no_clobber_and_permissions(tmp_path):
    target = tmp_path / 'export.json'
    blob = encrypt_export(entries(), PASSWORD)
    write_encrypted(target, blob)
    assert target.read_bytes() == blob
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_encrypted(target, b'other')
    assert target.read_bytes() == blob
    assert list(tmp_path.iterdir()) == [target]
    link = tmp_path / 'link'
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        write_encrypted(link, b'other')
    assert target.read_bytes() == blob


@pytest.mark.skipif(os.name != 'posix', reason='POSIX publication')
def test_cleanup_after_failure(tmp_path):
    with patch('os.link', side_effect=OSError('synthetic failure')):
        with pytest.raises(OSError):
            write_encrypted(tmp_path / 'export.json', b'encrypted synthetic bytes')
    assert not list(tmp_path.iterdir())


def test_cli_noninteractive_no_file(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(Path('src').resolve()))
    result = subprocess.run([sys.executable, '-m', 'authy_migrate.cli', 'demo', str(tmp_path/'x')],
                            input='', text=True, capture_output=True, env=env)
    assert result.returncode == 1
    assert not list(tmp_path.iterdir())
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('binary_path', [
    'reference/target/debug/authy-migrate-reference-check',
    'reference/legacy/target/debug/authy-migrate-legacy-check',
])
def test_official_importer(binary_path):
    binary = Path(binary_path)
    if os.name == 'nt':
        binary = binary.with_suffix('.exe')
    if not binary.exists():
        if os.environ.get('CI'):
            pytest.fail('Official importer is required in CI')
        pytest.skip('Build pinned official importer to run independent compatibility gate')
    result = subprocess.run([str(binary.resolve())], input=encrypt_export(entries(), PASSWORD), capture_output=True)
    assert result.returncode == 0, 'Official importer rejected synthetic export; details suppressed'
    assert result.stdout.startswith(b'PASS:')


def test_unknown_platform_fails_closed(tmp_path):
    with patch('authy_migrate.output.os.name', 'unknown'):
        with pytest.raises(ValidationError):
            write_encrypted(tmp_path / 'x', b'encrypted')
    assert not list(tmp_path.iterdir())


def test_cli_success_no_passphrase_in_output(tmp_path, capsys):
    from authy_migrate.cli import main
    target = tmp_path / 'demo.json'
    with patch('sys.argv', ['authy-migrate', 'demo', str(target)]), patch('sys.stdin.isatty', return_value=True), patch('getpass.getpass', side_effect=[PASSWORD, PASSWORD]):
        assert main() == 0
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert len(decode(target.read_bytes())['entries']) == 4
