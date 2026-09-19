import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest
from authy_migrate.authy import (MAX_INPUT_BYTES, convert_authy, decrypt_authy,
                                parameter_template, parse_authy, resolve_parameters)
from authy_migrate.core import ValidationError, ValidationStatus
from authy_migrate.synthetic import entries, PASSWORD

FIXTURES = Path(__file__).parent / 'fixtures'
BACKUP_PASSWORD = ' Authy backup synthétique 🔑 '


def fixture(extension='json'):
    p = FIXTURES / ('authy-synthetic.' + extension)
    return p.read_bytes(), p.with_suffix(p.suffix + '.parameters.json').read_bytes()


def changed_document(mutator):
    data, parameters = fixture()
    doc = json.loads(data)
    mutator(doc)
    data = json.dumps(doc, ensure_ascii=False).encode()
    settings = json.loads(parameters)
    settings['source_sha256'] = hashlib.sha256(data).hexdigest()
    return data, json.dumps(settings).encode()


@pytest.mark.parametrize('extension,source_format', [('json','authy-json'),('csv','twilio-csv')])
def test_independent_node_vectors(extension, source_format, capsys, caplog):
    data, parameters = fixture(extension)
    with patch('builtins.open', side_effect=AssertionError('file access')), patch('socket.socket', side_effect=AssertionError('network')):
        result = decrypt_authy(data, source_format, parameters, BACKUP_PASSWORD)
    assert result == entries()
    assert all(entry.validation is ValidationStatus.STRUCTURAL for entry in result)
    assert capsys.readouterr() == ('', '')
    assert not caplog.text
    assert 'example.invalid' not in repr(parse_authy(data, source_format))


@pytest.mark.parametrize('binary_path', [
    'reference/target/debug/authy-migrate-reference-check',
    'reference/legacy/target/debug/authy-migrate-legacy-check',
])
@pytest.mark.parametrize('extension,source_format', [('json','authy-json'),('csv','twilio-csv')])
def test_complete_conversion_with_both_official_importers(binary_path, extension, source_format):
    binary = Path(binary_path + ('.exe' if os.name == 'nt' else ''))
    if not binary.exists():
        if os.environ.get('CI'):
            pytest.fail('Reference importer is mandatory in CI')
        pytest.skip('Build the reference importer first')
    data, parameters = fixture(extension)
    blob = convert_authy(data, source_format, parameters, BACKUP_PASSWORD, PASSWORD)
    result = subprocess.run([str(binary.resolve())], input=blob, capture_output=True)
    assert result.returncode == 0, 'Independent importer rejected conversion; details redacted'
    assert result.stdout.startswith(b'PASS:')


@pytest.mark.parametrize('password', ['wrong password', BACKUP_PASSWORD.strip(), BACKUP_PASSWORD.replace('é', 'e\u0301')])
def test_password_exact_bytes(password):
    data, parameters = fixture()
    with pytest.raises(ValidationError, match='Record 1: decryption or secret validation failed'):
        decrypt_authy(data, 'authy-json', parameters, password)


@pytest.mark.parametrize('field,value', [
    ('key_derivation_iterations', 0), ('key_derivation_iterations', 1000001),
    ('key_derivation_iterations', True), ('key_derivation_iterations', '100000.0'),
    ('unique_iv', '00'*15), ('unique_iv', '00 '*16), ('unique_iv', None),
    ('encrypted_seed', 'not!base64'), ('encrypted_seed', 'YWJj'),
    ('encrypted_seed', 'A'*2000), ('salt', ''), ('salt', 'x'*257),
    ('name', '\ud800'), ('name', 'x'*257), ('digits', 7), ('digits', True),
    ('algorithm', 'SHA3'), ('period', 65536), ('period', 0),
    ('account_type', 'authy'), ('account_type', 'HOTP'), ('account_type', 'steam'),
])
def test_malformed_source_rejected_before_kdf(field,value):
    doc = json.loads(fixture()[0]); doc['authenticator_tokens'][0][field] = value
    data = json.dumps(doc).encode()
    with patch('authy_migrate.authy.PBKDF2HMAC', side_effect=AssertionError('KDF must not run')):
        with pytest.raises(ValidationError):
            parse_authy(data,'authy-json')


@pytest.mark.parametrize('field', ['unique_iv','key_derivation_iterations','salt','encrypted_seed','name'])
def test_missing_json_fields(field):
    doc = json.loads(fixture()[0]); del doc['authenticator_tokens'][0][field]
    with pytest.raises(ValidationError):
        parse_authy(json.dumps(doc).encode(),'authy-json')


def test_aggregate_kdf_budget_and_record_limit():
    doc = json.loads(fixture()[0]); first = doc['authenticator_tokens'][0]
    for count in (101,1001):
        doc['authenticator_tokens'] = [first]*count
        with pytest.raises(ValidationError):
            parse_authy(json.dumps(doc).encode(),'authy-json')
    with pytest.raises(ValidationError):
        parse_authy(b'x'*(MAX_INPUT_BYTES+1),'authy-json')


@pytest.mark.parametrize('data', [b'{"authenticator_tokens":[],"authenticator_tokens":[]}', b'NaN',
    b'[]', b'{"authenticator_tokens":null}', b'{"authenticator_tokens":[]}', b'\xff', b'{}',
    b'{"authenticator_tokens":[],"unknown":1}'])
def test_bad_envelope(data):
    with pytest.raises(ValidationError):
        parse_authy(data,'authy-json')


def test_proprietary_tokens_never_silently_dropped():
    doc = json.loads(fixture()[0]); doc['authy_tokens'] = [{'encrypted_seed':'private'}]
    with pytest.raises(ValidationError, match='proprietary'):
        parse_authy(json.dumps(doc).encode(),'authy-json')


@pytest.mark.parametrize('data', [
    b'name,encrypted_seed,salt,iv,iv\na,b,c,d,e\n',
    b'name,encrypted_seed,salt,iv\na,b,c\n',
    b'name,encrypted_seed,salt,iv\n"unclosed,b,c,d\n',
    b'"name,encrypted_seed,salt,iv\na,b,c,d"',
    b'name,encrypted_seed,salt,iv\na,b,c,d,e\n',
    b'name,encrypted_seed,salt,iv\n\n',
])
def test_no_csv_repair(data):
    with pytest.raises(ValidationError):
        parse_authy(data,'twilio-csv')


def test_quoted_commas_and_apostrophes_preserved():
    data, _ = fixture('csv')
    rows = list(csv.reader(io.StringIO(data.decode(),newline='')))
    rows[1][rows[0].index('name')] = 'Account, "quoted" O\'Connor'
    buffer = io.StringIO(newline=''); csv.writer(buffer).writerows(rows)
    record = parse_authy(buffer.getvalue().encode(),'twilio-csv')[0]
    assert record.label == 'Account, "quoted" O\'Connor'


def test_minimal_csv_has_only_documented_kdf_default():
    data,_ = fixture('csv'); rows = list(csv.DictReader(io.StringIO(data.decode())))
    buffer = io.StringIO(newline=''); writer = csv.DictWriter(buffer,fieldnames=['name','encrypted_seed','salt','iv'])
    writer.writeheader(); writer.writerow({key:rows[0][key] for key in writer.fieldnames})
    data = buffer.getvalue().encode()
    record = parse_authy(data,'twilio-csv')[0]
    assert record.iterations == 100000
    template = parameter_template(data,'twilio-csv')
    assert template['records'][0] == dict(row=1,otp_type=None,secret_encoding=None,issuer=None,algorithm=None,digits=None,period=None)
    with pytest.raises(ValidationError):
        decrypt_authy(data,'twilio-csv',json.dumps(template).encode(),BACKUP_PASSWORD)
    template['records'][0].update(otp_type='TOTP',secret_encoding='base32',issuer='Example',algorithm='SHA1',digits=6,period=30)
    assert decrypt_authy(data,'twilio-csv',json.dumps(template).encode(),BACKUP_PASSWORD) == entries()[:1]


@pytest.mark.parametrize('mutation', [
    lambda s:s.update(source_sha256='0'*64),
    lambda s:s.update(version=True),
    lambda s:s['records'].reverse(),
    lambda s:s['records'].pop(),
    lambda s:s['records'][0].update(algorithm='SHA512'),
    lambda s:s['records'][0].update(otp_type='HOTP'),
    lambda s:s['records'][0].update(secret_encoding='auto'),
    lambda s:s['records'][0].update(row=True),
])
def test_explicit_bound_parameters(mutation):
    data, parameters = fixture(); settings = json.loads(parameters); mutation(settings)
    with patch('authy_migrate.authy.PBKDF2HMAC', side_effect=AssertionError('KDF must not run')):
        with pytest.raises(ValidationError):
            decrypt_authy(data,'authy-json',json.dumps(settings).encode(),BACKUP_PASSWORD)


def test_partial_failure_produces_no_archive_and_no_secret_diagnostic(capsys):
    data,parameters = changed_document(lambda d:d['authenticator_tokens'][2].update(encrypted_seed=base64.b64encode(bytes(80)).decode()))
    with patch('authy_migrate.authy.encrypt_export', side_effect=AssertionError('No partial encryption')):
        with pytest.raises(ValidationError) as exc:
            convert_authy(data,'authy-json',parameters,BACKUP_PASSWORD,PASSWORD)
    assert str(exc.value).startswith('Record 3:')
    assert BACKUP_PASSWORD not in str(exc.value)
    assert 'example.invalid' not in str(exc.value)
    assert '1234567890' not in str(exc.value)
    assert capsys.readouterr() == ('','')


def test_cbc_valid_structure_is_not_authentication():
    # XOR first plaintext character G -> F through IV malleability. Both are Base32.
    def mutate(doc):
        row = doc['authenticator_tokens'][0]
        iv = bytearray.fromhex(row['unique_iv']); iv[0] ^= ord('G') ^ ord('F')
        row['unique_iv'] = iv.hex()
    data,params = changed_document(mutate)
    decoded = decrypt_authy(data,'authy-json',params,BACKUP_PASSWORD)
    assert decoded[0].secret != entries()[0].secret
    assert decoded[0].validation is ValidationStatus.STRUCTURAL


def test_declared_encoding_not_guessed():
    from authy_migrate.authy import _decode_secret
    ambiguous = b'DEADBEEFDEADBEEFDEADBEEFDEADBEEF'
    assert _decode_secret(ambiguous,'hex') != _decode_secret(ambiguous,'base32')
    for malformed in (b'MZXW6===\n',b'mzxw6===',b'ABC',b'12 34',b'\xff'):
        with pytest.raises(ValueError):
            _decode_secret(malformed,'base32')


def test_cli_inspection_template_contains_no_account_metadata(tmp_path,capsys):
    from authy_migrate.cli import main
    path = tmp_path/'input.json'; path.write_bytes(fixture()[0])
    with patch('sys.argv',['authy-migrate','inspect',str(path),'--format','authy-json']),patch('getpass.getpass',side_effect=AssertionError('No password')):
        assert main() == 0
    output = capsys.readouterr()
    assert 'example.invalid' not in output.out
    assert 'encrypted_seed' not in output.out
    assert json.loads(output.out)['records'][0]['secret_encoding'] is None


def test_cli_conversion_writes_only_encrypted_output(tmp_path,capsys):
    from authy_migrate.cli import main
    data,parameters=fixture(); source=tmp_path/'input.json'; settings=tmp_path/'settings.json'
    source.write_bytes(data); settings.write_bytes(parameters); target=tmp_path/'result.json'
    with patch('sys.argv',['authy-migrate','convert',str(source),str(target),'--format','authy-json','--parameters',str(settings)]),patch('sys.stdin.isatty',return_value=True),patch('getpass.getpass',side_effect=[BACKUP_PASSWORD,PASSWORD,PASSWORD]):
        assert main() == 0
    output=capsys.readouterr()
    assert BACKUP_PASSWORD not in output.out+output.err
    assert 'example.invalid' not in output.out+output.err
    assert set(json.loads(target.read_bytes())) == {'version','salt','content'}
    assert set(p.name for p in tmp_path.iterdir()) == {'input.json','settings.json','result.json'}
