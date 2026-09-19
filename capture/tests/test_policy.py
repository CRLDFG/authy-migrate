import json
from pathlib import Path
from urllib.parse import urlencode
import pytest
from authy_migrate.authy import parse_authy
from policy import CaptureError, Endpoint, encrypted_record

@pytest.mark.parametrize('host,path',[
    ('localhost.evil:443','/update'),('LOCALHOST','/update'),
    ('localhost','/update?extra=1'),('localhost','/x/../update'),
    ('localhost','/%75pdate'),('localhost','//update'),
])
def test_ambiguous_profiles_rejected(host,path):
    with pytest.raises(CaptureError):Endpoint(host,443,path,'127.0.0.1')

@pytest.mark.parametrize('body',[
    b'x='*40000,b'a=%ZZ',b'a=%FF',b'a=1&a=2',b'a',b'\xff',b'',
    b'encrypted_seed=x&decrypted_seed=never-accepted',
])
def test_malformed_form_rejected_without_values_in_errors(body):
    with pytest.raises(CaptureError) as error:encrypted_record(body,parse_authy)
    assert str(error.value) in ('Invalid capture body size.','Invalid encrypted capture record.')

def test_missing_iv_or_kdf_not_inferred():
    source=Path(__file__).resolve().parents[2]/'tests/fixtures/authy-synthetic.json'
    record=json.loads(source.read_bytes())['authenticator_tokens'][0]
    record['token_id']=record.pop('unique_id')
    for field in ('unique_iv','key_derivation_iterations'):
        incomplete={key:value for key,value in record.items() if key!=field}
        with pytest.raises(CaptureError):encrypted_record(urlencode(incomplete).encode(),parse_authy)
