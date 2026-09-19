import hashlib
import json
from pathlib import Path
import pytest
from authy_migrate.authy import parse_authy, parameter_template, resolve_parameters
from authy_migrate.core import ValidationError


def document():
    source=json.loads((Path(__file__).parent/'fixtures/authy-synthetic.json').read_bytes())
    source['capture']=dict(version=1,host='localhost',port=443,path='/authenticator_tokens/update',
        app_version='synthetic/v1',source_reference='local TLS fixture',engine_revision='a'*40)
    return source


def test_capture_provenance_is_explicit_and_bound():
    data=json.dumps(document()).encode()
    first=parse_authy(data,'authy-sync-json')[0]
    assert first.origin.startswith('experimental-ios-form/v1/')
    with pytest.raises(ValidationError):parse_authy(data,'authy-json')
    template=parameter_template(data,'authy-sync-json')
    assert template['source_sha256']==hashlib.sha256(data).hexdigest()
    changed=document();changed['capture']['app_version']='synthetic/v2'
    second=json.dumps(changed).encode()
    assert parse_authy(second,'authy-sync-json')[0].origin!=first.origin
    with pytest.raises(ValidationError):
        resolve_parameters(second,parse_authy(second,'authy-sync-json'),json.dumps(template).encode())


@pytest.mark.parametrize('field,value',[
    ('version',True),('version',2),('host','localhost:443'),('path','/update?x=1'),
    ('port',True),('port',0),('engine_revision','main'),('app_version',''),
    ('source_reference','x'*513),
])
def test_invalid_provenance_rejected(field,value):
    source=document();source['capture'][field]=value
    with pytest.raises(ValidationError):parse_authy(json.dumps(source).encode(),'authy-sync-json')


def test_missing_capture_metadata_is_not_inferred():
    source=document();del source['capture']
    with pytest.raises(ValidationError):parse_authy(json.dumps(source).encode(),'authy-sync-json')


@pytest.mark.parametrize('missing',[True,False])
def test_capture_identifiers_required_and_distinct(missing):
    source=document()
    if missing:
        del source['authenticator_tokens'][0]['unique_id']
    else:
        source['authenticator_tokens'][1]['unique_id']=source['authenticator_tokens'][0]['unique_id']
    with pytest.raises(ValidationError):parse_authy(json.dumps(source).encode(),'authy-sync-json')
