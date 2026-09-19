import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
import cli
from policy import CaptureError
from test_tls import upstream, request, ROOT, PYTHON, PATH
from session import Session
from authy_migrate.synthetic import PASSWORD
from authy_migrate.authy import parse_authy


def arguments(tmp_path,upstream):
    profile=tmp_path/'profile.json'
    profile.write_text(json.dumps(dict(version=1,host='localhost',port=upstream[0].server_port,
        path=PATH,app_version='synthetic/v1',source_reference='local TLS fixture')))
    return SimpleNamespace(profile=profile,capture_python=PYTHON,listen_ip='127.0.0.1',
        client_ip='127.0.0.1',expected_records=4,certificate=tmp_path/'public-certificate.pem',
        parameters=tmp_path/'parameters.json',output=tmp_path/'output.json',timeout=20)


def prepare(monkeypatch,args,upstream):
    sessions=[]
    def factory(*positional,**kwargs):
        session=Session(*positional,upstream_ca=upstream[1],**kwargs)
        sessions.append(session)
        return session
    def capture(session):
        for index in range(4):
            assert b'200' in request(session,upstream[0].server_port,index=index,auth='authy-migrate:public-proxy-password')
            session.collect()
        data=session.finish()
        decoded=json.loads(data)
        assert decoded['capture']['app_version']=='synthetic/v1'
        assert all(r.origin.startswith('experimental-ios-form/v1/')
                   for r in parse_authy(data,'authy-sync-json'))
        return data
    monkeypatch.setattr(cli,'Session',factory)
    monkeypatch.setattr(cli,'collect_interactively',capture)
    monkeypatch.setattr(cli.sys.stdin,'isatty',lambda:True)
    monkeypatch.setattr(cli.sys.stdout,'isatty',lambda:True)
    monkeypatch.setattr(cli.getpass,'getpass',lambda _: 'public-proxy-password')
    def passwords(converting):
        assert converting
        assert sessions[0].process.poll()==0
        assert not sessions[0].root.exists()
        return ' Authy backup synthétique 🔑 ',PASSWORD
    monkeypatch.setattr(cli,'_passwords',passwords)
    def complete_parameters(_):
        template=json.loads(args.parameters.read_bytes())
        expected=json.loads((ROOT/'tests/fixtures/authy-synthetic.json.parameters.json').read_bytes())
        template['records']=expected['records']
        args.parameters.write_text(json.dumps(template))
        return ''
    monkeypatch.setattr('builtins.input',complete_parameters)
    return sessions


def test_full_interactive_workflow_uses_passwords_after_reaping(tmp_path,upstream,monkeypatch,capsys):
    args=arguments(tmp_path,upstream)
    prepare(monkeypatch,args,upstream)
    cli.run(args)
    assert set(json.loads(args.output.read_bytes()))=={'version','salt','content'}
    assert b'PRIVATE KEY' not in args.certificate.read_bytes()
    output=capsys.readouterr()
    assert 'GEZDGNBVGY3TQOJQ' not in output.out+output.err
    assert PASSWORD not in output.out+output.err
    assert 'public-proxy-password' not in output.out+output.err
    assert 'remain unverified' in output.out


def test_count_mismatch_stops_before_passwords_or_output(tmp_path,upstream,monkeypatch):
    args=arguments(tmp_path,upstream);args.expected_records=5
    sessions=prepare(monkeypatch,args,upstream)
    monkeypatch.setattr(cli,'_passwords',lambda _:pytest.fail('Passwords requested for incomplete capture'))
    with pytest.raises(CaptureError,match='expected count'):cli.run(args)
    assert not args.output.exists()
    assert not args.parameters.exists()
    assert sessions[0].process.poll()==0


def test_noninteractive_refused_before_profile_or_proxy(tmp_path,monkeypatch):
    monkeypatch.setattr(cli.sys.stdin,'isatty',lambda:False)
    with pytest.raises(CaptureError,match='terminals'):
        cli.run(SimpleNamespace())


def test_enter_drains_pending_frames_then_reaps(upstream,monkeypatch):
    from test_tls import start
    with start(upstream) as session:
        for index in range(4):
            assert b'200' in request(session,upstream[0].server_port,index=index)
        read_fd,write_fd=os.pipe()
        with os.fdopen(read_fd) as terminal:
            monkeypatch.setattr(cli.sys,'stdin',terminal)
            os.write(write_fd,b'\n');os.close(write_fd)
            captured=cli.collect_interactively(session)
        assert session.process.poll()==0
        assert len(json.loads(captured)['authenticator_tokens'])==4
