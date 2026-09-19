import json
import pytest
from policy import diagnose_form, CaptureError
from authy_migrate.authy import parse_authy
from test_tls import upstream, start, request, body

PATH = '/json/users/123456/authenticator_tokens/update'


def test_diagnostic_blocks_upstream_and_exports_only_path_and_booleans(upstream):
    payload = body() + b'&api_key=public-secret-marker'
    with start(upstream, diagnostic=True) as session:
        directory = session.root
        assert b'409' in request(session, upstream[0].server_port, path=PATH, raw_body=payload)
        result = session.finish()
        assert session.records == []
        assert session.process.poll() == 0
        assert not directory.exists()
    assert upstream[0].bodies == []
    assert upstream[0].connections == 0
    assert result['path'] == PATH
    assert session.diagnostic_status['stages'] == dict(client_connections=1, authy_tunnels=1,
                                                       tls_requests=1, matching_requests=1)
    assert result['facts']['record_accepted'] is True
    assert all(type(value) is bool for value in result['facts'].values())
    assert b'public-secret-marker' not in json.dumps(result).encode()


def test_query_is_not_exported_or_accepted_as_capture_compatible(upstream):
    with start(upstream, diagnostic=True) as session:
        assert b'409' in request(session, upstream[0].server_port,
                                path=PATH + '?api_key=public-query-secret')
        result = session.finish()
    assert result['path'] == PATH
    assert result['facts']['has_query'] is True
    assert result['facts']['record_accepted'] is False
    assert 'public-query-secret' not in json.dumps(result)
    assert upstream[0].connections == 0


@pytest.mark.parametrize('path', ['/json/users/name/authenticator_tokens/update',
                                  PATH + '/other', '/other/update'])
def test_other_routes_are_not_observed_or_forwarded(upstream, path):
    with start(upstream, diagnostic=True) as session:
        assert b'403' in request(session, upstream[0].server_port, path=path)
        with pytest.raises(CaptureError, match='No update request'):
            session.finish()
    assert upstream[0].connections == 0


def test_unknown_names_and_values_do_not_enter_diagnostic():
    result = diagnose_form(body() + b'&private-field-name=private-value', parse_authy, has_query=False)
    assert result['unknown_fields'] is True
    assert result['record_accepted'] is False
    assert 'private' not in json.dumps(result)


def test_no_client_is_distinguishable_from_expired_session(upstream):
    with start(upstream, diagnostic=True) as session:
        with pytest.raises(CaptureError, match='No update request'):
            session.finish()
        assert not any(session.diagnostic_status['stages'].values())
        assert session.diagnostic_status['timed_out'] is False
    with start(upstream, diagnostic=True, timeout=1) as session:
        while session.done is None:
            session.collect(timeout=5)
        with pytest.raises(CaptureError, match='deadline'):
            session.finish()
        assert session.diagnostic_status['timed_out'] is True
        assert not any(session.diagnostic_status['stages'].values())


def test_deadline_returns_without_pressing_enter(upstream, monkeypatch):
    import os
    import diagnose
    read_fd, write_fd = os.pipe()
    try:
        with os.fdopen(read_fd) as terminal, start(upstream, diagnostic=True, timeout=1) as session:
            monkeypatch.setattr(diagnose.sys, 'stdin', terminal)
            diagnose.wait_for_diagnostic(session)
            assert session.done is False
            with pytest.raises(CaptureError, match='deadline'):
                session.finish()
    finally:
        os.close(write_fd)


def test_user_diagnostic_writes_private_observation_after_cleanup(upstream, tmp_path, monkeypatch, capsys):
    import diagnose
    from types import SimpleNamespace
    from test_tls import PYTHON
    sessions = []
    def factory(*args, **kwargs):
        session = start(upstream, diagnostic=True)
        sessions.append(session)
        return session
    monkeypatch.setattr(diagnose, 'Session', factory)
    monkeypatch.setattr(diagnose.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(diagnose.sys.stdout, 'isatty', lambda: True)
    monkeypatch.setattr(diagnose.getpass, 'getpass', lambda _: 'public-proxy-password')
    def interact(_):
        assert b'409' in request(sessions[0], upstream[0].server_port, path=PATH)
        return ''
    monkeypatch.setattr(diagnose, 'wait_for_diagnostic', interact)
    destination = tmp_path / 'diagnostic'
    diagnose.run(SimpleNamespace(mac_ip='192.168.50.10', iphone_ip='192.168.50.20',
                                capture_python=PYTHON, directory=destination))
    output = capsys.readouterr().out
    assert PATH not in output
    assert 'public-proxy-password' not in output
    assert not sessions[0].root.exists()
    result = destination / 'observation.private.json'
    assert result.stat().st_mode & 0o777 == 0o600
    assert destination.stat().st_mode & 0o777 == 0o700
    assert json.loads(result.read_bytes())['path'] == PATH
    assert upstream[0].connections == 0
