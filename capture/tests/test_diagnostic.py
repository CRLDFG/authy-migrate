import json
import pytest
from policy import diagnose_form, CaptureError, DIAGNOSTIC_STAGES
from authy_migrate.authy import parse_authy
from test_tls import upstream, start, request, body

PATH = '/json/users/123456/authenticator_tokens/update'


@pytest.mark.parametrize('host_headers,accepted', [
    (['localhost'], True), (['localhost:443'], True),
    (['localhost:444'], False), (['localhost', 'localhost:443'], False),
    (['other.invalid'], False),
])
def test_connect_default_https_port_host_equivalence(upstream, host_headers, accepted):
    import base64
    import socket
    import ssl
    from test_tls import AUTH
    # Diagnostic never connects upstream, so no service needs to listen on 443.
    with start(upstream, diagnostic=True, endpoint={'port': 443}) as session:
        headers = ''.join(f'Host: {value}\r\n' for value in host_headers)
        auth = base64.b64encode(AUTH.encode()).decode()
        raw = f'CONNECT localhost:443 HTTP/1.1\r\n{headers}Proxy-Authorization: Basic {auth}\r\n\r\n'
        sock = socket.create_connection(('127.0.0.1', session.port), timeout=3)
        try:
            sock.sendall(raw.encode())
            response = bytearray()
            while b'\r\n\r\n' not in response:
                part = sock.recv(1)
                if not part:
                    break
                response.extend(part)
            assert (b'200' if accepted else b'403') in response
            if accepted:
                context = ssl.create_default_context(cafile=str(session.certificate))
                with context.wrap_socket(sock, server_hostname='localhost') as tls:
                    payload = body()
                    tls.sendall((f'POST {PATH} HTTP/1.1\r\nHost: localhost\r\n'
                                 f'Content-Type: application/x-www-form-urlencoded\r\n'
                                 f'Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode() + payload)
                    assert b'409' in tls.recv(4096)
                assert session.finish()['facts']['record_accepted'] is True
            else:
                with pytest.raises(CaptureError):
                    session.finish()
        finally:
            sock.close()
    assert upstream[0].connections == 0


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
    expected = dict.fromkeys(DIAGNOSTIC_STAGES, 0)
    expected.update(client_connections=1, connect_requests=1, authy_connect_requests=1,
                    authy_tunnels=1, tls_requests=1, matching_requests=1)
    assert session.diagnostic_status['stages'] == expected
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


@pytest.mark.parametrize('case,expected,status', [
    ('missing_auth', 'proxy_auth_required', b'407'),
    ('wrong_auth', 'proxy_auth_required', b'407'),
    ('missing_host', 'connect_host_missing', b'403'),
    ('wrong_host', 'connect_host_rejected', b'403'),
    ('other_endpoint', 'connect_other_endpoint', b'403'),
])
def test_connect_rejection_reason_without_exposing_headers(upstream, case, expected, status):
    import base64
    import socket
    from test_tls import AUTH
    port = upstream[0].server_port
    with start(upstream, diagnostic=True) as session:
        target = 'localhost' if case != 'other_endpoint' else 'other.invalid'
        headers = []
        if case != 'missing_host':
            value = 'private-host.invalid' if case == 'wrong_host' else f'{target}:{port}'
            headers.append(f'Host: {value}')
        if case != 'missing_auth':
            value = 'private-user:private-password' if case == 'wrong_auth' else AUTH
            headers.append('Proxy-Authorization: Basic ' + base64.b64encode(value.encode()).decode())
        raw = f'CONNECT {target}:{port} HTTP/1.1\r\n' + '\r\n'.join(headers) + '\r\n\r\n'
        with socket.create_connection(('127.0.0.1', session.port), timeout=3) as sock:
            sock.sendall(raw.encode())
            assert status in sock.recv(4096)
        with pytest.raises(CaptureError, match='No update request'):
            session.finish()
        stages = session.diagnostic_status['stages']
        assert stages['connect_requests'] == 1
        assert stages[expected] == 1
        assert stages['authy_tunnels'] == 0
        assert 'private' not in json.dumps(session.diagnostic_status)
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
