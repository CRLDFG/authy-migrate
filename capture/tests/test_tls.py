"""Actual loopback TLS and mitmdump processes; public synthetic account data only."""
import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
from pathlib import Path
import socket
import signal
import ssl
import threading
import subprocess
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
from policy import CaptureError
from session import Session

ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / '.capture-venv/bin/python'
AUTH = 'synthetic:public-proxy-password'
PATH = '/authenticator_tokens/update'


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
            .sign(key,hashes.SHA256()))
    crt, pem = directory/'server.crt', directory/'server.key'
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    pem.chmod(0o600)
    return crt,pem


@pytest.fixture
def upstream(tmp_path):
    crt,key=certificate(tmp_path)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(crt,key)
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body=self.rfile.read(int(self.headers['Content-Length']))
            self.server.bodies.append(body)
            self.send_response(200);self.send_header('Content-Length','2');self.end_headers()
            self.wfile.write(b'OK')
        def log_message(self,*_):
            pass
    class Server(ThreadingHTTPServer):
        daemon_threads=True
        def get_request(self):
            sock,address=super().get_request()
            self.connections += 1
            sock.settimeout(3)
            try:
                return context.wrap_socket(sock,server_side=True),address
            except BaseException:
                sock.close();raise
    server=Server(('127.0.0.1',0),Handler)
    server.bodies=[];server.connections=0
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield server,crt
    server.shutdown();server.server_close();thread.join(timeout=5)


def start(upstream, **extra):
    server,crt=upstream
    endpoint=dict(host='localhost',port=server.server_port,path=PATH,client_ip='127.0.0.1')
    endpoint.update(extra.pop('endpoint',{}))
    return Session(PYTHON,endpoint,AUTH,upstream_ca=extra.pop('upstream_ca',crt),
                   timeout=extra.pop('timeout',15),app_version='synthetic/v1',
                   source_reference='local synthetic TLS harness',**extra)


def body(index=0):
    record=json.loads((ROOT/'tests/fixtures/authy-synthetic.json').read_bytes())['authenticator_tokens'][index]
    record['token_id']=record.pop('unique_id')
    return urlencode(record).encode()


def tunnel(session, port, host='localhost', auth=AUTH):
    sock=socket.create_connection(('127.0.0.1',session.port),timeout=3)
    authorization=base64.b64encode(auth.encode()).decode()
    sock.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {authorization}\r\n\r\n'.encode())
    response=bytearray()
    while b'\r\n\r\n' not in response:
        part=sock.recv(1)
        if not part: break
        response.extend(part)
    return sock,bytes(response)


def request(session, port, *, path=PATH, authority=None, content_type='application/x-www-form-urlencoded',index=0,auth=AUTH,raw_body=None):
    sock,response=tunnel(session,port,auth=auth)
    assert b'200' in response
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(session.certificate))
    with context.wrap_socket(sock,server_hostname='localhost') as tls:
        payload=body(index) if raw_body is None else raw_body
        tls.sendall((f'POST {path} HTTP/1.1\r\nHost: {authority or "localhost:"+str(port)}\r\n'
            f'Content-Type: {content_type}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode()+payload)
        return tls.recv(4096)


def test_actual_tls_capture_and_reaping(upstream):
    with start(upstream) as session:
        directory=session.root
        assert b'200' in request(session,upstream[0].server_port)
        assert session.collect()=='record'
        data=session.finish()
        assert session.process.poll()==0
        assert not directory.exists()
        assert len(json.loads(data)['authenticator_tokens'])==1
    assert upstream[0].bodies==[body()]


def test_transport_metadata_preserved_upstream_but_excluded_from_ipc(upstream):
    payload = body() + b'&api_key=public-test-api-key&locale=en-US&password_timestamp=1700000000&logo=Public'
    with start(upstream) as session:
        assert b'200' in request(session, upstream[0].server_port, raw_body=payload)
        assert session.collect() == 'record'
        data = session.finish()
    assert upstream[0].bodies == [payload]
    assert b'public-test-api-key' not in data
    record = json.loads(data)['authenticator_tokens'][0]
    assert not {'api_key', 'locale', 'password_timestamp', 'logo'} & record.keys()


@pytest.mark.parametrize('override',[dict(path=PATH+'/extra'),dict(authority='lookalike.invalid'),dict(content_type='text/plain')])
def test_out_of_scope_http_not_forwarded(upstream,override):
    with start(upstream) as session:
        assert b'403' in request(session,upstream[0].server_port,**override)
        with pytest.raises(CaptureError):session.finish()
    assert not upstream[0].bodies


@pytest.mark.parametrize('host,auth,status',[
    ('localhost.evil.invalid',AUTH,b'403'),('localhost','wrong:password',b'407')])
def test_connect_restrictions_before_tls(upstream,host,auth,status):
    with start(upstream) as session:
        sock,response=tunnel(session,upstream[0].server_port,host,auth)
        sock.close()
        assert status in response
    assert upstream[0].connections==0


def test_sni_substitution_rejected_before_upstream(upstream):
    with start(upstream) as session:
        sock,response=tunnel(session,upstream[0].server_port)
        assert b'200' in response
        context=ssl.create_default_context(cafile=str(session.certificate))
        with pytest.raises((ssl.SSLError,ConnectionError,OSError)):
            with context.wrap_socket(sock,server_hostname='impostor.invalid'):
                pytest.fail('Substituted SNI completed a TLS handshake')
    assert upstream[0].connections==0


def test_invalid_upstream_certificate_never_captured(upstream):
    with start(upstream,upstream_ca=None) as session:
        assert b'502' in request(session,upstream[0].server_port)
        with pytest.raises(CaptureError):session.finish()
    assert not upstream[0].bodies


def test_unapproved_client_ip_rejected(upstream):
    with start(upstream,endpoint={'client_ip':'127.0.0.2'}) as session:
        try:
            sock,response=tunnel(session,upstream[0].server_port)
            sock.close()
            assert not response
        except ConnectionError:
            pass
    assert upstream[0].connections==0


def test_timeout_is_failure_and_reaps(upstream):
    with start(upstream,timeout=1) as session:
        directory=session.root
        assert session.collect(timeout=5)=='done'
        with pytest.raises(CaptureError):session.finish()
        assert session.process.poll() is not None
        assert not directory.exists()


def test_termination_after_record_is_reaped(upstream):
    with start(upstream) as session:
        assert b'200' in request(session,upstream[0].server_port)
        session.collect()
        session.process.send_signal(signal.SIGTERM)
        data=session.finish()
        assert len(json.loads(data)['authenticator_tokens'])==1
        assert session.process.poll()==0


def test_session_ca_unique_and_key_logging_environment_ignored(upstream,tmp_path,monkeypatch):
    keylog=tmp_path/'tls-keys.log'
    monkeypatch.setenv('SSLKEYLOGFILE',str(keylog))
    monkeypatch.setenv('PYTHONPATH',str(tmp_path))
    with start(upstream) as first, start(upstream) as second:
        assert first.certificate.read_bytes()!=second.certificate.read_bytes()
        for session in (first,second):
            assert b'PRIVATE KEY' not in session.certificate.read_bytes()
            assert session.root.stat().st_mode & 0o777 == 0o700
            assert b'200' in request(session,upstream[0].server_port)
            session.collect()
            session.finish()
    assert not keylog.exists()


def test_capture_to_both_official_proton_importers_after_worker_exit(upstream):
    from authy_migrate.authy import convert_authy
    from authy_migrate.synthetic import PASSWORD
    with start(upstream) as session:
        for index in range(4):
            assert b'200' in request(session,upstream[0].server_port,index=index)
            assert session.collect()=='record'
        captured=session.finish()
        assert session.process.poll()==0
        assert not session.root.exists()
    parameters=json.loads((ROOT/'tests/fixtures/authy-synthetic.json.parameters.json').read_bytes())
    parameters['source_sha256']=hashlib.sha256(captured).hexdigest()
    # These public passwords are first used after the capture worker was reaped.
    archive=convert_authy(captured,'authy-sync-json',json.dumps(parameters).encode(),
                         ' Authy backup synthétique 🔑 ',PASSWORD)
    for name in ['reference/target/debug/authy-migrate-reference-check',
                 'reference/legacy/target/debug/authy-migrate-legacy-check']:
        result=subprocess.run([str(ROOT/name)],input=archive,capture_output=True)
        assert result.returncode==0,'Official importer rejected synthetic capture output'
        assert result.stdout.startswith(b'PASS:')
        assert not result.stderr
    assert upstream[0].bodies==[body(i) for i in range(4)]


def test_plain_http_never_uses_allow_hosts_exception(upstream):
    with start(upstream) as session:
        with socket.create_connection(('127.0.0.1',session.port),timeout=3) as sock:
            auth=base64.b64encode(AUTH.encode()).decode()
            sock.sendall(f'POST http://localhost:{upstream[0].server_port}{PATH} HTTP/1.1\r\nHost: localhost:{upstream[0].server_port}\r\nProxy-Authorization: Basic {auth}\r\nContent-Length: 0\r\n\r\n'.encode())
            assert b'403' in sock.recv(4096)
    assert upstream[0].connections==0


def test_worker_sigkill_is_not_success(upstream):
    with start(upstream) as session:
        root=session.root
        session.process.kill()
        session.process.wait(timeout=5)
        with pytest.raises(CaptureError):session.finish()
        assert not root.exists()


def test_repeated_sync_identifier_is_not_counted_as_another_account(upstream):
    with start(upstream) as session:
        assert b'200' in request(session,upstream[0].server_port)
        session.collect()
        # The source sees its unmodified second request, but capture must fail.
        request(session,upstream[0].server_port)
        with pytest.raises(CaptureError):session.finish()


def test_no_account_material_deliberately_saved_in_session_directory(upstream):
    with start(upstream) as session:
        assert b'200' in request(session,upstream[0].server_port)
        session.collect()
        for path in session.root.rglob('*'):
            if path.is_file():
                contents=path.read_bytes()
                assert b'GEZDGNBVGY3TQOJQ' not in contents
                assert b'demo@example.invalid' not in contents
                assert b'encrypted_seed' not in contents
                assert path.stat().st_mode & 0o077 == 0
        session.finish()


def test_cleanup_failure_prevents_success(upstream,monkeypatch):
    session=start(upstream)
    cleanup=session.directory.cleanup
    try:
        assert b'200' in request(session,upstream[0].server_port)
        session.collect()
        def fail_cleanup():
            raise OSError('Synthetic cleanup failure')
        monkeypatch.setattr(session.directory,'cleanup',fail_cleanup)
        with pytest.raises(OSError,match='Synthetic cleanup failure'):
            session.finish()
        assert session.process.poll()==0
        assert session.root.exists()
    finally:
        monkeypatch.setattr(session.directory,'cleanup',cleanup)
        session.close()
    assert not session.root.exists()


def test_invalid_record_after_valid_record_blocks_partial_conversion(upstream):
    with start(upstream) as session:
        assert b'200' in request(session,upstream[0].server_port)
        session.collect()
        assert b'422' in request(session,upstream[0].server_port,raw_body=b'name=invalid')
        with pytest.raises(CaptureError):session.finish()
    assert upstream[0].bodies==[body()]
