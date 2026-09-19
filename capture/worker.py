"""Private mitmdump engine worker. Configuration arrives only through stdin."""
import asyncio
import json
import logging
import ipaddress
import importlib.metadata
import os
from pathlib import Path
import signal
import struct
import sys

# -I excludes ambient import paths. Only this reviewed checkout is added.
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "src"))
from policy import CaptureError, Endpoint, MAX_BODY, encrypted_record
from policy import DiagnosticEndpoint, diagnose_form, DIAGNOSTIC_STAGES
from version import ENGINE_URL, ENGINE_ARCHIVE_SHA256
from authy_migrate.authy import parse_authy
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster


def send(kind, **values):
    payload = json.dumps({"type": kind, **values}, separators=(",", ":")).encode()
    if len(payload) > MAX_BODY:
        raise CaptureError("IPC message exceeds limit.")
    sys.stdout.buffer.write(struct.pack("!I", len(payload)) + payload)
    sys.stdout.buffer.flush()


class Capture:
    def __init__(self, master, endpoint, diagnostic=False):
        self.master, self.endpoint = master, endpoint
        self.diagnostic = diagnostic
        self.observation = None
        self.timed_out = False
        self.network_error = False
        self.stages = dict.fromkeys(DIAGNOSTIC_STAGES, 0)
        self.tunnels = set()
        self.denied = set()
        self.failed = False
        self.count = 0
        self.total_bytes = 0
        self.total_iterations = 0
        self.clients = set()
        self.identifiers = set()

    def count_stage(self, stage):
        self.stages[stage] = min(1000000, self.stages[stage] + 1)

    def client_connected(self, client):
        if not self.endpoint.client_allowed(client.peername[0]) or len(self.clients) >= 8:
            client.error = "Client not permitted."
        else:
            self.clients.add(client.id)
            self.stages['client_connections'] = min(1000000, self.stages['client_connections'] + 1)

    def client_disconnected(self, client):
        self.tunnels.discard(client.id)
        self.denied.discard(client.id)
        self.clients.discard(client.id)

    def http_connect(self, flow):
        e = self.endpoint
        self.count_stage('connect_requests')
        if flow.request.host == e.host and flow.request.port == e.port:
            self.count_stage('authy_connect_requests')
        # Built-in ProxyAuth runs first; never override its rejection.
        if flow.response is not None:
            if flow.response.status_code == 407:
                self.count_stage('proxy_auth_required')
            return
        rejection = None
        if flow.request.host != e.host or flow.request.port != e.port:
            rejection = 'connect_other_endpoint'
        elif flow.request.authority != f'{e.host}:{e.port}':
            rejection = 'connect_authority_rejected'
        elif not flow.request.headers.get_all('host'):
            rejection = 'connect_host_missing'
        elif flow.request.headers.get_all('host') != [f'{e.host}:{e.port}']:
            rejection = 'connect_host_rejected'
        if rejection:
            self.count_stage(rejection)
            flow.response = http.Response.make(403, b"Endpoint not permitted.")
            return
        self.tunnels.add(flow.client_conn.id)
        self.stages['authy_tunnels'] = min(1000000, self.stages['authy_tunnels'] + 1)

    def tls_clienthello(self, data):
        if (data.context.client.id not in self.tunnels
                or data.client_hello.sni != self.endpoint.host):
            self.denied.add(data.context.client.id)
            self.count_stage('sni_rejected')
            data.establish_server_tls_first = False

    def tls_start_client(self, data):
        # Runs after the engine's TLS configuration hook, before its handshake.
        if data.context.client.id in self.denied:
            data.ssl_conn = None

    def requestheaders(self, flow):
        e = self.endpoint
        if flow.client_conn.id in self.tunnels and flow.client_conn.sni == e.host:
            self.stages['tls_requests'] = min(1000000, self.stages['tls_requests'] + 1)
        if flow.response is not None:
            return
        try:
            allowed = (flow.client_conn.id in self.tunnels
                       and flow.client_conn.sni == e.host
                       and e.request_allowed(flow.request.method, flow.request.scheme,
                           flow.request.host, flow.request.port, flow.request.path,
                           flow.request.headers))
        except ValueError:
            allowed = False
        if not allowed:
            flow.response = http.Response.make(403, b"Request not permitted.")

    def request(self, flow):
        if flow.response is not None:
            return
        if self.diagnostic:
            self.stages['matching_requests'] = min(1000000, self.stages['matching_requests'] + 1)
            from urllib.parse import urlsplit
            target = urlsplit(flow.request.path)
            if self.observation is None:
                self.observation = dict(path=target.path, facts=diagnose_form(
                    flow.request.raw_content, parse_authy, has_query='?' in flow.request.path))
            # Diagnostic requests never reach Authy. This intentionally interrupts sync.
            flow.response = http.Response.make(409, b'Diagnostic only; request not forwarded.')
            return
        try:
            flow.metadata["encrypted_record"] = encrypted_record(
                flow.request.raw_content, parse_authy)
        except CaptureError:
            flow.response = http.Response.make(422, b"Invalid encrypted record.")
            self.failed = True

    def response(self, flow):
        record = flow.metadata.pop("encrypted_record", None)
        if record is None:
            return
        if not 200 <= flow.response.status_code < 300:
            self.failed = True
            return
        if record['unique_id'] in self.identifiers:
            self.failed = True
            self.master.shutdown()
            return
        self.identifiers.add(record['unique_id'])
        self.count += 1
        self.total_bytes += len(json.dumps(record))
        self.total_iterations += int(record["key_derivation_iterations"])
        if (self.count > 1000 or self.total_bytes > 8 * 1024 * 1024
                or self.total_iterations > 10_000_000):
            self.failed = True
            self.master.shutdown()
            return
        send("record", record=record)

    def error(self, flow):
        self.failed = True
        self.network_error = True

    async def running(self):
        server = self.master.addons.get("proxyserver")
        for _ in range(100):
            addresses = server.listen_addrs()
            if addresses:
                send("ready", port=addresses[0][1])
                return
            await asyncio.sleep(.05)
        self.failed = True
        self.master.shutdown()


async def run(config):
    distribution = importlib.metadata.distribution('mitmproxy')
    source = json.loads(distribution.read_text('direct_url.json') or '{}')
    if (distribution.version != '13.0.0.dev0' or source.get('url') != ENGINE_URL
            or source.get('archive_info', {}).get('hashes', {}).get('sha256') != ENGINE_ARCHIVE_SHA256):
        raise CaptureError('Capture engine does not match the pinned source.')
    required = {"endpoint", "confdir", "listen_host", "proxy_auth", "timeout"}
    if set(config) - required - {"upstream_ca", "diagnostic"} or not required <= config.keys():
        raise CaptureError("Invalid worker configuration.")
    endpoint = Endpoint(**config["endpoint"])
    diagnostic = config.get('diagnostic', False)
    if type(diagnostic) is not bool:
        raise CaptureError('Invalid diagnostic mode.')
    if diagnostic:
        endpoint = DiagnosticEndpoint(endpoint)
    if (type(config["timeout"]) is not int or not 1 <= config["timeout"] <= 300
            or not ipaddress.ip_address(config["listen_host"]).is_private
            or ipaddress.ip_address(config["listen_host"]).is_unspecified
            or type(config["proxy_auth"]) is not str
            or not 20 <= len(config["proxy_auth"]) <= 256
            or config["proxy_auth"].count(":") != 1):
        raise CaptureError("Invalid session bounds or authentication.")
    directory = Path(config["confdir"])
    if (not directory.is_dir() or directory.is_symlink() or list(directory.iterdir())
            or directory.stat().st_uid != os.getuid()
            or directory.stat().st_mode & 0o077):
        raise CaptureError("Capture requires a fresh private directory.")
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    opts = options.Options(confdir=str(directory), listen_host=config["listen_host"],
                           listen_port=0, mode=["regular"], ssl_insecure=False)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    opts.update(proxyauth=config["proxy_auth"], connection_strategy="lazy",
                body_size_limit=str(MAX_BODY), onboarding=False,
                command_history=False, rawtcp=False, http2=False, http3=False,
                scripts=[], save_stream_file=None, hardump="",
                ssl_verify_upstream_trusted_ca=config.get("upstream_ca"),
                allow_hosts=[rf"^{endpoint.host.replace('.', '[.]')}:{endpoint.port}$"])
    capture = Capture(master, endpoint, diagnostic)
    master.addons.add(capture)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, master.shutdown)
    def timeout():
        capture.failed = True
        capture.timed_out = True
        master.shutdown()
    timer = loop.call_later(config["timeout"], timeout)
    try:
        await master.run()
    finally:
        timer.cancel()
    if diagnostic:
        send('diagnostic_status', stages=capture.stages,
             timed_out=capture.timed_out, network_error=capture.network_error)
        if capture.observation is not None:
            send('diagnostic', **capture.observation)
    send("done", ok=not capture.failed)


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise CaptureError("Configuration exceeds limit.")
        asyncio.run(run(json.loads(raw)))
    except BaseException:
        # Neither tracebacks nor TLS/parser errors cross the process boundary.
        try:
            send("failed")
        finally:
            sys.exit(1)
