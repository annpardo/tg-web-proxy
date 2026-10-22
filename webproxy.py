"""Telegram WEB v1 transport for the existing Python MTProxy backend.

Only the documented websocket carrier is advertised. HTTP bootstrap, native
WebView/MessagePort boundaries and shared frames follow Telegram's public v1
wire contract. No native binaries or runtime downloads are required.
"""
import asyncio
import base64
import collections
import contextlib
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import time

OPEN, DATA, CLOSE, WINDOW, PONG = 1, 2, 3, 4, 6
INITIAL_WINDOW = 4 * 1024 * 1024
MAX_PAYLOAD = 1024 * 1024
MAX_BATCH = 2 * 1024 * 1024
MAX_FRAMES = 4096
MAX_STREAMS = 32
MAX_SESSIONS = 16
MAX_CONNECTIONS = 128
MAX_PENDING = 8 * 1024 * 1024
MAX_GLOBAL_PENDING = 64 * 1024 * 1024
HELLO = bytes.fromhex("100000000000000101")
WELCOME = bytes.fromhex("1100000000000000")
HOME = b"<!doctype html><meta charset=utf-8><title>Welcome</title><h1>Welcome</h1>"
CF_NETWORKS = tuple(ipaddress.ip_network(s) for s in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32"))


def canonical_domain(value):
    if not isinstance(value, str):
        raise ValueError("WEB_DOMAIN must be a hostname")
    value = value.strip().lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Invalid WEB_DOMAIN") from error
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(value) > 253 or not re.fullmatch(label + r"(?:\." + label + r")+", value):
        raise ValueError("WEB_DOMAIN: use a hostname without https://, port or path")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("WEB_DOMAIN must be a DNS hostname, not an IP address")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def normalize_secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:dd)?[0-9a-f]{32}", value, re.IGNORECASE):
        raise ValueError("WEB secret must be 32 hex characters, or dd followed by 32 hex characters")
    return value.lower()


def capability(domain, secret):
    return b64(hmac.new(bytes.fromhex(normalize_secret(secret)),
        ("tdesktop-web-proxy-bridge-v1\n" + domain).encode(), hashlib.sha256).digest())


def frame(kind, stream, payload=b""):
    return bytes([kind]) + stream.to_bytes(3, "big") + len(payload).to_bytes(4, "big") + payload


class ProtocolError(Exception):
    pass


def parse_frames(data):
    if not data or len(data) > MAX_BATCH:
        raise ProtocolError("invalid shared batch size")
    values, offset = [], 0
    while offset < len(data):
        if len(data) - offset < 8 or len(values) >= MAX_FRAMES:
            raise ProtocolError("truncated/oversized shared batch")
        kind = data[offset]
        stream = int.from_bytes(data[offset+1:offset+4], "big")
        size = int.from_bytes(data[offset+4:offset+8], "big")
        end = offset + 8 + size
        if size > MAX_PAYLOAD or end > len(data):
            raise ProtocolError("invalid shared payload")
        payload = data[offset+8:end]
        if stream == 0:
            # We do not issue shared-frame PING; therefore no PONG is expected.
            raise ProtocolError("unexpected session frame")
        if kind in (OPEN, CLOSE):
            valid = size == 0
        elif kind == DATA:
            valid = size > 0
        elif kind == WINDOW:
            valid = size == 4 and int.from_bytes(payload, "big") > 0
        else:
            valid = False
        if not valid:
            raise ProtocolError("invalid shared frame shape")
        values.append((kind, stream, payload))
        offset = end
    return values


def private_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    descriptor = os.open(str(temp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
        os.replace(str(temp), str(path))
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def tls_context(domain, directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    directory = Path(directory)
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    now = datetime.datetime.now(datetime.timezone.utc)
    reusable = False
    if cert_path.is_file() and key_path.is_file():
        try:
            certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            expiry = getattr(certificate, "not_valid_after_utc", None)
            if expiry is None:
                expiry = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            reusable = domain in names.get_values_for_type(x509.DNSName) and expiry > now + datetime.timedelta(days=7)
        except (ValueError, x509.ExtensionNotFound):
            pass
    if not reusable:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
        private_file(key_path, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private_file(cert_path, certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


class WebSocket:
    """Bounded RFC 6455 binary carrier. Client messages must be masked."""
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.lock = asyncio.Lock()
        self.last_received = time.monotonic()
        self.fragments = bytearray()
        self.fragmented = False

    async def send(self, payload, opcode=2):
        async with self.lock:
            length = len(payload)
            header = bytes([0x80 | opcode])
            if length < 126:
                header += bytes([length])
            elif length < 65536:
                header += b"\x7e" + struct.pack("!H", length)
            else:
                header += b"\x7f" + struct.pack("!Q", length)
            self.writer.write(header + payload)
            await asyncio.wait_for(self.writer.drain(), 30)

    async def read_frame(self):
        head = await self.reader.readexactly(2)
        fin, opcode = bool(head[0] & 128), head[0] & 15
        if head[0] & 112 or not head[1] & 128 or opcode not in (0, 2, 8, 9, 10):
            raise ProtocolError("unsupported websocket frame")
        size, marker = head[1] & 127, head[1] & 127
        if marker == 126:
            size = int.from_bytes(await self.reader.readexactly(2), "big")
            if size < 126:
                raise ProtocolError("noncanonical websocket size")
        elif marker == 127:
            size = int.from_bytes(await self.reader.readexactly(8), "big")
            if size < 65536 or size >= 2**63:
                raise ProtocolError("noncanonical websocket size")
        if size > MAX_BATCH or (opcode >= 8 and (not fin or size > 125)):
            raise ProtocolError("oversized websocket frame")
        mask = await self.reader.readexactly(4)
        payload = await self.reader.readexactly(size)
        # Slice translation applies the four mask bytes without a Python byte loop.
        decoded = bytearray(payload)
        for i, value in enumerate(mask):
            decoded[i::4] = decoded[i::4].translate(bytes(x ^ value for x in range(256)))
        self.last_received = time.monotonic()
        return fin, opcode, bytes(decoded)

    async def receive(self):
        while True:
            pending = asyncio.create_task(self.read_frame())
            try:
                while not pending.done():
                    done, _ = await asyncio.wait({pending}, timeout=25)
                    if not done:
                        if time.monotonic() - self.last_received >= 50:
                            raise ProtocolError("websocket heartbeat timeout")
                        await self.send(secrets.token_bytes(8), 9)
                fin, opcode, data = pending.result()
            finally:
                if not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
            if opcode == 8:
                if len(data) == 1:
                    raise ProtocolError("invalid websocket close")
                if len(data) >= 2:
                    code = int.from_bytes(data[:2], "big")
                    if code < 1000 or code >= 5000 or code in (1004, 1005, 1006, 1015) or 1016 <= code < 3000:
                        raise ProtocolError("invalid websocket close code")
                    try:
                        data[2:].decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise ProtocolError("invalid websocket close reason") from error
                await self.send(data, 8)
                return None
            if opcode == 9:
                await self.send(data, 10)
                continue
            if opcode == 10:
                continue
            if opcode == 2:
                if self.fragmented:
                    raise ProtocolError("interleaved websocket messages")
                if fin:
                    return data
                self.fragmented = True
                self.fragments.extend(data)
            else:
                if not self.fragmented:
                    raise ProtocolError("unexpected websocket continuation")
                self.fragments.extend(data)
                if len(self.fragments) > MAX_BATCH:
                    raise ProtocolError("oversized fragmented message")
                if fin:
                    result = bytes(self.fragments)
                    self.fragments.clear()
                    self.fragmented = False
                    return result


class Stream:
    def __init__(self, session, number):
        self.session, self.number = session, number
        self.send_credit = self.receive_credit = INITIAL_WINDOW
        self.queue = collections.deque()
        self.cost = 0
        self.data_ready = asyncio.Event()
        self.credit_ready = asyncio.Event()
        self.writer = None
        self.task = None
        self.closed = False

    async def run(self):
        pumps = []
        try:
            reader, self.writer = await asyncio.wait_for(asyncio.open_connection(
                "127.0.0.1", self.session.owner.backend_port), 5)
            if self.closed:
                return
            pumps = [asyncio.create_task(self.upload()), asyncio.create_task(self.download(reader))]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ProtocolError):
            pass
        finally:
            for task in pumps:
                task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            if self.writer:
                self.writer.close()
                with contextlib.suppress(OSError):
                    await self.writer.wait_closed()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await self.session.end_stream(self.number, notify=True)

    async def upload(self):
        while not self.closed:
            if not self.queue:
                self.data_ready.clear()
                await self.data_ready.wait()
                continue
            data = self.queue.popleft()
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), 30)
            if self.closed:
                return
            charge = len(data) + 256
            self.session.release(charge)
            self.cost -= charge
            self.receive_credit += len(data)
            await self.session.send(WINDOW, self.number, len(data).to_bytes(4, "big"))

    async def download(self, reader):
        while not self.closed:
            if not self.send_credit:
                self.credit_ready.clear()
                await self.credit_ready.wait()
                continue
            data = await reader.read(min(65536, self.send_credit))
            if not data:
                return
            self.send_credit -= len(data)
            await self.session.send(DATA, self.number, data)


class Session:
    def __init__(self, owner, token, user):
        self.owner, self.token, self.user = owner, token, user
        self.created = time.monotonic()
        self.ws = None
        self.streams = {}
        # 2 MiB bitmap prevents ID reuse for the entire session without an
        # unbounded Python set; IDs have exactly 24 bits in the wire format.
        self.seen = bytearray(1 << 21)
        self.pending = 0
        self.closed = False
        self.tasks = set()
        self.send_lock = asyncio.Lock()

    def was_seen(self, sid):
        return bool(self.seen[sid >> 3] & (1 << (sid & 7)))

    def remember(self, sid):
        self.seen[sid >> 3] |= 1 << (sid & 7)

    def release(self, cost):
        self.pending -= cost
        self.owner.pending -= cost
        self.owner.budget_ready.set()

    async def send(self, kind, sid, payload=b""):
        async with self.send_lock:
            if self.closed or (kind != CLOSE and sid not in self.streams):
                return
            await self.ws.send(frame(kind, sid, payload))

    async def end_stream(self, sid, notify):
        stream = self.streams.pop(sid, None)
        if stream is None:
            return
        stream.closed = True
        stream.queue.clear()
        self.release(stream.cost)
        stream.cost = 0
        self.owner.stream_count -= 1
        stream.data_ready.set()
        stream.credit_ready.set()
        if stream.writer:
            stream.writer.transport.abort()
        if stream.task and stream.task is not asyncio.current_task():
            stream.task.cancel()
        if notify and not self.closed:
            await self.send(CLOSE, sid)

    async def process(self, data):
        values = parse_frames(data)
        for kind, sid, payload in values:
            if self.closed:
                return
            stream = self.streams.get(sid)
            if kind == OPEN:
                if self.was_seen(sid):
                    raise ProtocolError("stream ID reused")
                self.remember(sid)
                if len(self.streams) >= MAX_STREAMS or self.owner.stream_count >= 128:
                    await self.send(CLOSE, sid)
                    continue
                stream = Stream(self, sid)
                self.streams[sid] = stream
                self.owner.stream_count += 1
                stream.task = asyncio.create_task(stream.run())
                self.tasks.add(stream.task)
                stream.task.add_done_callback(self.tasks.discard)
            elif stream is None:
                if not self.was_seen(sid):
                    raise ProtocolError("unknown stream")
                # Late DATA/WINDOW/CLOSE from an already-closed stream is ignored.
            elif kind == CLOSE:
                await self.end_stream(sid, notify=False)
            elif kind == WINDOW:
                stream.send_credit = min(0xffffffff, stream.send_credit + int.from_bytes(payload, "big"))
                stream.credit_ready.set()
            else:
                if len(payload) > stream.receive_credit:
                    raise ProtocolError("receive window exceeded")
                charge = len(payload) + 256
                deadline = time.monotonic() + 30
                while self.pending + charge > MAX_PENDING or self.owner.pending + charge > MAX_GLOBAL_PENDING:
                    self.owner.budget_ready.clear()
                    await asyncio.wait_for(self.owner.budget_ready.wait(), max(0.01, deadline - time.monotonic()))
                    if stream.closed or self.closed:
                        break
                if stream.closed or self.closed:
                    continue
                stream.receive_credit -= len(payload)
                stream.cost += charge
                self.pending += charge
                self.owner.pending += charge
                stream.queue.append(payload)
                stream.data_ready.set()

    async def run(self, reader, writer):
        self.ws = WebSocket(reader, writer)
        try:
            while True:
                message = await self.ws.receive()
                if message is None:
                    return
                await self.process(message)
        except ProtocolError:
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await self.ws.send(struct.pack("!H", 1002), 8)
        finally:
            await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.owner.sessions.pop(self.token, None)
        for token, record in list(self.owner.bootstraps.items()):
            if record["session"] is self:
                self.owner.bootstraps.pop(token, None)
        for sid in list(self.streams):
            await self.end_stream(sid, notify=False)
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.ws:
            self.ws.writer.close()
        self.owner.budget_ready.set()


class WebProxyServer:
    def __init__(self, config, backend_handler, state_dir):
        self.config = config
        self.domain = canonical_domain(config.WEB_DOMAIN)
        self.backend_handler = backend_handler
        self.state_dir = Path(state_dir)
        # WEB_TLS = False: serve plain HTTP/WS on PORT and let the layer in front
        # (InstaCloud http endpoint, nginx) terminate TLS.
        self.context = tls_context(self.domain, self.state_dir) if getattr(config, "WEB_TLS", True) else None
        key_path = self.state_dir / "token.key"
        if not key_path.exists():
            private_file(key_path, secrets.token_bytes(32))
        self.key = key_path.read_bytes()
        if len(self.key) != 32:
            raise ValueError(".webproxy/token.key must contain 32 bytes")
        self.capabilities = {capability(self.domain, secret): user for user, secret in config.USERS.items()}
        self.bootstraps = {}
        self.sessions = {}
        self.servers = []
        self.connections = set()
        self.backend_tasks = set()
        self.pending = self.stream_count = 0
        self.budget_ready = asyncio.Event()
        self.cleanup_task = None
        self.close_task = None
        self.backend_port = None
        self.closing = False
        self.rate = collections.OrderedDict()

    async def start(self):
        try:
            backend = await asyncio.start_server(self.backend, "127.0.0.1", 0, limit=65536)
            self.servers.append(backend)
            self.backend_port = backend.sockets[0].getsockname()[1]
            addresses = []
            if self.config.LISTEN_ADDR_IPV4:
                addresses.append(self.config.LISTEN_ADDR_IPV4)
            if self.config.LISTEN_ADDR_IPV6 and socket.has_ipv6:
                addresses.append(self.config.LISTEN_ADDR_IPV6)
            if not addresses:
                raise ValueError("No WEB listen address enabled")
            for address in addresses:
                try:
                    server = await asyncio.start_server(self.connection, address, self.config.PORT,
                        ssl=self.context, ssl_handshake_timeout=10 if self.context else None, limit=16384)
                except OSError:
                    if ":" in address and len(self.servers) > 1:
                        print("WEB: IPv6 listener unavailable; IPv4 listener remains active", flush=True)
                        continue
                    raise
                self.servers.append(server)
            self.cleanup_task = asyncio.create_task(self.cleanup())
            print("WEB HTTPS listening on PORT={}; transport=websocket".format(self.config.PORT), flush=True)
        except BaseException:
            await self.aclose()
            raise

    async def backend(self, reader, writer):
        task = asyncio.current_task()
        self.backend_tasks.add(task)
        try:
            await self.backend_handler(reader, writer)
        finally:
            self.backend_tasks.discard(task)
            writer.close()

    def token(self, kind):
        nonce = secrets.token_bytes(16)
        mac = hmac.new(self.key, b"tproxy-server-token-v1\0" + bytes([kind]) + nonce, hashlib.sha256).digest()[:16]
        return b64(nonce + mac)

    def authenticated_token(self, token, kind):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return False
        raw = base64.urlsafe_b64decode(token + "=")
        if b64(raw) != token:
            return False
        expected = hmac.new(self.key, b"tproxy-server-token-v1\0" + bytes([kind]) + raw[:16], hashlib.sha256).digest()[:16]
        return hmac.compare_digest(expected, raw[16:])

    def client_ip(self, headers, writer):
        peer = writer.get_extra_info("peername")[0]
        try:
            address = ipaddress.ip_address(peer)
            if getattr(address, "ipv4_mapped", None):
                address = address.ipv4_mapped
            if any(address in net for net in CF_NETWORKS):
                return str(ipaddress.ip_address(headers.get("cf-connecting-ip", peer)))
        except ValueError:
            pass
        # A provider NAT gateway may hide Cloudflare's peer address. Authentication
        # still uses the capability/token; don't reject that legitimate topology.
        return peer

    def allow_bootstrap(self, client):
        minute = int(time.monotonic() // 60)
        bucket = self.rate.pop(client, (minute, 0))
        count = bucket[1] if bucket[0] == minute else 0
        self.rate[client] = (minute, count + 1)
        while len(self.rate) > 1024:
            self.rate.popitem(last=False)
        return count < 60 and len(self.bootstraps) < 256

    async def cleanup(self):
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            for token, record in list(self.bootstraps.items()):
                if record["expires"] < now:
                    self.bootstraps.pop(token, None)
            for session in list(self.sessions.values()):
                if session.ws is None and now - session.created > 120:
                    await session.close()

    async def response(self, writer, status=200, body=b"", headers=None, head=False):
        reasons = {200:"OK", 204:"No Content", 400:"Bad Request", 404:"Not Found", 503:"Service Unavailable"}
        values = {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body)),
                  "Connection": "close", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        values.update(headers or {})
        line = f"HTTP/1.1 {status} {reasons[status]}\r\n"
        writer.write((line + "".join(f"{k}: {v}\r\n" for k, v in values.items()) + "\r\n").encode("ascii"))
        if not head:
            writer.write(body)
        await asyncio.wait_for(writer.drain(), 15)

    async def request(self, reader):
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        if len(raw) > 16384:
            raise ProtocolError("header too large")
        lines = raw[:-4].split(b"\r\n")
        method, target, version = lines[0].decode("ascii").split(" ")
        if version != "HTTP/1.1" or not target.startswith("/") or "#" in target:
            raise ProtocolError("invalid HTTP request line")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ProtocolError("invalid header")
            value = value.strip(b" \t")
            if any(c < 32 and c != 9 or c == 127 for c in value):
                raise ProtocolError("invalid header value")
            name = name.decode("ascii").lower()
            if name in headers:
                # Combining security-relevant headers can create ambiguous routing.
                raise ProtocolError("duplicate header")
            headers[name] = value.decode("latin1")
        if "content-length" in headers and "transfer-encoding" in headers:
            raise ProtocolError("ambiguous HTTP framing")
        return method, target, headers

    async def body(self, reader, headers):
        if "transfer-encoding" in headers:
            if headers["transfer-encoding"].lower() != "chunked":
                raise ProtocolError("unsupported encoding")
            data = bytearray()
            while True:
                line = await reader.readuntil(b"\r\n")
                if len(line) > 128 or not re.fullmatch(rb"[0-9a-fA-F]+\r\n", line):
                    raise ProtocolError("invalid HTTP chunk")
                size = int(line[:-2], 16)
                if len(data) + size > 64:
                    raise ProtocolError("create body too large")
                if not size:
                    if await reader.readexactly(2) != b"\r\n":
                        raise ProtocolError("trailers are not supported")
                    return bytes(data)
                data.extend(await reader.readexactly(size))
                if await reader.readexactly(2) != b"\r\n":
                    raise ProtocolError("invalid HTTP chunk ending")
        value = headers.get("content-length", "0")
        if not re.fullmatch(r"[0-9]+", value) or len(value) > 4 or int(value) > 64:
            raise ProtocolError("create body too large")
        return await reader.readexactly(int(value))

    async def connection(self, reader, writer):
        task = asyncio.current_task()
        if self.closing or len(self.connections) >= MAX_CONNECTIONS:
            writer.close()
            return
        self.connections.add(task)
        try:
            method, target, headers = await self.request(reader)
            if headers.get("host", "").lower() not in (self.domain, self.domain + ":443"):
                await self.response(writer, 404)
                return
            cap = target[len("/?bridge="):] if target.startswith("/?bridge=") else ""
            user = self.capabilities.get(cap)
            if method == "GET" and user is not None:
                if not self.allow_bootstrap(self.client_ip(headers, writer)):
                    await self.response(writer, 503, headers={"Retry-After":"1"})
                    return
                token = self.token(1)
                self.bootstraps[token] = {"user":user, "expires":time.monotonic()+120, "session":None}
                html, extra = render_bridge(token, self.domain)
                await self.response(writer, body=html, headers=extra)
            elif target == "/api/v1/session":
                authorization = headers.get("authorization", "")
                token = authorization[7:] if authorization.startswith("Bearer ") else ""
                if "cookie" in headers:
                    await self.response(writer, 404)
                    return
                if method == "DELETE":
                    session = self.sessions.get(token) if self.authenticated_token(token, 2) else None
                    if session is None:
                        await self.response(writer, 404)
                        return
                    await session.close()
                    await self.response(writer, 204)
                    return
                record = self.bootstraps.get(token) if self.authenticated_token(token, 1) else None
                if (method != "POST" or headers.get("content-type", "").lower() != "application/octet-stream"
                        or record is None or record["expires"] < time.monotonic()):
                    await self.response(writer, 404)
                    return
                if await asyncio.wait_for(self.body(reader, headers), 10) != HELLO:
                    await self.response(writer, 404)
                    return
                session = record["session"]
                if session is None:
                    if len(self.sessions) >= MAX_SESSIONS:
                        await self.response(writer, 503, headers={"Retry-After":"1"})
                        return
                    session = Session(self, self.token(2), record["user"])
                    self.sessions[session.token] = session
                    record["session"] = session
                if session.closed:
                    await self.response(writer, 404)
                    return
                await self.response(writer, body=WELCOME, headers={"Content-Type":"application/octet-stream",
                    "X-Session-Token":session.token, "X-Down-Cursor":"0", "X-Carrier-Mode":"websocket"})
            elif target == "/api/v1/ws" and method == "GET":
                protocol = headers.get("sec-websocket-protocol", "")
                token = protocol[len("tproxy-v1."):] if protocol.startswith("tproxy-v1.") else ""
                session = self.sessions.get(token) if self.authenticated_token(token, 2) else None
                key = headers.get("sec-websocket-key", "")
                try:
                    valid_key = len(base64.b64decode(key, validate=True)) == 16
                except ValueError:
                    valid_key = False
                if (session is None or session.closed or session.ws is not None or not valid_key
                        or headers.get("upgrade", "").lower() != "websocket"
                        or "upgrade" not in [s.strip().lower() for s in headers.get("connection", "").split(",")]
                        or headers.get("sec-websocket-version") != "13"
                        or headers.get("content-length", "0") != "0" or "transfer-encoding" in headers):
                    await self.response(writer, 404)
                    return
                # Reserve before the first await; simultaneous upgrades must not
                # acquire the same relay session.
                session.ws = WebSocket(reader, writer)
                accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n").encode())
                try:
                    await asyncio.wait_for(writer.drain(), 10)
                    await session.run(reader, writer)
                finally:
                    await session.close()
            else:
                # No file serving: config.py, keys and user files cannot become
                # reachable through a URL, including path-traversal requests.
                await self.response(writer, body=HOME, head=method == "HEAD")
        except (ProtocolError, ValueError, UnicodeError, asyncio.LimitOverrunError):
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await self.response(writer, 400)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            self.connections.discard(task)
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 3)

    def close(self):
        if self.close_task is None:
            self.close_task = asyncio.create_task(self.aclose())

    async def wait_closed(self):
        if self.close_task is not None:
            await self.close_task

    async def aclose(self):
        self.closing = True
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()
        for session in list(self.sessions.values()):
            await session.close()
        tasks = list(self.connections | self.backend_tasks)
        if self.cleanup_task:
            tasks.append(self.cleanup_task)
        current = asyncio.current_task()
        tasks = [task for task in tasks if task is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.bootstraps.clear()


def render_bridge(token, domain):
    nonce = b64(secrets.token_bytes(18))
    script = BRIDGE_JS.replace("__BOOTSTRAP__", json.dumps(token))
    html = ("<!doctype html><meta charset=utf-8><title>Connection</title>"
        f'<script nonce="{nonce}">' + script + "</script>").encode()
    policy = ("default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://" + domain +
        "; font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; frame-src 'none'; "
        "img-src 'none'; manifest-src 'none'; media-src 'none'; object-src 'none'; "
        f"script-src 'nonce-{nonce}'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts")
    return html, {"Content-Security-Policy":policy, "Referrer-Policy":"no-referrer",
        "X-DNS-Prefetch-Control":"off", "Permissions-Policy":"camera=(), microphone=(), geolocation=(), payment=(), usb=()"}


BRIDGE_JS = r"""
(() => {
  'use strict';
  const bootstrap = __BOOTSTRAP__;
  const origin = location.origin;
  const nonce = /^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1];
  history.replaceState(null, '', location.pathname);
  const batchLimit = 2 * 1024 * 1024, queueLimit = 32 * 1024 * 1024;
  let port = null, native = false, started = false, closed = false;
  let socket = null, token = null, timer = 0, pendingBytes = 0, busy = false;
  let pending = [], controller = null;
  const emit = value => { if (port) port.postMessage(value); };
  const status = state => { if (!closed) emit({t:'status', state}); };
  const frames = buffer => {
    if (!(buffer instanceof ArrayBuffer) || !buffer.byteLength || buffer.byteLength > batchLimit) throw Error('bad batch');
    const view = new DataView(buffer), result = [];
    let at = 0;
    while (at < buffer.byteLength) {
      if (at + 8 > buffer.byteLength || result.length >= 4096) throw Error('bad header');
      const length = view.getUint32(at + 4);
      if (length > 1048576 || at + 8 + length > buffer.byteLength) throw Error('bad payload');
      result.push(buffer.slice(at, at + 8 + length));
      at += 8 + length;
    }
    return result;
  };
  function deliver(buffer) {
    const list = frames(buffer);
    if (native) for (const item of list) emit(item);
    else emit(buffer);
  }
  function options(method, bearer, body, signal) {
    const headers = {'Authorization':'Bearer ' + bearer};
    if (body !== undefined) headers['Content-Type'] = 'application/octet-stream';
    return {method, headers, body, signal, mode:'same-origin', credentials:'omit',
      cache:'no-store', redirect:'error', referrerPolicy:'no-referrer'};
  }
  function close(notify) {
    if (closed) return;
    closed = true;
    if (timer) clearTimeout(timer);
    if (controller) controller.abort();
    pending = []; pendingBytes = 0;
    if (socket) { try { socket.close(); } catch (_) {} }
    if (notify && token) fetch(origin + '/api/v1/session', options('DELETE', token)).catch(() => {});
    if (port) port.close();
  }
  function fail() { if (!closed) { status('failed'); emit({t:'close'}); close(true); } }
  function drain() {
    timer = 0;
    if (closed || busy || !socket || socket.readyState !== WebSocket.OPEN || !pending.length) return;
    if (socket.bufferedAmount > batchLimit) { timer = setTimeout(drain, 10); return; }
    busy = true;
    try {
      let size = 0, count = 0;
      while (count < pending.length && count < 4096 && size + pending[count].byteLength <= batchLimit) {
        size += pending[count++].byteLength;
      }
      if (!count) throw Error('oversized frame');
      const output = new Uint8Array(size);
      let offset = 0;
      for (const item of pending.splice(0, count)) { output.set(new Uint8Array(item), offset); offset += item.byteLength; }
      pendingBytes -= size;
      socket.send(output.buffer);
      emit({t:'traffic', up:size, down:0});
    } catch (_) { fail(); }
    finally { busy = false; }
    if (pending.length && !closed) timer = setTimeout(drain, 0);
  }
  function queue(data) {
    const values = frames(data);
    if (pendingBytes + data.byteLength + (socket ? socket.bufferedAmount : 0) > queueLimit || pending.length + values.length > 16384) throw Error('queue full');
    pending.push(...values); pendingBytes += data.byteLength; drain();
  }
  async function create(hello) {
    try {
      const wire = new Uint8Array(hello);
      if (wire.length !== 9 || wire[0] !== 16 || wire[7] !== 1 || wire[8] !== 1 || wire.slice(1,7).some(x=>x!==0)) throw Error('bad hello');
      const deadline = Date.now() + 90000;
      let response, failures = 0;
      while (!closed) {
        controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        try { response = await fetch(origin + '/api/v1/session', options('POST', bootstrap, hello, controller.signal)); }
        catch (error) { if (++failures > 3 || Date.now() > deadline) throw error; response = null; }
        finally { clearTimeout(timeout); controller = null; }
        if (response && response.ok) break;
        if (response && response.status !== 503) throw Error('session failed');
        if (Date.now() > deadline) throw Error('session timeout');
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      if (closed) return;
      token = response.headers.get('X-Session-Token');
      if (!/^[A-Za-z0-9_-]{43}$/.test(token || '') || response.headers.get('X-Carrier-Mode') !== 'websocket') throw Error('bad session');
      const welcome = await response.arrayBuffer();
      const check = new Uint8Array(welcome);
      if (check.length !== 8 || check[0] !== 17 || check.slice(1).some(x=>x!==0)) throw Error('bad welcome');
      socket = new WebSocket(origin.replace(/^https:/, 'wss:') + '/api/v1/ws', 'tproxy-v1.' + token);
      socket.binaryType = 'arraybuffer';
      const opening = setTimeout(fail, 15000);
      socket.onopen = () => {
        clearTimeout(opening);
        if (closed) { socket.close(); return; }
        deliver(welcome); status('connected'); drain();
      };
      socket.onmessage = event => {
        if (closed) return;
        try { deliver(event.data); emit({t:'traffic', up:0, down:event.data.byteLength}); }
        catch (_) { fail(); }
      };
      socket.onerror = () => { clearTimeout(opening); fail(); };
      socket.onclose = () => { clearTimeout(opening); if (!closed) fail(); };
    } catch (_) { if (!closed) fail(); }
  }
  function activate(next) {
    port = next;
    port.onmessage = event => {
      if (closed) return;
      try {
        if (event.data instanceof ArrayBuffer) {
          if (!started) { started = true; create(event.data); }
          else queue(event.data);
        } else if (event.data && event.data.t === 'close') close(true);
      } catch (_) { fail(); }
    };
    port.start(); status('connecting');
  }
  addEventListener('message', event => {
    if (port || event.source !== parent || !event.data || typeof event.data !== 'object') return;
    if (Object.keys(event.data).sort().join(',') !== 't,v' || event.data.t !== 'tproxy-init' || event.data.v !== 1 || event.ports.length !== 1) return;
    let from; try { from = new URL(event.origin); } catch (_) { return; }
    if (from.protocol !== 'http:' || from.hostname !== '127.0.0.1' || !from.port || from.origin !== event.origin) return;
    activate(event.ports[0]);
  });
  const bridge = globalThis.TelegramWebProxy;
  if (nonce && /^[A-Za-z0-9_-]{43}$/.test(nonce) && bridge && typeof bridge.postMessage === 'function') {
    native = true;
    const adapted = {onmessage:null, start(){}, close(){bridge.onmessage=null;},
      postMessage(value){bridge.postMessage(value instanceof ArrayBuffer ? value : JSON.stringify(value));}};
    bridge.onmessage = event => {
      let data = event.data;
      if (typeof data === 'string') { try { data = JSON.parse(data); } catch (_) { return; } }
      if (adapted.onmessage) adapted.onmessage({data});
    };
    activate(adapted);
    bridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce}));
  }
  addEventListener('pagehide', () => close(true), {once:true});
})();
"""
