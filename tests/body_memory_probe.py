"""Wire and resource checks for body_memory_integration.sh (no benchmark)."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import zlib

import h2.connection
import h2.events

PORT, PID = map(int, sys.argv[1:3])
WORK, BUILD = map(Path, sys.argv[3:5])
THRESHOLD = 1048576
REPEATS = int(os.environ.get('BODY_SOAK_REQUESTS', '1000'))
SECONDS = int(os.environ.get('BODY_SOAK_SECONDS', '30'))
assert REPEATS > 0 and SECONDS > 0
CTX = ssl._create_unverified_context()
CALLS = 0
REPORT = {'repeats': REPEATS, 'minimum_soak_seconds': SECONDS, 'snapshots': {}, 'samples': [], 'cases': []}
STOP = threading.Event()


def connect(alpn='http/1.1', timeout=10):
    ctx = ssl._create_unverified_context()
    ctx.set_alpn_protocols([alpn])
    raw = socket.create_connection(('127.0.0.1', PORT), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        return ctx.wrap_socket(raw, server_hostname='localhost')
    except BaseException:
        raw.close()
        raise


def sample():
    pending, pids = [PID], []
    while pending:
        pid = pending.pop()
        if pid in pids:
            continue
        try:
            pending.extend(map(int, Path(f'/proc/{pid}/task/{pid}/children').read_text().split()))
            pids.append(pid)
        except FileNotFoundError:
            continue
    rss = anon = fds = bodyfds = 0
    for pid in pids:
        try:
            status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
            rss += int(status.get('VmRSS', '0').split()[0])
            anon += int(status.get('RssAnon', '0').split()[0])
            for fd in Path(f'/proc/{pid}/fd').iterdir():
                try:
                    path = os.readlink(fd)
                    fds += 1
                    bodyfds += path.startswith(str(WORK / 'tmp') + '/')
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
    return {'t': round(time.monotonic(), 3), 'pids': pids, 'rss_kb': rss,
            'anon_kb': anon, 'fds': fds, 'body_fds': bodyfds, 'tmp_files': len(list((WORK / 'tmp').iterdir()))}


def sampler():
    while not STOP.wait(.1):
        REPORT['samples'].append(sample())


HTTP = http.client.HTTPSConnection('127.0.0.1', PORT, context=CTX, timeout=15)


def request(path='/stats', data=None, content_type='application/octet-stream'):
    HTTP.request('GET' if data is None else 'POST', path, body=data,
                 headers={'Host': 'localhost', 'Content-Type': content_type})
    response = HTTP.getresponse()
    return response.status, response.read()


def validate(response, body, materialized=0):
    global CALLS
    obj = json.loads(response)
    assert obj == {'size': len(body), 'state': 0 if not body else 2 if len(body) >= THRESHOLD else 1,
                   'file': materialized, 'sha256': hashlib.sha256(body).hexdigest()}, obj
    CALLS += 1


def checked(body, path='/body', content_type='application/octet-stream'):
    status, response = request(path, body, content_type)
    assert status == 200, (path, len(body), status, response)
    validate(response, body, path == '/file')


def stats():
    status, data = request()
    assert status == 200
    assert json.loads(data)['calls'] == CALLS, (json.loads(data), CALLS)


def drain(label, base=None, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        s = sample()
        if not s['tmp_files'] and not s['body_fds'] and (base is None or s['fds'] <= base['fds'] + 8):
            REPORT['snapshots'][label] = s
            stats()
            return s
        time.sleep(.1)
    raise AssertionError(('resources did not drain', label, s))


class Wire:
    def __init__(self):
        self.sock = connect()
        self.file = self.sock.makefile('rb')

    def response(self):
        status = int(self.file.readline().split()[1])
        headers = {}
        while True:
            line = self.file.readline()
            if line == b'\r\n':
                break
            assert line
            key, value = line.decode().split(':', 1)
            headers[key.lower()] = value.strip()
        size = int(headers['content-length'])
        return status, self.read(size)

    def read(self, size):
        data = self.file.read(size)
        assert len(data) == size, (len(data), size)
        return data

    def close(self):
        self.file.close()
        self.sock.close()


def headers(size, path='/body'):
    return f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n'.encode()


class H2:
    def __init__(self):
        self.sock = connect('h2')
        assert self.sock.selected_alpn_protocol() == 'h2'
        self.conn = h2.connection.H2Connection()
        self.conn.initiate_connection()
        self.flush()
        self.responses = {}
        self.done = set()

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def pump(self):
        data = self.sock.recv(65536)
        assert data, 'HTTP/2 disconnected'
        for e in self.conn.receive_data(data):
            if isinstance(e, h2.events.ResponseReceived):
                assert dict(e.headers)[b':status'] == b'200', e.headers
                self.responses[e.stream_id] = bytearray()
            elif isinstance(e, h2.events.DataReceived):
                self.responses[e.stream_id].extend(e.data)
                self.conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
            elif isinstance(e, h2.events.StreamEnded):
                self.done.add(e.stream_id)
            elif isinstance(e, h2.events.StreamReset):
                raise AssertionError(e)
        self.flush()

    def start(self, length=None):
        sid = self.conn.get_next_available_stream_id()
        fields = [(':method', 'POST'), (':scheme', 'https'), (':authority', 'localhost'), (':path', '/body')]
        if length is not None:
            fields.append(('content-length', str(length)))
        self.conn.send_headers(sid, fields, end_stream=False)
        self.flush()
        return sid

    def send(self, sid, data, end=False):
        offset = 0
        while offset < len(data):
            count = min(self.conn.local_flow_control_window(sid), self.conn.max_outbound_frame_size, len(data)-offset)
            if count == 0:
                self.pump()
                continue
            self.conn.send_data(sid, data[offset:offset+count], end_stream=end and offset+count == len(data))
            offset += count
            self.flush()
        if end and not data:
            self.conn.end_stream(sid)
            self.flush()

    def check(self, data, known):
        sid = self.start(len(data) if known else None)
        self.send(sid, data, True)
        while sid not in self.done:
            self.pump()
        validate(self.responses.pop(sid), data)
        self.done.remove(sid)

    def close(self):
        self.sock.close()


class WS(Wire):
    def __init__(self, resource=False, compression=False):
        super().__init__()
        self.resource, self.compression = resource, compression
        key = base64.b64encode(b'body-memory-test').decode()
        extra = ('Sec-WebSocket-Protocol: resource\r\n' if resource else '')
        if compression:
            extra += 'Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n'
        self.sock.sendall(f'GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n{extra}\r\n'.encode())
        assert b'101' in self.file.readline()
        response = bytearray()
        while True:
            line = self.file.readline()
            if line == b'\r\n':
                break
            assert line
            response.extend(line)
        if compression:
            assert b'permessage-deflate' in response.lower()

    def frame(self, data, opcode=2, fin=True, compressed=False):
        mask = b'\x01\x23\x45\x67'
        head = bytes([(128 if fin else 0) | (64 if compressed else 0) | opcode])
        n = len(data)
        head += bytes([128 | n]) if n < 126 else bytes([254]) + struct.pack('!H', n) if n < 65536 else bytes([255]) + struct.pack('!Q', n)
        # Four independent translation tables avoid a Python loop per byte.
        encoded = bytearray(n)
        for i in range(4):
            encoded[i::4] = data[i::4].translate(bytes(x ^ mask[i] for x in range(256)))
        self.sock.sendall(head + mask + encoded)

    def receive(self, first=None):
        a, b = self.read(2) if first is None else first + self.read(1)
        n = b & 127
        if n == 126:
            n = struct.unpack('!H', self.read(2))[0]
        elif n == 127:
            n = struct.unpack('!Q', self.read(8))[0]
        assert not b & 128
        data = self.read(n)
        if a & 64:
            data = zlib.decompressobj(-15).decompress(data + b'\x00\x00\xff\xff')
        return a & 15, data

    def check(self, body, fragments=False):
        payload = (b'POST /body ' if self.resource else b'') + body
        if self.compression:
            compressor = zlib.compressobj(wbits=-15)
            payload = (compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
        if fragments and len(payload) > 1:
            cut = len(payload)//2
            self.frame(payload[:cut], fin=False, compressed=self.compression)
            self.frame(b'ping', opcode=9)
            opcode, data = self.receive()
            assert opcode == 10 and data == b'ping'
            self.frame(payload[cut:], opcode=0)
        else:
            self.frame(payload, compressed=self.compression)
        opcode, response = self.receive()
        assert opcode in (1, 2), (opcode, response)
        validate(response, body)


def main():
    global CALLS
    for _ in range(100):
        try:
            request()
            break
        except (OSError, http.client.HTTPException):
            HTTP.close()
            time.sleep(.1)
    else:
        raise AssertionError('server did not start')
    worker = threading.Thread(target=sampler, daemon=True)
    worker.start()
    for _ in range(20):
        checked(b'x'*20000)
    baseline = drain('warm')
    pattern = bytes(range(256)) * 8193
    sizes = [0, 1, 200, 20000, THRESHOLD-1, THRESHOLD, THRESHOLD+1, 2*THRESHOLD]
    for size in sizes:
        checked(pattern[:size])
        if size:
            checked(pattern[:size], '/file')
    checked(b'{"value":123}', '/json', 'application/json')
    status, _ = request('/json', b'{broken', 'application/json')
    assert status == 400
    CALLS += 1
    checked(b'value=x%00y', '/form', 'application/x-www-form-urlencoded')
    multipart = b'--b\r\nContent-Disposition: form-data; name="value"\r\n\r\nx\0y\r\n--b--\r\n'
    checked(multipart, '/form', 'multipart/form-data; boundary=b')
    pipe = Wire()
    bodies = [b'x'*200, pattern[:THRESHOLD], b'last']
    pipe.sock.sendall(b''.join(headers(len(body))+body for body in bodies))
    for body in bodies:
        status, data = pipe.response()
        assert status == 200
        validate(data, body)
    pipe.close()
    delayed = Wire()
    delayed.sock.sendall(headers(5) + b'last')
    time.sleep(.1)
    stats()
    delayed.sock.sendall(b'!')
    status, data = delayed.response()
    assert status == 200
    validate(data, b'last!')
    delayed.close()
    oversized = Wire()
    oversized.sock.sendall(headers(4194305) + b'x')
    status, _ = oversized.response()
    # The existing header parser classifies an oversized Content-Length as 400.
    assert status == 400, status
    oversized.close()
    stats()
    REPORT['cases'].append('HTTP/1.1 sizes/forms/JSON/file API/pipeline/delayed final byte/oversize')

    h2 = H2()
    for known in (True, False):
        for size in sizes:
            h2.check(pattern[:size], known)
    incomplete = [h2.start() for _ in range(4)]
    for sid in incomplete:
        h2.send(sid, pattern[:THRESHOLD+1])
    h2.check(b'parallel', True)
    for sid in incomplete:
        h2.conn.reset_stream(sid)
    h2.flush()
    h2.close()
    drain('h2_cancelled', baseline)
    REPORT['cases'].append('HTTP/2 known/unknown sizes, parallel streams and RST_STREAM')

    output = subprocess.check_output([str(BUILD/'exec/body_memory_h3'), str(PORT), str(WORK/'tmp')], timeout=90)
    h3 = json.loads(output)
    assert h3['calls'] == 7 and h3['cancelled_streams'] == 4 and h3['spilled_cancelled_streams'] == 4
    CALLS += h3['calls']
    drain('h3_cancelled', baseline)
    REPORT['h3'] = h3

    for resource in (False, True):
        for compressed in (False, True):
            ws = WS(resource, compressed)
            for size in sizes:
                ws.check(pattern[:size], fragments=True)
            # Disconnect in the middle of a whole-message upload after crossing threshold.
            ws.frame((b'POST /body ' if resource else b'') + pattern[:THRESHOLD+1], fin=False)
            ws.close()
    drain('ws_disconnected', baseline)
    for invalid_deflate in (False, True):
        broken = WS(compression=invalid_deflate)
        broken.frame(b'\xff\xff\xff' if invalid_deflate else b'\xff',
                     opcode=2 if invalid_deflate else 1, compressed=invalid_deflate)
        # Existing parser errors may disconnect directly or send a CLOSE.
        first = broken.file.read(1)
        if first:
            opcode, response = broken.receive(first)
            assert opcode == 8, ('malformed message did not close', opcode, response)
        broken.close()
    drain('ws_errors', baseline)
    REPORT['cases'].append('WebSocket default/resource masked/compressed/fragmented/control/disconnect/error')

    for size in (THRESHOLD-1, THRESHOLD+1):
        before_active = sample()
        REPORT['snapshots'][f'before_incomplete_{size}'] = before_active
        sockets = [connect() for _ in range(32)]
        for s in sockets:
            declared = size if size < THRESHOLD else size+1
            s.sendall(headers(declared) + pattern[:declared-1])
        time.sleep(.5)
        active = sample()
        REPORT['snapshots'][f'incomplete_{size}'] = active
        if size < THRESHOLD:
            assert active['tmp_files'] == 0 and active['body_fds'] == 0, active
            REPORT['snapshots'][f'incomplete_{size}']['active_anon_delta_kb'] = active['anon_kb'] - before_active['anon_kb']
        else:
            assert active['tmp_files'] == 32 and active['body_fds'] == 32, active
        stats()  # No incomplete request may dispatch.
        for s in sockets:
            s.close()
        drain(f'incomplete_{size}_drained', baseline)
    REPORT['cases'].append('32 simultaneous incomplete memory/file bodies and disconnect drain')

    # The shell caps each server process at 128 fds; enough connections plus
    # file bodies exhaust it. Failures must not crash the worker or dispatch.
    pressure = []
    for _ in range(90):
        try:
            s = connect(timeout=1)
            pressure.append(s)
            s.sendall(headers(THRESHOLD+1)+b'x')
        except OSError:
            break
    time.sleep(.5)
    REPORT['snapshots']['fd_pressure'] = sample()
    refusals = 0
    for s in pressure:
        s.settimeout(.02)
        try:
            response = s.recv(4096)
            if not response or response.startswith((b'HTTP/1.1 400', b'HTTP/1.1 500')):
                refusals += 1
        except TimeoutError:
            pass  # This upload is still open and incomplete.
        except OSError:
            refusals += 1
        s.close()
    REPORT['fd_pressure_refusals'] = refusals
    assert refusals > 0, 'fd pressure did not reject incomplete uploads'
    assert REPORT['snapshots']['fd_pressure']['fds'] >= int(os.environ.get('BODY_FD_LIMIT', '128')) - 2, 'fd limit was not reached'

    HTTP.close()
    drain('fd_pressure_drained', baseline)
    checked(b'worker survived fd exhaustion')

    # Equal mixed-size warmup before comparing post-soak RSS.
    for _ in range(10):
        checked(pattern[:THRESHOLD+1])
    ws = WS()
    ws.check(b'warmup')
    before = drain('before_soak', baseline)
    started = time.monotonic()
    count = 0
    while count < REPEATS or time.monotonic()-started < SECONDS:
        checked(pattern[:THRESHOLD+1] if count % 100 == 0 else b'x'*200)
        ws.check(b'x'*200)
        count += 1
    ws.close()
    after = drain('after_soak', baseline)
    growth = after['rss_kb'] - before['rss_kb']
    assert growth <= int(os.environ.get('BODY_RSS_GROWTH_KB', '16384')), ('post-soak RSS growth', growth)
    REPORT['soak'] = {'iterations': count, 'responses': 2*count, 'seconds': round(time.monotonic()-started,3), 'rss_growth_kb': growth}
    REPORT['validated_handler_calls'] = CALLS
    REPORT['status'] = 'PASS'
    HTTP.close()
    STOP.set()
    worker.join()
    (WORK/'results.json').write_text(json.dumps(REPORT, indent=2)+'\n')
    print(json.dumps({k:v for k,v in REPORT.items() if k != 'samples'}, indent=2))


try:
    main()
except BaseException as e:
    STOP.set()
    REPORT['status'] = 'FAIL'
    REPORT['error'] = repr(e)
    REPORT['failure_snapshot'] = sample()
    (WORK/'results.json').write_text(json.dumps(REPORT, indent=2)+'\n')
    raise
