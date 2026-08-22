#!/usr/bin/env python3
"""RFC 8441 (WebSocket over HTTP/2) against a strict third-party client.

Why this exists: the tunnel was implemented and tested with our own client, and
our own client checked only what we thought to check. The first outside client
to try it — python-`h2`, which enforces the RFC where we merely intended it —
refused to open a tunnel at all:

    InvalidBodyLengthError: Expected 0 bytes, received 18

The 200 answering the extended CONNECT carried `content-length: 0`, which
RFC 9110 §9.3.6 forbids ("A server MUST NOT send Content-Length ... in a
successful response to CONNECT"), and a client that believes the length treats
the first DATA frame of the tunnel as a violation. Nothing in the suite could
have caught that, because the suite spoke our dialect.

So this probe is deliberately NOT another hand-rolled client: it drives the
server through python-`h2`, whose state machine says no to things ours would
have shrugged at. What it asserts:

  1. SETTINGS advertises ENABLE_CONNECT_PROTOCOL — without it a client is not
     even allowed to try (RFC 8441 §3).
  2. The tunnel opens: 200, and no framing headers on it (the regression above).
  3. Messages flow both ways through the tunnel.
  4. Two tunnels on ONE connection both receive a broadcast, and the fan-out
     arrives batched rather than one socket read per message (docs/http2/09).

Usage: h2ws_probe.py [host] [port]   (exit 0 = pass, 1 = fail, 2 = unusable)
"""

import os
import socket
import struct
import sys
import time

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2 import events
except ImportError:
    print("python-h2 is not installed (pip install h2)", file=sys.stderr)
    sys.exit(2)


HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18099

FANOUT_MESSAGES = 200

failures = []


def check(ok, what, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {what}{(' -- ' + detail) if detail and not ok else ''}")
    if not ok:
        failures.append(what)
    return ok


def ws_frame(payload: bytes) -> bytes:
    """A masked text frame: a client that does not mask is a protocol error
    (RFC 6455 §5.3), and the server is entitled to say so."""
    mask = os.urandom(4)
    head = bytes([0x81])
    if len(payload) < 126:
        head += bytes([0x80 | len(payload)])
    else:
        head += bytes([0x80 | 126]) + struct.pack("!H", len(payload))
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_messages(buf: bytes):
    """Split server frames out of a byte stream; returns (messages, leftover)."""
    out, i = [], 0
    while i + 2 <= len(buf):
        masked = buf[i + 1] & 0x80
        length = buf[i + 1] & 0x7F
        j = i + 2
        if length == 126:
            if j + 2 > len(buf):
                break
            length = struct.unpack("!H", buf[j:j + 2])[0]
            j += 2
        elif length == 127:
            if j + 8 > len(buf):
                break
            length = struct.unpack("!Q", buf[j:j + 8])[0]
            j += 8
        if masked:
            j += 4
        if j + length > len(buf):
            break
        out.append(buf[j:j + length])
        i = j + length
    return out, buf[i:]


class Client:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT), 10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        self.conn.initiate_connection()
        self.flush()
        self.headers = {}      # stream -> response headers
        self.raw = {}          # stream -> undecoded tunnel bytes
        self.messages = {}     # stream -> [payloads]
        self.reads = 0         # how many times the socket handed us data
        self.settings = {}
        self.errors = []

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def open_tunnel(self, path="/ws"):
        stream = self.conn.get_next_available_stream_id()
        self.conn.send_headers(stream, [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":path", path),
            (":authority", f"{HOST}:{PORT}"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-protocol", "resource"),
        ])
        self.flush()
        self.raw[stream] = b""
        self.messages[stream] = []
        return stream

    def send(self, stream, text: bytes):
        while self.conn.local_flow_control_window(stream) < len(text) + 16:
            if not self.pump(0.2):
                break
        self.conn.send_data(stream, ws_frame(text))
        self.flush()

    def pump(self, timeout=0.4):
        """Read whatever is available; returns True if anything arrived."""
        self.sock.settimeout(timeout)
        got = False
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    break
                self.reads += 1
                got = True
                for event in self.conn.receive_data(data):
                    self._on_event(event)
                self.flush()
        except socket.timeout:
            pass
        except Exception as exc:        # a protocol error from h2 lands here
            self.errors.append(repr(exc))
        return got

    def _on_event(self, event):
        if isinstance(event, events.RemoteSettingsChanged):
            for code, setting in event.changed_settings.items():
                self.settings[int(code)] = setting.new_value
        elif isinstance(event, events.ResponseReceived):
            self.headers[event.stream_id] = dict(event.headers)
        elif isinstance(event, events.DataReceived):
            self.raw[event.stream_id] = self.raw.get(event.stream_id, b"") + event.data
            messages, rest = ws_messages(self.raw[event.stream_id])
            self.raw[event.stream_id] = rest
            self.messages.setdefault(event.stream_id, []).extend(messages)
            self.conn.acknowledge_received_data(len(event.data), event.stream_id)
        elif isinstance(event, (events.StreamReset, events.ConnectionTerminated)):
            self.errors.append(type(event).__name__)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    print("h2ws: RFC 8441 tunnels against python-h2")

    # 1. The capability itself. SETTINGS_ENABLE_CONNECT_PROTOCOL is 0x8.
    subscriber = Client()
    subscriber.pump(0.5)
    check(subscriber.settings.get(0x8) == 1,
          "SETTINGS advertises ENABLE_CONNECT_PROTOCOL",
          f"settings={subscriber.settings}")

    # 2. The tunnel opens, and its response carries no framing headers.
    echo = subscriber.open_tunnel()
    subscriber.pump(0.5)
    headers = subscriber.headers.get(echo, {})
    check(headers.get(":status") == "200", "extended CONNECT is answered 200", str(headers))
    # REGRESSION (RFC 9110 §9.3.6): content-length on a tunnel makes a strict
    # client treat the first DATA frame as a body overrun and kill the stream.
    check("content-length" not in headers,
          "no content-length on the tunnel response", str(headers))
    check("transfer-encoding" not in headers,
          "no transfer-encoding on the tunnel response", str(headers))

    # 3. Messages flow through it. The resource subprotocol routes by the
    #    message itself: "<METHOD> <path> <payload>".
    subscriber.send(echo, b"GET /echo")
    subscriber.pump(0.5)
    check(len(subscriber.messages.get(echo, [])) > 0, "the tunnel carries a reply",
          str(subscriber.messages.get(echo)))
    check(not subscriber.errors, "no protocol errors on the tunnel", str(subscriber.errors))

    # A connection python-h2 has already torn down cannot carry the fan-out
    # phase, and the traceback from trying would bury the failure that caused
    # it. Report what is known and stop here instead.
    if subscriber.errors:
        print("h2ws: the tunnel is unusable, skipping the fan-out checks")
        subscriber.close()
        return 1

    # 4. Two tunnels on ONE connection, both subscribed to the same channel.
    #    This is the shape that used to break the fan-out batch: the messages of
    #    two tunnels alternate in the connection's queue, and a batch may carry
    #    only one of them.
    first = subscriber.open_tunnel()
    second = subscriber.open_tunnel()
    subscriber.pump(0.4)
    subscriber.send(first, b"GET /join")
    subscriber.send(second, b"GET /join")
    subscriber.pump(0.4)

    before_reads = subscriber.reads

    sender = Client()
    sender.pump(0.4)
    sender_tunnel = sender.open_tunnel()
    sender.pump(0.4)

    for i in range(FANOUT_MESSAGES):
        sender.send(sender_tunnel, b"POST /send m%d" % i)

    deadline = time.time() + 20
    while time.time() < deadline:
        subscriber.pump(0.2)
        got_first = len(subscriber.messages.get(first, []))
        got_second = len(subscriber.messages.get(second, []))
        if got_first > FANOUT_MESSAGES and got_second > FANOUT_MESSAGES:
            break

    # Each tunnel gets the "done" reply to its own join plus every broadcast.
    got_first = len(subscriber.messages.get(first, [])) - 1
    got_second = len(subscriber.messages.get(second, [])) - 1
    check(got_first == FANOUT_MESSAGES and got_second == FANOUT_MESSAGES,
          "both tunnels on one connection receive the whole fan-out",
          f"{got_first} and {got_second} of {FANOUT_MESSAGES}")

    # The batch: without it the server answers every delivery with its own response
    # and its own socket write, and the client sees one read per message. The
    # threshold is deliberately loose -- this asserts "batched at all", not a
    # particular batch size.
    fanout_reads = subscriber.reads - before_reads
    check(fanout_reads <= FANOUT_MESSAGES,
          "the fan-out arrives batched, not one write per delivery",
          f"{fanout_reads} reads for {2 * FANOUT_MESSAGES} deliveries")

    check(not subscriber.errors and not sender.errors,
          "no protocol errors during the fan-out",
          str(subscriber.errors + sender.errors))

    sender.close()
    subscriber.close()

    if failures:
        print(f"h2ws: {len(failures)} check(s) failed")
        return 1

    print("h2ws: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
