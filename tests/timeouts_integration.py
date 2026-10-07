"""Real HTTP/1 and WebSocket timeout/config/reload checks, using only stdlib."""
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    binary, module = map(os.path.abspath, sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix="cwfr-timeouts-") as tmp:
        work = Path(tmp)
        (work / "www").mkdir()
        (work / "www" / "index.html").write_text("ready")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = {
            "main": {
                "workers": 1, "threads": 2, "reload": "soft",
                "buffer_size": 16384, "client_max_body_size": 1048576,
                "tmp": tmp, "gzip": [], "log": {"enabled": True, "level": "info"},
                "timeouts": {"request_header_timeout_ms": 100,
                             "request_body_idle_timeout_ms": 100,
                             "ws_ping_interval_ms": 100, "ws_pong_timeout_ms": 300,
                             "ws_close_timeout_ms": 100, "ws_send_idle_timeout_ms": 50},
            },
            "servers": {"s1": {
                "domains": ["localhost"], "ip": "127.0.0.1", "port": port,
                "root": str(work / "www"), "index": "index.html",
                "http": {"routes": {"/ws": {"GET": {
                    "file": module, "function": "body_upgrade"}},
                    "/stats": {"GET": {"file": module, "function": "body_stats", "timeouts": {
                        "request_body_idle_timeout_ms": 3000, "slow_request_threshold_ms": 10000}}},
                    "/short": {"POST": {"file": module, "function": "body_check", "timeouts": {
                        "request_body_idle_timeout_ms": 50}}},
                    "/long": {"POST": {"file": module, "function": "body_check", "timeouts": {
                        "request_body_idle_timeout_ms": 1500}}},
                    "/slow": {"GET": {"file": module, "function": "body_delay"}}}},
                "websockets": {"default": {"file": module, "function": "body_ws"}},
            }},
            "mimetypes": {"text/html": ["html"]},
        }
        path = work / "config.json"

        def save(value):
            path.write_text(json.dumps(value))

        def connect():
            return socket.create_connection(("127.0.0.1", port), timeout=3)

        def receive(sock, end=b"", eof=False):
            result = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                result += chunk
                if end and end in result and not eof:
                    break
            return result

        def get():
            with connect() as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                return receive(sock, eof=True)

        def rejected(candidate, expected):
            save(candidate)
            result = subprocess.run([binary, "-c", str(path), "-f"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
            output = result.stdout.decode(errors="replace")
            assert result.returncode != 0 and expected in output, output

        for value in (-1, 1.5, "100", None):
            candidate = copy.deepcopy(config)
            candidate["main"]["timeouts"]["request_header_timeout_ms"] = value
            rejected(candidate, "main.timeouts.request_header_timeout_ms")
        candidate = copy.deepcopy(config)
        candidate["servers"]["s1"]["timeouts"] = {"request_body_idle_timeout_ms": 0}
        rejected(candidate, "servers.s1.timeouts")
        # There is one mode: every timeout terminates. The former switch is
        # an unknown key, not a silently ignored one.
        candidate = copy.deepcopy(config)
        candidate["main"]["timeouts"]["request_timeout_mode"] = "observe"
        rejected(candidate, "main.timeouts.request_timeout_mode")
        candidate = copy.deepcopy(config)
        candidate["servers"]["s1"]["http"]["routes"]["/ws"]["GET"]["timeouts"] = {
            "request_header_timeout_ms": 10}
        rejected(candidate, "timeouts")

        # The header budget applies before Host/SNI picks a vhost, so vhosts
        # sharing a listener must agree on it.
        candidate = copy.deepcopy(config)
        candidate["servers"]["s2"] = copy.deepcopy(candidate["servers"]["s1"])
        candidate["servers"]["s2"]["domains"] = ["other.localhost"]
        candidate["servers"]["s2"]["timeouts"] = {"request_header_timeout_ms": 60000}
        rejected(candidate, "vhosts sharing a listener")
        # The pre-policy HTTP/2 timeout is gone; a config that still sets it is
        # refused instead of silently changing its HTTP/2 budgets.
        candidate = copy.deepcopy(config)
        candidate["main"]["env"] = {"http2_request_timeout_sec": 120}
        rejected(candidate, "main.env.http2_request_timeout_sec")

        save(config)
        with (work / "server.log").open("w+") as log:
            proc = subprocess.Popen([binary, "-c", str(path), "-f"],
                                    stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        assert b"ready" in get()
                        break
                    except (OSError, AssertionError):
                        assert proc.poll() is None, "server exited at startup"
                        assert time.monotonic() < deadline, "server did not start"
                        time.sleep(.05)

                for request in (
                    b"GET / HTTP/1.1\r\nHost: local",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\na",
                ):
                    with connect() as sock:
                        sock.sendall(request)
                        response = receive(sock, eof=True)
                        assert b"HTTP/1.1 408" in response, response
                # Without a single request byte there is nothing to answer: the
                # connection closes silently, as nginx does, and a pooled client
                # never takes a 408 for the reply to a request it was sending.
                with connect() as sock:
                    started = time.monotonic()
                    response = receive(sock, eof=True)
                    assert response == b"" and time.monotonic() - started < 2, response
                assert b"ready" in get(), "timeout stopped other connections"

                # Two complete requests and a partial third share one read.
                # The first route's generous body budget must not protect the third headers.
                with connect() as sock:
                    sock.sendall(b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                 b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                 b"GET / HTTP/1.1\r\nHost: local")
                    response = receive(sock, eof=True)
                    assert b"ready" not in response, response
                    assert response.count(b"HTTP/1.1 200") <= 2, response
                    # Either 408 follows completed responses, or closing preserves
                    # already queued response ordering; no response for request three.
                    assert response.count(b"HTTP/1.1 408") <= 1, response

                # A short deadline on the preceding request cannot cancel a
                # later pipelined upload with its own route policy.
                with connect() as sock:
                    sock.sendall(b"POST /short HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
                                 b"POST /long HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                                 b"Connection: close\r\n\r\na")
                    time.sleep(.7)
                    sock.sendall(b"bcd")
                    response = receive(sock, eof=True)
                    assert response.count(b"HTTP/1.1 200") == 2 and b"408" not in response, response

                # Pong must acknowledge the actual server Ping; missing Pong closes the session.
                with connect() as sock:
                    sock.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                                 b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                                 b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                    pending = receive(sock, end=b"\r\n\r\n")
                    headers, pending = pending.split(b"\r\n\r\n", 1)
                    assert b"101" in headers, headers

                    def frame():
                        nonlocal pending
                        while len(pending) < 2:
                            pending += sock.recv(4096)
                        length = pending[1] & 127
                        assert length < 126, "unexpected large control frame"
                        while len(pending) < length + 2:
                            chunk = sock.recv(4096)
                            assert chunk, "unexpected EOF"
                            pending += chunk
                        opcode, payload = pending[0] & 15, pending[2:length + 2]
                        pending = pending[length + 2:]
                        return opcode, payload

                    opcode, payload = frame()
                    assert opcode == 9 and len(payload) == 8, (opcode, payload)
                    # The Ping is fully sent: send idle may expire while Pong
                    # remains within its longer budget.
                    time.sleep(.1)
                    mask = b"1234"
                    sock.sendall(bytes([0x8a, 0x80 | len(payload)]) + mask + bytes(
                        value ^ mask[index % 4] for index, value in enumerate(payload)))
                    opcode, payload = frame()
                    assert opcode == 9, "matching Pong did not preserve session"
                    opcode, close_payload = frame()
                    assert close_payload[:2] == b"\x03\xf0", close_payload
                    assert opcode == 8, "missing Pong did not initiate Close"
                    receive(sock, eof=True)

                # Invalid reload must preserve the serving generation.
                candidate = copy.deepcopy(config)
                candidate["main"]["timeouts"]["request_header_timeout_ms"] = -1
                save(candidate)
                proc.send_signal(signal.SIGUSR1)
                time.sleep(.3)
                assert proc.poll() is None and b"ready" in get()

                # Active upload and WebSocket retain the old generation's policy.
                with connect() as upload, connect() as websocket:
                    websocket.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                                      b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                                      b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                    handshake = receive(websocket, end=b"\r\n\r\n")
                    headers, pending_ws = handshake.split(b"\r\n\r\n", 1)
                    assert b"101" in headers, headers

                    def reload_ws_frame():
                        nonlocal pending_ws
                        while len(pending_ws) < 2:
                            chunk = websocket.recv(4096)
                            assert chunk, "old WebSocket closed during soft reload"
                            pending_ws += chunk
                        length = pending_ws[1] & 127
                        assert length < 126
                        while len(pending_ws) < length + 2:
                            chunk = websocket.recv(4096)
                            assert chunk, "old WebSocket frame truncated"
                            pending_ws += chunk
                        opcode, payload = pending_ws[0] & 15, pending_ws[2:length + 2]
                        pending_ws = pending_ws[length + 2:]
                        return opcode, payload

                    def reload_ws_send(opcode, payload):
                        mask = b"1234"
                        websocket.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + bytes(
                            value ^ mask[index % 4] for index, value in enumerate(payload)))
                    upload.sendall(b"POST /long HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                                   b"Connection: close\r\n\r\na")
                    time.sleep(.05)
                    config["servers"]["s1"]["http"]["routes"]["/long"]["POST"]["timeouts"]["request_body_idle_timeout_ms"] = 50
                    config["main"]["timeouts"]["ws_ping_interval_ms"] = 0
                    config["main"]["timeouts"]["ws_pong_timeout_ms"] = 10
                    save(config)
                    proc.send_signal(signal.SIGUSR1)
                    opcode, payload = reload_ws_frame()
                    assert opcode == 9, "old generation must still send its enabled heartbeat"
                    time.sleep(.1)  # longer than the candidate Pong budget, within the old one
                    reload_ws_send(10, payload)
                    time.sleep(.2)
                    upload.sendall(b"bcd")
                    response = receive(upload, eof=True)
                    assert b"HTTP/1.1 200" in response, response
                    reload_ws_send(8, b"\x03\xe8")
                    opcode, payload = reload_ws_frame()
                    if opcode == 9:
                        opcode, payload = reload_ws_frame()
                    assert opcode == 8 and payload[:2] == b"\x03\xe8", (opcode, payload)
                time.sleep(.3)
                with connect() as upload:
                    upload.sendall(b"POST /long HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\na")
                    response = receive(upload, eof=True)
                    assert b"HTTP/1.1 408" in response, response

                # Valid reload switches policy: a longer header budget accepts
                # the same slow request the 100ms one rejected.
                config["main"]["timeouts"]["request_header_timeout_ms"] = 1500
                save(config)
                proc.send_signal(signal.SIGUSR1)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with connect() as sock:
                            sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
                            time.sleep(.7)
                            sock.sendall(b"host\r\nConnection: close\r\n\r\n")
                            response = receive(sock, eof=True)
                            if b"ready" in response:
                                break
                    except OSError:
                        pass
                    assert time.monotonic() < deadline, "longer header budget reload did not take effect"

                # Back to 100ms for the parked-connection regressions below.
                config["main"]["timeouts"]["request_header_timeout_ms"] = 100
                save(config)
                proc.send_signal(signal.SIGUSR1)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with connect() as sock:
                            sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
                            if b"408" in receive(sock, eof=True):
                                break
                    except OSError:
                        pass
                    assert time.monotonic() < deadline, "short header budget reload did not take effect"

                # A pipelined request parked behind a running handler must not be
                # timed out on the server's own stall: while the handler runs the
                # connection is not read, so the second request's header budget
                # must not accrue (regression: the timeout closed the connection and
                # lost the first response already being computed).
                with connect() as sock:
                    sock.sendall(b"GET /slow?ms=800 HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                 b"GET / HTTP/1.1\r\nHost: local")
                    time.sleep(.4)  # past the 100ms header budget, within the handler
                    sock.sendall(b"host\r\nConnection: close\r\n\r\n")
                    response = receive(sock, eof=True)
                    assert response.count(b"HTTP/1.1 200") == 2 and b"408" not in response, response

                # ...but the pause is not banked: once the slow response is out
                # and the connection reads again, the next request has the plain
                # 100ms header budget, not 100ms plus the 2s the server spent not
                # reading (regression: wall-time stamps checked on the paused
                # clock carried every pause forward -- and a client stretches
                # pauses at will by not reading its responses). The bound leaves
                # room for the 500ms sweep tick.
                with connect() as sock:
                    sock.sendall(b"GET /slow?ms=2000 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    first = receive(sock, end=b'{"delay":1}')
                    assert b"HTTP/1.1 200" in first, first
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: local")
                    started = time.monotonic()
                    response = receive(sock, eof=True)
                    elapsed = time.monotonic() - started
                    assert b"408" in response and elapsed < 1.2, (elapsed, response)

                # Hard reload with a handler still running on the old generation:
                # the old worker drains and frees its listeners while the handler
                # thread holds the last connection reference, and the handler's
                # completion path (including the parser free) must not touch the
                # freed listener (regression: use-after-free in __reset_receive).
                config["main"]["reload"] = "hard"
                save(config)
                proc.send_signal(signal.SIGUSR1)
                time.sleep(.3)
                assert proc.poll() is None and b"ready" in get(), "reload-mode switch stopped serving"
                with connect() as slow:
                    slow.sendall(b"GET /slow?ms=1500 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    time.sleep(.2)
                    proc.send_signal(signal.SIGUSR1)
                    time.sleep(.4)
                    assert proc.poll() is None, "hard reload killed the server"
                deadline = time.monotonic() + 5
                while True:
                    try:
                        assert b"ready" in get()
                        break
                    except (OSError, AssertionError):
                        assert proc.poll() is None, "server exited after hard reload"
                        assert time.monotonic() < deadline, "new generation did not start serving"
                        time.sleep(.05)
                time.sleep(1.5)  # the handler outlives the old worker's listeners
                if proc.poll() is not None:
                    log.flush()
                    log.seek(0)
                    raise AssertionError(
                        f"handler completion crashed on the freed listener, rc={proc.returncode}:\n"
                        + log.read())
                print("timeouts: config/listener validation, pipeline, route overrides, Ping/Pong/Close, active upload/WebSocket soft reload, policy reload, parked pipeline, unbanked pause and hard-reload handler lifetime passed")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            log.seek(0)
            output = log.read()
            assert not any(marker in output for marker in (
                "ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:",
                "SUMMARY: AddressSanitizer", "SUMMARY: UndefinedBehaviorSanitizer")), output


if __name__ == "__main__":
    main()
