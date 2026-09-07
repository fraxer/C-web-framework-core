#!/usr/bin/env python3
"""Regression: failed startup must not free configs still used by other threads."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

server, injector = map(lambda value: str(Path(value).resolve()), sys.argv[1:3])
build_type = sys.argv[3] if len(sys.argv) > 3 else "Release"
env = dict(os.environ)
# An instrumented executable needs libasan ahead of the fault-injection preload.
linked = subprocess.run(["ldd", server], capture_output=True, text=True, check=True).stdout
asan = next((line.split("=>", 1)[1].split()[0] for line in linked.splitlines()
             if "libasan.so" in line and "=>" in line), None)
env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:exitcode=99"
env["LSAN_OPTIONS"] = "exitcode=99"


def clean_log(text):
    for marker in ("AddressSanitizer", "LeakSanitizer", "runtime error:",
                   "double free", "corrupted", "still running after"):
        assert marker not in text, text


with tempfile.TemporaryDirectory(prefix="cwfr-startup-lifetime-") as directory:
    root = Path(directory)
    (root / "index.html").write_text("ready\n")
    (root / ".env").write_text("")
    path = root / "config.json"
    config = {
        "main": {"workers": 12, "threads": 1, "reload": "hard",
                 "buffer_size": 16384, "client_max_body_size": 1048576,
                 "tmp": directory, "gzip": [],
                 "log": {"enabled": True, "level": "info"},
                 "env": {"http2_shutdown_grace_sec": 2}},
        "servers": {"s1": {"domains": ["localhost"], "ip": "127.0.0.1",
                           "port": 0, "root": directory, "index": "index.html"}},
        "mimetypes": {"text/html": ["html"]},
        "task_manager": [],
    }
    modes = [["-f"]]
    if build_type in ("Release", "RelWithDebInfo"):
        modes.append([])

    def fails(mode, run_env, expected):
        # File output also covers the child of a daemonizing Release build.
        with (root / "failure.log").open("w+") as log:
            result = subprocess.run([server, "-c", str(path), *mode], env=run_env,
                                    stdout=log, stderr=log, timeout=10)
            log.seek(0)
            text = log.read()
        assert result.returncode == 1, (result.returncode, text)
        assert expected in text, text
        clean_log(text)

    # Include a no-scheduler case: a fast failing worker can otherwise become
    # the last owner while the main thread is still creating later workers.
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        config["servers"]["s1"]["port"] = busy.getsockname()[1]
        for scheduler in (False, True):
            if scheduler:
                config["task_manager"] = []
            else:
                config.pop("task_manager", None)
            path.write_text(json.dumps(config))
            for mode in modes:
                for _ in range(10):
                    fails(mode, env, "startup: a worker could not start")
    print("ok: occupied port, with/without scheduler, foreground/daemon", flush=True)

    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        config["servers"]["s1"]["port"] = available.getsockname()[1]
    config["task_manager"] = []
    path.write_text(json.dumps(config))
    for mode in modes:
        for fail_at in (0, 1, 2, 8, 14):
            faulty_env = dict(env, CWFR_TEST_THREAD_FAIL_AT=str(fail_at),
                              LD_PRELOAD=":".join(filter(None, (asan, injector))))
            fails(mode, faulty_env, "startup: configuration or thread initialization failed")
    print("ok: partial pthread_create failure in every thread category", flush=True)

    # The same config must still serve and survive both reload modes.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def serving():
        request = urllib.request.Request(
            f'http://127.0.0.1:{config["servers"]["s1"]["port"]}/',
            headers={"Host": "localhost"})
        try:
            with opener.open(request, timeout=0.3) as response:
                return response.read() == b"ready\n"
        except OSError:
            return False

    with (root / "success.log").open("w+") as log:
        process = subprocess.Popen([server, "-f", "-c", str(path)], env=env,
                                   stdout=log, stderr=log)
        try:
            for reload_mode in ("hard", "soft"):
                deadline = time.monotonic() + 5
                while not serving() and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert serving(), "valid server did not start"
                config["main"]["reload"] = reload_mode
                path.write_text(json.dumps(config))
                # First reload changes the mode; the next uses it.
                for _ in range(2):
                    process.send_signal(signal.SIGUSR1)
                    time.sleep(0.6)
                    assert serving(), f"{reload_mode} reload stopped serving"
            process.terminate()
            assert process.wait(timeout=5) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            log.seek(0)
            clean_log(log.read())
    print("ok: successful startup, hard/soft reload and graceful shutdown", flush=True)
