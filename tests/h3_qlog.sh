#!/usr/bin/env bash

# qlog end to end (docs/http3/04-quic-transport.md §10, 08-testing.md §10).
#
# The unit tests own the file format and the event call sites. What only a
# running server can answer is everything around them, and all of it is
# configuration that fails silently when it breaks:
#
#   1. `http3_qlog_dir` creates the directory and traces land in it, one file
#      per connection, named by the original destination connection id;
#   2. every record is valid JSON and one line -- the check that catches an
#      event whose data was built with an unescaped byte in it, which corrupts
#      the whole file rather than one field;
#   3. `http3_qlog_connections` is a real bound: the connection after the budget
#      gets no file. Without this, "enable qlog on a busy server" is a way to
#      fill a disk;
#   4. the budget is re-armed by a reload, which is how qlog gets switched on
#      for a server that is already running -- the case it exists for;
#   5. an empty `http3_qlog_dir` (the shipped default) writes nothing at all.
#
# The failure this guards against is the one this feature already had once: a
# facility that compiles, has call sites, and produces nothing.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_qlog.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-qlog}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_QLOG_PORT:-18497}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 qlog: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'SKIP: python3 is needed to validate the JSON records\n'
    exit 0
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/www"
printf 'qlog\n' > "$WORK_DIR/www/index.html"

QLOG_DIR="$WORK_DIR/traces"

# The directory is deliberately NOT created here: the server has to create it,
# and a run that pre-made it would pass with that code removed.
write_config() {
    local dir=$1 connections=$2
    cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_qlog_dir": "$dir",
            "http3_qlog_connections": $connections
        }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/www", "index": "index.html",
            "tls": {
                "fullchain": "$CORE_DIR/tests/data/quic_test_cert.pem",
                "private": "$CORE_DIR/tests/data/quic_test_key.pem",
                "ciphers": "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
            },
            "http3": { "enabled": true, "port": $PORT }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON
}

server_pid=
cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

start_server() {
    "$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 50); do
        kill -0 "$server_pid" 2>/dev/null || break
        curl -ksS --max-time 2 "https://localhost:$PORT/" >/dev/null 2>&1 && return 0
        sleep 0.1
    done

    kill -0 "$server_pid" 2>/dev/null
}

request() {
    "$CLIENT" 127.0.0.1 "$PORT" -p /index.html -q > "$WORK_DIR/client.log" 2>&1
}

traces() { ls "$QLOG_DIR"/*.sqlog 2>/dev/null | wc -l; }

# ---- 1 and 2: a trace is written, and it is readable ----

write_config "$QLOG_DIR" 2
start_server || { printf 'h3 qlog: server did not start\n' >&2; cat "$WORK_DIR/server.log" >&2; exit 1; }

if [ -d "$QLOG_DIR" ]; then
    printf 'ok: the server created the qlog directory\n'
else
    fail "http3_qlog_dir was not created"
fi

request || fail "the first request did not complete"

if [ "$(traces)" = 1 ]; then
    printf 'ok: one trace per connection\n'
else
    fail "expected one trace after one connection, found $(traces)"
fi

python3 - "$QLOG_DIR" <<'PY'
import glob, json, sys

path = sorted(glob.glob(sys.argv[1] + "/*.sqlog"))[0]
raw = open(path, "rb").read().decode()
records = [r for r in raw.split("\x1e") if r.strip()]
status = 0

for record in records:
    try:
        json.loads(record)
    except ValueError as error:
        print("FAIL: invalid JSON record: %s: %.120r" % (error, record))
        status = 1
    # One record per line: a reader splits on newlines, so an event carrying a
    # raw newline would swallow the record after it.
    if record.count("\n") != 1 or not record.endswith("\n"):
        print("FAIL: record is not exactly one line: %.120r" % record)
        status = 1

names = {json.loads(r).get("name") for r in records if "name" in json.loads(r)}
required = {
    "connectivity:connection_started",
    "connectivity:connection_state_updated",
    "transport:packet_sent",
    "transport:packet_received",
    "recovery:metrics_updated",
}
missing = required - names
if missing:
    print("FAIL: the trace has no %s" % ", ".join(sorted(missing)))
    status = 1

if status == 0:
    print("ok: %d records, all valid JSON-SEQ, every expected event present"
          % len(records))

sys.exit(status)
PY
[ $? -eq 0 ] || failed=1

# ---- 3: the budget bounds the traces ----

request || fail "the second request did not complete"
request || fail "the third request did not complete"

if [ "$(traces)" = 2 ]; then
    printf 'ok: http3_qlog_connections stopped at its budget\n'
else
    fail "expected two traces under a budget of two, found $(traces)"
fi

# ---- 4: a reload re-arms the budget ----

# SIGUSR1, not SIGHUP: HUP is ignored on purpose (src/signal/signal.c), and a
# reload signalled with it would leave this check passing for the wrong reason.
kill -USR1 "$server_pid" 2>/dev/null
sleep 2

request || fail "the request after the reload did not complete"

if [ "$(traces)" -gt 2 ]; then
    printf 'ok: a reload re-arms the budget, so qlog can be enabled on a live server\n'
else
    fail "the budget was not re-armed by the reload, found $(traces) traces"
fi

cleanup
server_pid=

# ---- 5: empty means off ----

rm -rf "$WORK_DIR/off"
write_config "" 10
start_server || { printf 'h3 qlog: server did not start with qlog off\n' >&2; exit 1; }
request || fail "the request with qlog off did not complete"

if [ "$(find "$WORK_DIR" -name '*.sqlog' -newer "$WORK_DIR/config.json" | wc -l)" = 0 ]; then
    printf 'ok: an empty http3_qlog_dir writes nothing\n'
else
    fail "traces were written with http3_qlog_dir empty"
fi

exit "$failed"
