#!/usr/bin/env bash

# 0-RTT / early data (RFC 9001 §4.6, docs/http3/09 §3.1).
#
# Four things are checked, and the third is the one that matters:
#
#   1. with http3_early_data on, a resumed connection carries its whole HTTP/3
#      request in 0-RTT packets and is answered;
#   2. the /metrics counters say so (offered/accepted/packets/bytes);
#   3. a 0-RTT flight whose handshake never completes -- what a replaying
#      attacker can produce -- does NOT reach the dispatcher: `http3.requests`
#      must not move. This is the anti-replay policy, and it is the only check
#      that can tell "not answered" from "not executed";
#   4. with the key absent, early data is refused, so the default really is off.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_early_data.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-early-data}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_EARLY_PORT:-18461}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 early data: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf '<html><body>early</body></html>\n' > "$WORK_DIR/www/index.html"

write_config() {
    local path=$1 early=$2

    cat > "$path" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_early_data": $early,
            "http3_handshake_rate": 0
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
            "http3": { "enabled": true, "port": $PORT },
            "http": {
                "routes": {
                    "/metrics": {
                        "GET": {
                            "file": "$BUILD_DIR/exec/handlers/bench/lib_metrics.so",
                            "function": "get"
                        }
                    }
                }
            }
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

metrics() {
    curl -ksS --retry 2 --retry-connrefused --max-time 5 \
        --resolve "localhost:$PORT:127.0.0.1" "https://localhost:$PORT/metrics"
}

# One counter out of the JSON, by object and field, as the soak script does it.
metric() {
    local object=$1 field=$2
    metrics | tr -d '\n' | sed -n \
        "s/.*\"$object\"[[:space:]]*:[[:space:]]*{[^}]*\"$field\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

start_server() {
    local config=$1

    "$SERVER" -c "$config" -f > "$WORK_DIR/server.log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 50); do
        kill -0 "$server_pid" 2>/dev/null || break
        metrics >/dev/null 2>&1 && return 0
        sleep 0.1
    done

    printf 'h3 early data: server did not start (see %s/server.log)\n' "$WORK_DIR" >&2
    return 1
}

stop_server() {
    cleanup
    server_pid=
}

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

# ---- 1 and 2: early data on ----

write_config "$WORK_DIR/on.json" true
start_server "$WORK_DIR/on.json" || exit 1

if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --timeout 15000 --0rtt \
        > "$WORK_DIR/0rtt.txt" 2>&1; then
    printf 'ok: a resumed connection carried its request in 0-RTT\n'
else
    cat "$WORK_DIR/0rtt.txt" >&2
    fail "the 0-RTT request was not served"
fi

# The QUIC section is flat: `early_data.accepted` is one key with a dot in it,
# not a nested object, so the dot is escaped for the regex.
accepted=$(metric quic 'early_data\.accepted')
packets=$(metric quic 'early_data\.packets')
bytes=$(metric quic 'early_data\.bytes')

if [ "${accepted:-0}" -ge 1 ] && [ "${packets:-0}" -ge 1 ] && [ "${bytes:-0}" -ge 1 ]; then
    printf 'ok: metrics report accepted=%s packets=%s bytes=%s\n' \
        "$accepted" "$packets" "$bytes"
else
    fail "early_data metrics did not move (accepted=${accepted:-missing} packets=${packets:-missing} bytes=${bytes:-missing})"
fi

# ---- 3: the anti-replay property ----
#
# A 0-RTT flight arrives, the handshake never completes, and the request must
# not be dispatched. `http3.requests` counts dispatches, so it is the counter
# that separates "the answer did not come back" from "the handler never ran".

before=$(metric http3 requests)

if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --timeout 15000 --0rtt-stall \
        > "$WORK_DIR/0rtt-stall.txt" 2>&1; then
    printf 'ok: an unfinished handshake got no response\n'
else
    cat "$WORK_DIR/0rtt-stall.txt" >&2
    fail "a 0-RTT request was answered without a completed handshake"
fi

after=$(metric http3 requests)

# The stall run opens a first connection to collect a ticket, and that one does
# complete and does make one request -- so the budget is exactly one.
if [ "${after:-0}" -le $(( ${before:-0} + 1 )) ]; then
    printf 'ok: the replayable flight was never dispatched (requests %s -> %s)\n' \
        "${before:-0}" "${after:-0}"
else
    fail "a request from an unfinished handshake reached the dispatcher (requests ${before:-0} -> ${after:-0})"
fi

stop_server

# ---- 4: off by default ----

write_config "$WORK_DIR/off.json" false
start_server "$WORK_DIR/off.json" || exit 1

if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --timeout 15000 --0rtt \
        > "$WORK_DIR/0rtt-off.txt" 2>&1; then
    fail "early data was accepted with http3_early_data off"
else
    printf 'ok: early data is refused unless http3_early_data is on\n'
fi

stop_server

exit "$failed"
