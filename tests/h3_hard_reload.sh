#!/usr/bin/env bash

# End-to-end regression for a hard HTTP/3 reload.  The important assertion is
# about threads, not merely requests: every Server worker from the old config
# generation must disappear even while it owns an unfinished QUIC connection.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_hard_reload.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-hard-reload}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_RELOAD_PORT:-18444}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'hard reload: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf '<html><body>hard reload</body></html>\n' > "$WORK_DIR/www/index.html"

CONFIG="$WORK_DIR/config.json"
cat > "$CONFIG" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": { "metrics": true }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"],
            "ip": "127.0.0.1", "port": $PORT,
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

server_pid=
blocked_pid=
cleanup() {
    if [ -n "$blocked_pid" ]; then
        kill "$blocked_pid" 2>/dev/null || true
        wait "$blocked_pid" 2>/dev/null || true
    fi
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

worker_tids() {
    local task comm
    for task in "/proc/$server_pid/task/"*; do
        [ -r "$task/comm" ] || continue
        IFS= read -r comm < "$task/comm"
        [ "$comm" = "Server worker" ] && printf '%s\n' "${task##*/}"
    done
}

wait_for_worker_count() {
    local wanted=$1
    local i count
    for i in $(seq 1 100); do
        kill -0 "$server_pid" 2>/dev/null || return 1
        count=$(worker_tids | wc -l)
        [ "$count" -eq "$wanted" ] && return 0
        sleep 0.1
    done
    return 1
}

"$SERVER" -c "$CONFIG" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!

if ! wait_for_worker_count 2; then
    printf 'hard reload: initial workers did not start; see %s/server.log\n' "$WORK_DIR" >&2
    exit 1
fi

old_tids=$(worker_tids)
[ "$(printf '%s\n' "$old_tids" | sed '/^$/d' | wc -l)" -eq 2 ] || exit 1

# Keep an Initial alive in an old worker.  Dropping every server datagram means
# the client cannot finish its handshake and therefore cannot close the server
# connection before SIGUSR1 exercises the abort path.
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --handshake-only \
    --loss-in 100 --timeout 10000 > "$WORK_DIR/blocked.log" 2>&1 &
blocked_pid=$!

# Observe the process gauge through HTTP/3 before signalling.  This proves the
# impaired client reached the server and owns an unfinished handshake; without
# it, a test could pass merely because all of that client's Initials vanished.
handshake_seen=0
for i in $(seq 1 30); do
    if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /metrics \
            --out "$WORK_DIR/metrics.json" > "$WORK_DIR/before.log" 2>&1 &&
       grep -Eq '"handshakes"[[:space:]]*:[[:space:]]*\{[[:space:]]*"inflight"[[:space:]]*:[[:space:]]*[1-9]' \
            "$WORK_DIR/metrics.json"; then
        handshake_seen=1
        break
    fi
    sleep 0.1
done

if [ "$handshake_seen" -ne 1 ]; then
    printf 'hard reload: no unfinished server handshake observed; see %s/metrics.json\n' \
        "$WORK_DIR" >&2
    exit 1
fi

kill -USR1 "$server_pid"

# New workers may start before the old ones finish.  Check both properties:
# none of the recorded TIDs survives, and exactly two current workers remain.
for i in $(seq 1 100); do
    old_alive=0
    for tid in $old_tids; do
        [ -d "/proc/$server_pid/task/$tid" ] && old_alive=1
    done
    if [ "$old_alive" -eq 0 ] && [ "$(worker_tids | wc -l)" -eq 2 ]; then
        break
    fi
    sleep 0.1
done

for tid in $old_tids; do
    if [ -d "/proc/$server_pid/task/$tid" ]; then
        printf 'hard reload: old Server worker %s is still alive\n' "$tid" >&2
        exit 1
    fi
done

if [ "$(worker_tids | wc -l)" -ne 2 ]; then
    printf 'hard reload: replacement worker generation is incomplete\n' >&2
    exit 1
fi

if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost > "$WORK_DIR/after.log" 2>&1; then
    printf 'hard reload: request after reload failed; see %s/after.log\n' "$WORK_DIR" >&2
    exit 1
fi

printf 'hard reload: old workers exited and the new generation serves HTTP/3\n'
