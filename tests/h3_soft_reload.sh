#!/usr/bin/env bash

# End-to-end regression for HTTP/3 soft reload.  A connection established by
# the old generation sends a request and pauses before reading its response,
# crosses SIGUSR1 with the same CID, and must finish through the old context. A fresh
# connection must simultaneously see the new configuration.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_soft_reload.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-soft-reload}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_SOFT_RELOAD_PORT:-18445}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'soft reload: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/old" "$WORK_DIR/new"
# Larger than QUICCONN_WRITE_AHEAD_MAX, so seeing the first DATA bytes cannot
# mean the response has already been fully staged and drained.
dd if=/dev/zero bs=1048576 count=1 status=none | tr '\0' 'o' > "$WORK_DIR/old/index.html"
printf 'new generation\n' > "$WORK_DIR/new/index.html"

CONFIG="$WORK_DIR/config.json"
write_config() {
    local root=$1
    cat > "$CONFIG.next" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "soft",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"],
            "ip": "127.0.0.1", "port": $PORT,
            "root": "$root", "index": "index.html",
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
    mv "$CONFIG.next" "$CONFIG"
}

server_pid=
old_client_pid=
cleanup() {
    if [ -n "$old_client_pid" ]; then
        kill "$old_client_pid" 2>/dev/null || true
        wait "$old_client_pid" 2>/dev/null || true
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

write_config "$WORK_DIR/old"
"$SERVER" -c "$CONFIG" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!

if ! wait_for_worker_count 2; then
    printf 'soft reload: initial workers did not start; see %s/server.log\n' "$WORK_DIR" >&2
    exit 1
fi

old_tids=$(worker_tids)

"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost \
    --pause-after-response 4000 --timeout 15000 --out "$WORK_DIR/old.body" \
    > "$WORK_DIR/old-client.log" 2>&1 &
old_client_pid=$!

paused=0
for i in $(seq 1 100); do
    if grep -q 'pausing after response data' "$WORK_DIR/old-client.log"; then
        paused=1
        break
    fi
    kill -0 "$old_client_pid" 2>/dev/null || break
    sleep 0.1
done

if [ "$paused" -ne 1 ]; then
    printf 'soft reload: old client did not receive response data before pause\n' >&2
    exit 1
fi

# Atomic replacement prevents the signal-side validator from observing a
# half-written JSON document.
write_config "$WORK_DIR/new"
kill -USR1 "$server_pid"

# While the old CID is alive, both generations must coexist: two old workers
# retain timer/wakeup ownership and two new workers own the sole UDP reader.
if ! wait_for_worker_count 4; then
    printf 'soft reload: old and new worker generations did not coexist\n' >&2
    exit 1
fi

for tid in $old_tids; do
    if [ ! -d "/proc/$server_pid/task/$tid" ]; then
        printf 'soft reload: old worker %s exited before its QUIC request\n' "$tid" >&2
        exit 1
    fi
done

# Thread creation precedes endpoint registration.  Seeing four thread names
# proves coexistence, but not yet that both new workers completed the reader
# handoff; give the bounded epoll shutdown turn time to finish before asserting
# which configuration a fresh connection reaches.
sleep 1

if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --timeout 5000 \
        --out "$WORK_DIR/new.body" > "$WORK_DIR/new-client.log" 2>&1; then
    printf 'soft reload: new-generation request failed\n' >&2
    exit 1
fi

if ! wait "$old_client_pid"; then
    old_client_pid=
    printf 'soft reload: old CID did not finish its request after SIGUSR1\n' >&2
    exit 1
fi
old_client_pid=

if ! cmp -s "$WORK_DIR/old/index.html" "$WORK_DIR/old.body"; then
    printf 'soft reload: old CID did not use the old routing context\n' >&2
    exit 1
fi
if ! grep -qx 'new generation' "$WORK_DIR/new.body"; then
    printf 'soft reload: fresh connection did not use the new routing context\n' >&2
    exit 1
fi

# The client's application CONNECTION_CLOSE releases the last old-generation
# connection, after which both original workers must retire.
for i in $(seq 1 100); do
    old_alive=0
    for tid in $old_tids; do
        [ -d "/proc/$server_pid/task/$tid" ] && old_alive=1
    done
    [ "$old_alive" -eq 0 ] && [ "$(worker_tids | wc -l)" -eq 2 ] && break
    sleep 0.1
done

for tid in $old_tids; do
    if [ -d "/proc/$server_pid/task/$tid" ]; then
        printf 'soft reload: drained old worker %s is still alive\n' "$tid" >&2
        exit 1
    fi
done

printf 'soft reload: old CID survived, configs split, old workers drained\n'
