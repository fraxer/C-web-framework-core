#!/usr/bin/env bash

# Process-wide QUIC connection and dynamic-buffer limits under real handshakes.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_resource_limits.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-resource-limits}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_LIMITS_PORT:-18459}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'resource limits: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf 'resource limits\n' > "$WORK_DIR/www/index.html"

server_pid=
client_pids=
cleanup() {
    for pid in $client_pids; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    client_pids=
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    server_pid=
}
trap cleanup EXIT INT TERM

write_config() {
    local memory_limit=$1
    cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_max_connections": 64,
            "http3_buffer_memory_limit": $memory_limit,
            "http3_idle_timeout_sec": 1,
            "http3_retry": "never",
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

metrics() {
    curl -ksS --retry 2 --retry-connrefused --max-time 5 \
        --resolve "localhost:$PORT:127.0.0.1" "https://localhost:$PORT/metrics"
}

metric() {
    local object=$1 field=$2
    metrics | tr -d '\n' | sed -n \
        "s/.*\"$object\"[[:space:]]*:[[:space:]]*{[^}]*\"$field\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

scalar_metric() {
    local field=$1
    metrics | tr -d '\n' | sed -n \
        "s/.*\"$field\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

start_server() {
    "$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
    server_pid=$!
    for _ in $(seq 1 50); do
        kill -0 "$server_pid" 2>/dev/null || return 1
        metrics >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

# 64 is the supported minimum. Clients discard every server packet, keeping
# their server-side handshakes alive without completing or closing them.
write_config 16777216
start_server || { printf 'resource limits: server did not start\n' >&2; exit 1; }

for i in $(seq 1 66); do
    "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --handshake-only \
        --loss-in 100 --timeout 10000 > "$WORK_DIR/conn-$i.log" 2>&1 &
    client_pids="$client_pids $!"
done

at_cap=0
for _ in $(seq 1 80); do
    current=$(metric connections current)
    peak=$(metric connections peak)
    refused_connections=$(scalar_metric 'refused.at_capacity')
    if [ "${current:-0}" -eq 64 ] && [ "${peak:-0}" -eq 64 ] &&
       [ "${refused_connections:-0}" -gt 0 ]; then
        at_cap=1
        break
    fi
    sleep 0.1
done
if [ "$at_cap" -ne 1 ]; then
    printf 'resource limits: connection limit was not enforced (current=%s peak=%s refused=%s)\n' \
        "${current:-missing}" "${peak:-missing}" \
        "${refused_connections:-missing}" >&2
    exit 1
fi

for pid in $client_pids; do kill "$pid" 2>/dev/null || true; done
for pid in $client_pids; do wait "$pid" 2>/dev/null || true; done
client_pids=

drained=0
for _ in $(seq 1 80); do
    current=$(metric connections current)
    [ "${current:-1}" -eq 0 ] && { drained=1; break; }
    sleep 0.1
done
if [ "$drained" -ne 1 ]; then
    printf 'resource limits: connection slots did not drain (current=%s)\n' \
        "${current:-missing}" >&2
    exit 1
fi
cleanup

# One CRYPTO receive buffer grows to 4096 bytes. A 4095-byte process budget
# must refuse that growth, count it, close/expire the connection and return to
# zero rather than leaking a partial reservation.
write_config 4095
start_server || { printf 'resource limits: memory-limit server did not start\n' >&2; exit 1; }
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --handshake-only --timeout 1500 \
    > "$WORK_DIR/memory-client.log" 2>&1 || true

memory_ok=0
for _ in $(seq 1 50); do
    refused=$(metric memory refused)
    current_bytes=$(metric memory current_bytes)
    if [ "${refused:-0}" -gt 0 ] && [ "${current_bytes:-1}" -eq 0 ]; then
        memory_ok=1
        break
    fi
    sleep 0.1
done
if [ "$memory_ok" -ne 1 ]; then
    printf 'resource limits: memory refusal/rollback missing (refused=%s current=%s)\n' \
        "${refused:-missing}" "${current_bytes:-missing}" >&2
    exit 1
fi

printf 'resource limits: connection cap and memory refusal drain cleanly\n'
