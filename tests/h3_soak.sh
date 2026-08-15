#!/usr/bin/env bash

# Sustained HTTP/3 requests plus impairment/migration and post-drain RSS checks.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_soak.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-soak}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_SOAK_PORT:-18460}
REQUESTS=${SOAK_REQUESTS:-1000}
RSS_GROWTH_KB=${SOAK_RSS_GROWTH_KB:-16384}
# The in-tree client has 64 stream slots and reserves eight for control/QPACK.
BATCH=50

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 soak: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi
if [ "$REQUESTS" -lt 1 ]; then
    printf 'h3 soak: SOAK_REQUESTS must be positive\n' >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf 'soak\n' > "$WORK_DIR/www/index.html"

cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "soft",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_buffer_memory_limit": 67108864,
            "http3_idle_timeout_sec": 2,
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

metric() {
    local object=$1 field=$2
    metrics | tr -d '\n' | sed -n \
        "s/.*\"$object\"[[:space:]]*:[[:space:]]*{[^}]*\"$field\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

rss_kb() {
    sed -n 's/^VmRSS:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "/proc/$server_pid/status"
}

wait_drained() {
    local current memory
    for _ in $(seq 1 80); do
        current=$(metric connections current)
        memory=$(metric memory current_bytes)
        if [ "${current:-1}" -eq 0 ] && [ "${memory:-1}" -eq 0 ]; then
            return 0
        fi
        sleep 0.1
    done
    printf 'h3 soak: resources did not drain (connections=%s memory=%s)\n' \
        "${current:-missing}" "${memory:-missing}" >&2
    return 1
}

"$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
    kill -0 "$server_pid" 2>/dev/null || break
    metrics >/dev/null 2>&1 && break
    sleep 0.1
done
metrics >/dev/null 2>&1 || { printf 'h3 soak: server did not start\n' >&2; exit 1; }

# Warm allocator/OpenSSL caches before taking the baseline; retained one-time
# arenas are not a per-request leak.
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -n "$BATCH" --timeout 15000 \
    > "$WORK_DIR/warmup.log" 2>&1 || {
        printf 'h3 soak: warmup failed\n' >&2; exit 1;
    }
wait_drained || exit 1
rss_before=$(rss_kb)

done_requests=0
run=0
while [ "$done_requests" -lt "$REQUESTS" ]; do
    left=$((REQUESTS - done_requests))
    count=$BATCH
    [ "$left" -lt "$count" ] && count=$left
    run=$((run + 1))
    if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -n "$count" \
            --timeout 15000 > "$WORK_DIR/run-$run.log" 2>&1; then
        printf 'h3 soak: request batch %d failed after %d requests\n' \
            "$run" "$done_requests" >&2
        exit 1
    fi
    done_requests=$((done_requests + count))
done

# Deterministic adverse-path samples are separate from the request count: the
# assertion here is survival and recovery, not throughput under impairment.
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -n 20 --loss-in 10 \
    --reorder 10 --dup 10 --seed 42 --timeout 15000 \
    > "$WORK_DIR/impaired.log" 2>&1 || {
        printf 'h3 soak: loss/reorder/dup scenario failed\n' >&2; exit 1;
    }
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost --cid --migrate \
    --timeout 15000 > "$WORK_DIR/migration.log" 2>&1 || {
        printf 'h3 soak: migration scenario failed\n' >&2; exit 1;
    }

wait_drained || exit 1
rss_after=$(rss_kb)
if [ -z "$rss_before" ] || [ -z "$rss_after" ] ||
   [ "$rss_after" -gt $((rss_before + RSS_GROWTH_KB)) ]; then
    printf 'h3 soak: RSS did not return near baseline (%s -> %s KiB, allowance %s)\n' \
        "${rss_before:-missing}" "${rss_after:-missing}" "$RSS_GROWTH_KB" >&2
    exit 1
fi

printf 'h3 soak: %d requests, impairment and migration drained (RSS %s -> %s KiB)\n' \
    "$done_requests" "$rss_before" "$rss_after"
