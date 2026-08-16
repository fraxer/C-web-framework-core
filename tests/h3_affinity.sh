#!/usr/bin/env bash

# A connection follows its datagrams to the worker they arrive at
# (docs/http3/09-options.md §2.6).
#
# The kernel hands a datagram to a worker by hashing the 4-tuple; QUIC addresses
# a connection by its id and outlives the 4-tuple. So a client that migrates is
# served, from then on, by a worker that does not own it -- while the owner goes
# on sweeping it and draining its send queue. What is asserted here is that the
# split does not last: after a bounded run of misdirected datagrams the
# connection is rehomed, and the rest of the transfer is served locally.
#
# The assertion is on the *share*, not on a timing: without rehoming every
# datagram after the migration is foreign (measured at 82-86 % of a transfer),
# with it only the run that triggers the move is.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_affinity.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-affinity}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_AFFINITY_PORT:-18464}
# Enough workers that a migrated 4-tuple is unlikely to hash back to the worker
# it came from: with four, one run in four proves nothing, which is why the
# transfers below are repeated and the totals are what is judged.
WORKERS=${H3_AFFINITY_WORKERS:-4}
TRANSFERS=${H3_AFFINITY_TRANSFERS:-6}
# The rehome threshold is 8 datagrams per move (QUIC_REHOME_STREAK), plus the
# handshake datagrams that precede the migration. Threefold headroom over the
# worst case keeps this from measuring the scheduler.
MAX_FOREIGN_PER_TRANSFER=${H3_AFFINITY_MAX_FOREIGN:-30}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 affinity: server or quicclient unavailable\n' >&2
    exit 77
fi

mkdir -p "$WORK_DIR/www"
printf 'affinity\n' > "$WORK_DIR/www/index.html"
dd if=/dev/zero of="$WORK_DIR/www/large.bin" bs=1M count=8 status=none

cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": $WORKERS, "threads": 2, "reload": "soft",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": [],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_buffer_memory_limit": 67108864,
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
    "mimetypes": {
        "text/html": ["html"],
        "application/octet-stream": ["bin"]
    }
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

"$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!

ready=0
for _ in $(seq 1 50); do
    if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /index.html \
            --timeout 2000 > /dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    printf 'h3 affinity: server did not become ready\n' >&2
    exit 1
fi

# Reads one QUIC counter out of /metrics. The metrics route is itself an HTTP/3
# request, so it adds a connection of its own -- always a local one, which is
# why it can only make the assertion stricter, never looser.
counter() {
    local name=$1
    "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /metrics --timeout 5000 \
        --out "$WORK_DIR/metrics.json" > /dev/null 2>&1 || return 1
    sed -n "s/.*\"$name\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" \
        "$WORK_DIR/metrics.json" | head -1
}

foreign_before=$(counter routing.foreign) || exit 1
local_before=$(counter routing.local) || exit 1

for _ in $(seq 1 "$TRANSFERS"); do
    "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /large.bin --migrate \
        --timeout 60000 > "$WORK_DIR/transfer.log" 2>&1 || {
            printf 'h3 affinity: migrating transfer failed\n' >&2
            exit 1
        }
done

foreign_after=$(counter routing.foreign) || exit 1
local_after=$(counter routing.local) || exit 1
rehomed=$(counter routing.rehomed) || exit 1

foreign=$((foreign_after - foreign_before))
served=$((local_after - local_before + foreign))
budget=$((MAX_FOREIGN_PER_TRANSFER * TRANSFERS))

if [ "$served" -lt $((TRANSFERS * 50)) ]; then
    printf 'h3 affinity: only %d datagrams served, too few to judge\n' "$served" >&2
    exit 1
fi

# Nothing migrated onto another worker at all: every transfer's 4-tuple hashed
# back to its own worker. Nothing is proven, and nothing is broken either.
if [ "$foreign" -eq 0 ]; then
    printf 'h3 affinity: no transfer changed worker (%d datagrams, %d rehomed); skipped\n' \
        "$served" "$rehomed"
    exit 77
fi

if [ "$rehomed" -lt 1 ]; then
    printf 'h3 affinity: %d foreign datagrams and not one connection rehomed\n' \
        "$foreign" >&2
    exit 1
fi

if [ "$foreign" -gt "$budget" ]; then
    printf 'h3 affinity: %d of %d datagrams served by the wrong worker, budget %d\n' \
        "$foreign" "$served" "$budget" >&2
    printf 'h3 affinity: connections are not following their datagrams (rehomed %d)\n' \
        "$rehomed" >&2
    exit 1
fi

printf 'h3 affinity: %d rehomed, %d of %d datagrams foreign (budget %d)\n' \
    "$rehomed" "$foreign" "$served" "$budget"
