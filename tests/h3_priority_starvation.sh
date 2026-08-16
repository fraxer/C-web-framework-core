#!/usr/bin/env bash

# What a small response pays for being asked for second (RFC 9218 §7).
#
# The send path walks its stream list in the order the streams were opened and
# gives the first one that can send as much of the packet as it will hold
# (quicconn.c). There is no per-stream quantum, so a large response owns the
# connection until it ends. RFC 9218 exists to tell a server when that is right
# -- it is the recommended behaviour for equal-urgency, non-incremental
# responses -- and when it is not. We accept and validate PRIORITY_UPDATE and
# ignore what it says (h3session.c), which is permitted (§2, the signals are
# advisory) and leaves the question open: what would honouring it be worth?
#
# This measures the ceiling of that answer. Three phases on one connection:
#
#   1. the small response alone -- what it costs with nothing in the way;
#   2. the large one first on the lower stream id, the small one 20 ms later;
#   3. the same two, same delay, same bytes -- stream ids swapped, so the small
#      one sits ahead of the large one in the server's list.
#
# Phase 3 is the control and the reason this concludes anything: a small
# response that is slow in phase 2 could be the server's send order, or it could
# be a client busy reading 64 MB and getting to the small stream late (docs/http3/08
# §7c, a mistake this project has already made once). Phase 3 holds the client's
# load constant and changes only what the server sees.
#
# What is asserted here is what must be true whether or not priorities are ever
# implemented: every response arrives whole, and a small response that IS ahead
# in the list is served at once. The scheduling cost itself is measured and
# printed, not bounded from below -- when RFC 9218 scheduling lands, that number
# drops towards zero and this test must keep passing.

set -u -o pipefail

# Every number here is a decimal fraction handed to awk. Under a locale whose
# decimal separator is a comma, awk reads "0.0026" as 0 -- which made the
# HTTP/2 comparison pass by comparing zero against zero.
export LC_ALL=C

BUILD_DIR=${1:?usage: tests/h3_priority_starvation.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-priority-starvation}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_PRIORITY_PORT:-18465}
STAGGER=${H3_PRIORITY_STAGGER:-20}

# 64 MB against 4 KB. The point is a ratio large enough that the wait cannot be
# mistaken for noise: on loopback the big one takes ~100 ms, which is three
# orders of magnitude above what the small one costs alone.
BIG_MB=${H3_PRIORITY_BIG_MB:-64}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 priority: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
dd if=/dev/zero of="$WORK_DIR/www/big.bin" bs=1M count="$BIG_MB" status=none
dd if=/dev/zero of="$WORK_DIR/www/small.bin" bs=4096 count=1 status=none
printf '<html><body>priority</body></html>\n' > "$WORK_DIR/www/index.html"

cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": [],
        "log": { "enabled": true, "level": "error" },
        "env": { "http3_buffer_memory_limit": 268435456 }
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
            "http": { "routes": {} }
        }
    },
    "mimetypes": { "text/html": ["html"], "application/octet-stream": ["bin"] }
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
    kill -0 "$server_pid" 2>/dev/null || break
    if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /small.bin --timeout 2000 \
            > "$WORK_DIR/warmup.txt" 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    printf 'h3 priority: server did not become ready (see %s/server.log)\n' "$WORK_DIR" >&2
    exit 1
fi

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

# ---- the measurement ----

if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /big.bin --mix /small.bin \
        --mix-delay "$STAGGER" --timeout 60000 > "$WORK_DIR/mix.txt" 2>&1; then
    cat "$WORK_DIR/mix.txt" >&2
    fail "the mixed-size run did not complete every response intact"
    exit 1
fi

value() { sed -n "s/^$1: *\([0-9.]*\) ms.*/\1/p" "$WORK_DIR/mix.txt" | head -1; }

alone=$(value 'small alone')
behind=$(value 'small behind the big one')
ahead=$(value 'small ahead of it')
big=$(sed -n 's/^  big alongside it: *\([0-9.]*\) ms.*/\1/p' "$WORK_DIR/mix.txt" | head -1)
cost=$(value 'scheduling cost')

if [ -z "$alone" ] || [ -z "$behind" ] || [ -z "$ahead" ] || [ -z "$big" ]; then
    cat "$WORK_DIR/mix.txt" >&2
    fail "could not read the timings out of the client's output"
    exit 1
fi

printf 'measured: small alone %s ms, behind the big one %s ms, ahead of it %s ms (big %s ms)\n' \
    "$alone" "$behind" "$ahead" "$big"

# 0. There has to be something to measure. If the big response finishes before
#    the small request is even sent, every number below is about an idle
#    connection -- and on a faster machine, or with H3_PRIORITY_BIG_MB turned
#    down, that is exactly what would happen without a word of warning.
if ! awk -v b="$big" -v s="$STAGGER" 'BEGIN { exit !(b > s * 2) }'; then
    printf 'h3 priority: the %s ms transfer is too short for a %s ms stagger; raise H3_PRIORITY_BIG_MB\n' \
        "$big" "$STAGGER" >&2
    exit 2
fi

# 1. The control. A small response that is ahead in the server's list must be
#    served straight away even while 64 MB is flowing past it -- and if it is
#    not, every other number here is about this client, not about the server.
if awk -v v="$ahead" 'BEGIN { exit !(v <= 20) }'; then
    printf 'ok: ahead of the big response, the small one took %s ms\n' "$ahead"
else
    fail "the control is not sound: a small response AHEAD in the list took $ahead ms"
fi

# 2. The same response, same load, second in the list. Not bounded from below on
#    purpose: this is the number the test exists to produce, and implementing
#    RFC 9218 scheduling is supposed to shrink it. Bounded from ABOVE, because a
#    wait longer than the transfer it is waiting for would be a defect of its
#    own rather than the queueing this documents.
if awk -v v="$behind" -v b="$big" 'BEGIN { exit !(v <= b + 50) }'; then
    printf 'measured: the scheduling cost is %s ms on a %s ms transfer\n' "$cost" "$big"
else
    fail "the small response waited $behind ms behind a $big ms transfer -- longer than the transfer itself"
fi

# 3. HTTP/2, same server, same two files, one connection. Not a nicety: it says
#    whether this is a property of our server or of h3 specifically, and the
#    answer decides whether the fix belongs in the QUIC send loop or nowhere.
#    curl must actually multiplex for the comparison to mean anything, which is
#    what num_connects=0 on the second transfer proves.
h2=$(curl -ks --http2 --parallel --resolve "localhost:$PORT:127.0.0.1" \
        -o /dev/null -o /dev/null \
        -w '%{url} %{num_connects} %{time_total}\n' \
        "https://localhost:$PORT/big.bin" "https://localhost:$PORT/small.bin" 2>/dev/null)

h2_small=$(printf '%s\n' "$h2" | awk '/small.bin/ { print $3 * 1000 }')
h2_big=$(printf '%s\n' "$h2" | awk '/big.bin/ { print $3 * 1000 }')
h2_reused=$(printf '%s\n' "$h2" | awk '/small.bin/ { print $2 }')

if [ -z "$h2_small" ] || [ -z "$h2_big" ] ||
   ! awk -v b="$h2_big" 'BEGIN { exit !(b > 1) }'; then
    # A big transfer that reportedly took under a millisecond means the numbers
    # did not parse, not that HTTP/2 is instant. Comparing them would be the
    # vacuous pass this guard exists to prevent.
    printf 'skip: curl produced no usable HTTP/2 timings (%s)\n' "${h2_big:-none}"
elif [ "${h2_reused:-1}" != "0" ]; then
    printf 'skip: curl opened a second connection, so there is nothing to compare\n'
elif awk -v s="$h2_small" -v b="$h2_big" 'BEGIN { exit !(s <= b * 0.5) }'; then
    printf 'ok: over HTTP/2 on one connection the small response took %.1f ms against %.1f ms\n' \
        "$h2_small" "$h2_big"
else
    fail "HTTP/2 starves the small response too: ${h2_small} ms against ${h2_big} ms"
fi

exit "$failed"
