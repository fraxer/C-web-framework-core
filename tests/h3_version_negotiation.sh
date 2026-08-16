#!/usr/bin/env bash

# Version negotiation (RFC 9000 §6.1, §14.1, §17.2.1).
#
# A server that implements one QUIC version still owes a defined behaviour to a
# peer that speaks another one, and that behaviour was the only server-visible
# QUIC feature with no test above the unit level: the encoder was checked byte
# by byte in tests/unit/test_quic_invariants.c, but nothing ever asked a running
# server for a Version Negotiation packet. Four things are checked:
#
#   1. a full-sized Initial of an unknown version (QUIC v2, RFC 9369) is
#      answered with a Version Negotiation packet that offers version 1 and a
#      reserved version, echoes the connection ids swapped, is smaller than the
#      probe, and does NOT offer the version that was probed;
#   2. one byte under the §14.1 minimum, the same probe is ignored -- otherwise
#      the endpoint amplifies for a spoofed source address -- and the counters
#      say which rule dropped it;
#   3. the /metrics counters move: version_negotiation_sent and
#      drop.short_initial;
#   4. http3_version_negotiation_rate caps the reply rate, so the packet cannot
#      be used as an amplifier at volume.
#
# What this cannot check is a client that then falls back to version 1: this
# client has no version 2 to fall back from. That belongs to the interop runner
# (docs/http3/08 §2), where the peers are real implementations.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_version_negotiation.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-version-negotiation}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_VN_PORT:-18463}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 version negotiation: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf '<html><body>vn</body></html>\n' > "$WORK_DIR/www/index.html"

write_config() {
    local path=$1 rate=$2 burst=$3

    cat > "$path" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_version_negotiation_rate": $rate,
            "http3_version_negotiation_burst": $burst
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

    printf 'h3 version negotiation: server did not start (see %s/server.log)\n' "$WORK_DIR" >&2
    return 1
}

stop_server() {
    cleanup
    server_pid=
}

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

# ---- 1, 2 and 3: the packet itself, and the counters ----

write_config "$WORK_DIR/default.json" 100 200
start_server "$WORK_DIR/default.json" || exit 1

vn_before=$(metric quic 'version_negotiation_sent')
short_before=$(metric quic 'drop\.short_initial')

if "$CLIENT" 127.0.0.1 "$PORT" -q --timeout 5000 --version \
        > "$WORK_DIR/probe.txt" 2>&1; then
    printf 'ok: an unknown version is answered with version negotiation\n'
else
    cat "$WORK_DIR/probe.txt" >&2
    fail "the version negotiation probe did not get a conforming answer"
fi

vn_after=$(metric quic 'version_negotiation_sent')
short_after=$(metric quic 'drop\.short_initial')

# Exactly one: the full-sized probe. The undersized one must not be counted
# here, which is what separates "answered both" from "answered the right one".
if [ "$(( ${vn_after:-0} - ${vn_before:-0} ))" -eq 1 ]; then
    printf 'ok: version_negotiation_sent moved by one (%s -> %s)\n' \
        "${vn_before:-0}" "${vn_after:-0}"
else
    fail "version_negotiation_sent went ${vn_before:-missing} -> ${vn_after:-missing}, expected +1"
fi

# And the undersized probe was dropped for the documented reason rather than
# for some other one -- the counter is the only place that distinction exists.
if [ "$(( ${short_after:-0} - ${short_before:-0} ))" -ge 1 ]; then
    printf 'ok: the undersized probe was dropped as a short Initial (%s -> %s)\n' \
        "${short_before:-0}" "${short_after:-0}"
else
    fail "drop.short_initial went ${short_before:-missing} -> ${short_after:-missing}, expected +1"
fi

# ---- our own version is not answered with version negotiation ----
#
# The mirror image of check 1, and the reason it is worth its own run: a server
# that answered every Initial with a Version Negotiation packet would pass
# everything above and be unable to serve anybody.

vn_before=$(metric quic 'version_negotiation_sent')

"$CLIENT" 127.0.0.1 "$PORT" --version 00000001 --version-flood 3 \
    > "$WORK_DIR/v1.txt" 2>&1
v1_answered=$(sed -n 's/^version negotiation: *\([0-9][0-9]*\)$/\1/p' "$WORK_DIR/v1.txt")

if [ "${v1_answered:-1}" -eq 0 ]; then
    printf 'ok: a version 1 Initial is not answered with version negotiation\n'
else
    cat "$WORK_DIR/v1.txt" >&2
    fail "version 1 probes drew ${v1_answered:-?} version negotiation packets"
fi

stop_server

# ---- 4: the rate limit ----
#
# A Version Negotiation packet is sent to an unvalidated address, so it is
# exactly the kind of reply an attacker would want to trigger in volume. One
# token per second, one in the bucket: the first probe is answered and the rest
# are not, apart from the token or two that regenerate while the flood runs.

write_config "$WORK_DIR/limited.json" 1 1
start_server "$WORK_DIR/limited.json" || exit 1

budget_before=$(metric quic 'drop\.no_budget')

"$CLIENT" 127.0.0.1 "$PORT" --version-flood 8 > "$WORK_DIR/flood.txt" 2>&1
flood_status=$?
answered=$(sed -n 's/^version negotiation: *\([0-9][0-9]*\)$/\1/p' "$WORK_DIR/flood.txt")

budget_after=$(metric quic 'drop\.no_budget')

if [ "$flood_status" -ne 0 ]; then
    cat "$WORK_DIR/flood.txt" >&2
    fail "the flood could not be sent"
elif [ "${answered:-0}" -ge 1 ] && [ "${answered:-99}" -le 3 ]; then
    printf 'ok: 8 probes drew %s answers under a 1/s limit\n' "$answered"
else
    cat "$WORK_DIR/flood.txt" >&2
    fail "8 probes drew ${answered:-?} answers under a 1/s limit (expected 1..3)"
fi

if [ "$(( ${budget_after:-0} - ${budget_before:-0} ))" -ge 1 ]; then
    printf 'ok: the refused probes were counted as drop.no_budget (%s -> %s)\n' \
        "${budget_before:-0}" "${budget_after:-0}"
else
    fail "drop.no_budget went ${budget_before:-missing} -> ${budget_after:-missing}, expected to grow"
fi

stop_server

exit "$failed"
