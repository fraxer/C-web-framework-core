#!/usr/bin/env bash

# QUIC v2 (RFC 9369) and compatible version negotiation (RFC 9368).
#
# v2 is v1 with four constants moved -- a different initial salt, a "quicv2 "
# prefix on the packet-protection labels, a different Retry integrity key, and
# the four long-header type codes rotated. The unit vectors
# (tests/unit/test_quic_crypto.c, tests/unit/test_quic_retry.c) prove each
# constant against the RFC's own numbers; this asks a running server the only
# questions those cannot:
#
#   1. with http3_version_2 on, a client that speaks v2 outright completes a
#      handshake and gets its response;
#   2. with it on, a client that *starts* in v1 and offers v2 is moved to v2 by
#      the server, and the exchange completes in the new version -- which is the
#      whole of RFC 9368 §2.3, and the case the interop runner calls `v2`;
#   3. with it off, the same v2 client gets a Version Negotiation packet instead
#      of a handshake, and the v1-with-an-offer client stays in v1 -- i.e. the
#      switch off leaves a plain RFC 9000 server;
#   4. the counters move, because "the option is on" and "anything ever used it"
#      are different facts and only the second one matters.
#
# Every one of v2's differences is silent when wrong: the packets stay well
# formed and simply never open. So the assertion that means something is always
# a response arriving, never a packet being accepted.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_version_2.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-version-2}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_V2_PORT:-18466}

QUIC_V2=6b3343cf
QUIC_V1=00000001

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 version 2: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf '<html><body>v2</body></html>\n' > "$WORK_DIR/www/index.html"

failures=0
fail() { printf 'FAIL: %s\n' "$1"; failures=$((failures + 1)); }

write_config() {
    local path=$1 enabled=$2

    cat > "$path" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": [],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_version_2": $enabled,
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
stop_server() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    server_pid=
}
trap stop_server EXIT INT TERM

start_server() {
    "$SERVER" -c "$1" -f > "$WORK_DIR/server.log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 50); do
        if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /index.html \
                --timeout 2000 > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done

    printf 'h3 version 2: server did not start (see %s/server.log)\n' "$WORK_DIR" >&2
    return 1
}

metric() {
    curl -fsk --resolve "localhost:$PORT:127.0.0.1" "https://localhost:$PORT/metrics" |
        sed -n "s/.*\"$1\":[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -1
}

# The version a completed exchange ended in, or nothing when it did not
# complete. Both halves matter: a client that failed prints no version at all,
# and one that quietly stayed in v1 prints the wrong one.
ran_version() {
    local log=$1
    shift

    if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /index.html \
            --timeout 5000 "$@" > "$log" 2>&1; then
        return 1
    fi

    sed -n 's/^quic version: *\([0-9a-f]*\)$/\1/p' "$log" | head -1
}

# ---- 1 and 2: with the option on ----

write_config "$WORK_DIR/on.json" true
start_server "$WORK_DIR/on.json" || exit 1

v2_before=$(metric 'version2\.connections')
neg_before=$(metric 'version2\.negotiated')

got=$(ran_version "$WORK_DIR/direct.txt" --quic-version "$QUIC_V2") || got=
if [ "$got" = "$QUIC_V2" ]; then
    printf 'ok: a client speaking v2 completed the exchange in v2\n'
else
    fail "a v2 client ended in version '${got:-none}' (see $WORK_DIR/direct.txt)"
fi

# The interop runner's `v2` case, in one line: start in v1, list v2 as
# available, and the server is expected to move the connection.
got=$(ran_version "$WORK_DIR/compat.txt" --offer-versions "$QUIC_V2,$QUIC_V1") || got=
if [ "$got" = "$QUIC_V2" ]; then
    printf 'ok: a v1 client offering v2 was moved to v2 (RFC 9368 §2.3)\n'
else
    fail "compatible version negotiation ended in '${got:-none}' (see $WORK_DIR/compat.txt)"
fi

# And the announcement carried nothing but the announcement. A peer is entitled
# to read the Version field of that packet and discard the rest -- picoquic
# does, and its own server never puts anything there -- so a ServerHello riding
# in it is a handshake that dies of idle timeout against a real client while
# passing every test written against our own (docs/http3/08 §17f).
if grep -q '^switch packet carried crypto: no$' "$WORK_DIR/compat.txt"; then
    printf 'ok: the packet announcing the switch carried no CRYPTO\n'
else
    fail "the version announcement carried CRYPTO (see $WORK_DIR/compat.txt)"
fi

# ---- 4: the counters ----

v2_after=$(metric 'version2\.connections')
neg_after=$(metric 'version2\.negotiated')

if [ "${v2_after:-0}" -ge $(( ${v2_before:-0} + 1 )) ]; then
    printf 'ok: version2.connections moved (%s -> %s)\n' "${v2_before:-0}" "${v2_after:-0}"
else
    fail "version2.connections went ${v2_before:-?} -> ${v2_after:-?}, expected to grow"
fi

if [ "${neg_after:-0}" -ge $(( ${neg_before:-0} + 1 )) ]; then
    printf 'ok: version2.negotiated moved (%s -> %s)\n' "${neg_before:-0}" "${neg_after:-0}"
else
    fail "version2.negotiated went ${neg_before:-?} -> ${neg_after:-?}, expected to grow"
fi

# A v1 client that says nothing about versions must be untouched by any of this.
got=$(ran_version "$WORK_DIR/plain-on.txt") || got=
if [ "$got" = "$QUIC_V1" ]; then
    printf 'ok: a plain v1 client is left in v1 even with v2 on\n'
else
    fail "a plain v1 client ended in '${got:-none}' with v2 on"
fi

stop_server

# ---- 3: with the option off ----

write_config "$WORK_DIR/off.json" false
start_server "$WORK_DIR/off.json" || exit 1

vn_before=$(metric 'version_negotiation_sent')

if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /index.html \
        --quic-version "$QUIC_V2" --timeout 3000 > "$WORK_DIR/off-direct.txt" 2>&1; then
    fail "a v2 client completed a handshake against a server with v2 switched off"
else
    printf 'ok: with v2 off, a v2 client gets no handshake\n'
fi

vn_after=$(metric 'version_negotiation_sent')
if [ "${vn_after:-0}" -gt "${vn_before:-0}" ]; then
    printf 'ok: and it was told so with a Version Negotiation packet (%s -> %s)\n' \
        "${vn_before:-0}" "${vn_after:-0}"
else
    fail "no Version Negotiation packet was sent (${vn_before:-?} -> ${vn_after:-?})"
fi

# The other half of "off": nothing is advertised, so nothing is negotiated.
got=$(ran_version "$WORK_DIR/off-compat.txt" --offer-versions "$QUIC_V2,$QUIC_V1") || got=
if [ "$got" = "$QUIC_V1" ]; then
    printf 'ok: with v2 off, a client offering v2 stays in v1\n'
else
    fail "with v2 off a client offering v2 ended in '${got:-none}'"
fi

v2_off=$(metric 'version2\.connections')
if [ "${v2_off:-0}" -eq 0 ]; then
    printf 'ok: and version2.connections stayed at zero\n'
else
    fail "version2.connections is ${v2_off:-?} on a server with v2 off"
fi

stop_server

if [ "$failures" -gt 0 ]; then
    printf '\nh3 version 2: %d check(s) failed\n' "$failures" >&2
    exit 1
fi

printf '\nh3 version 2: v2 served, negotiated when offered, and absent when switched off\n'
