#!/usr/bin/env bash

# The IPv6 endpoint (docs/http3/01-udp-endpoint.md §7).
#
# Until this existed the whole server was IPv4: a config `ip` was parsed with
# inet_addr, a listener and a connection carried an in_addr_t, and the QUIC
# endpoint -- whose own socket layer had been sockaddr_storage since phase 1 --
# narrowed that address to AF_INET on the way in. What is checked here is the
# part no unit test can reach, because it is about two real sockets and the
# kernel:
#
#   1. a vhost configured on ::1 binds both TCP and UDP there, and a request
#      over each transport is answered by that vhost -- the answer matters more
#      than the bind, because vhost selection compares the connection's local
#      address with the vhost's, and an address that arrives as "unset" matches
#      nothing and yields 421 rather than a connection error;
#   2. HTTP/3 over IPv6 completes end to end, and the server's own counters --
#      not the client's report -- say a handshake finished;
#   3. connection migration over IPv6 works, which is the one QUIC feature that
#      rewrites the path address mid-connection;
#   4. IPv4 and IPv6 on the *same port number* are two separate endpoints
#      serving their own vhost. This is the check that fails if any of the three
#      address comparisons (listener lookup, QUIC endpoint lookup, vhost
#      selection) is family-blind: the second family would fold onto the first
#      one's socket and both roots would serve the same file;
#   5. a malformed `ip` rejects the config. inet_addr reported failure as
#      (in_addr_t)-1, which is also 255.255.255.255, so a typo used to become a
#      broadcast address and the bind failed naming an address nobody wrote.
#
# Skipped rather than failed where the machine has no IPv6 loopback: that is a
# property of the environment, and a gate that fails on it teaches people to
# ignore the gate.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_ipv6.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-ipv6}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${H3_IPV6_PORT:-18494}

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 ipv6: server or quicclient is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

# No IPv6 loopback, no test. Checked by binding rather than by reading
# /proc/net/if_inet6, because what matters is whether a socket can be bound
# here -- a container may have the address and forbid the family.
if ! python3 - <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::1", 0))
    s.close()
except OSError:
    sys.exit(1)
PY
then
    printf 'SKIP: this machine has no usable IPv6 loopback\n'
    exit 0
fi

mkdir -p "$WORK_DIR/www6" "$WORK_DIR/www4"
printf 'served over ipv6\n' > "$WORK_DIR/www6/index.html"
printf 'served over ipv4\n' > "$WORK_DIR/www4/index.html"

METRICS_SO="$BUILD_DIR/exec/handlers/bench/lib_metrics.so"

# One vhost per address, same port on both -- see check 4.
write_config() {
    cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": { "metrics": true }
    },
    "servers": {
        "s6": {
            "domains": ["localhost"], "ip": "::1", "port": $PORT,
            "root": "$WORK_DIR/www6", "index": "index.html",
            "tls": {
                "fullchain": "$CORE_DIR/tests/data/quic_test_cert.pem",
                "private": "$CORE_DIR/tests/data/quic_test_key.pem",
                "ciphers": "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
            },
            "http3": { "enabled": true, "port": $PORT },
            "http": {
                "routes": {
                    "/metrics": {
                        "GET": { "file": "$METRICS_SO", "function": "get" }
                    }
                }
            }
        },
        "s4": {
            "domains": ["localhost"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/www4", "index": "index.html",
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

get() {
    local address=$1 protocol=$2
    curl -ksS "$protocol" --max-time 5 --retry 3 --retry-connrefused \
        --resolve "localhost:$PORT:$address" "https://localhost:$PORT/"
}

metrics() {
    curl -ksS --max-time 5 --retry 3 --retry-connrefused \
        --resolve "localhost:$PORT:[::1]" "https://localhost:$PORT/metrics"
}

metric() {
    local object=$1 field=$2
    metrics | tr -d '\n' | sed -n \
        "s/.*\"$object\"[[:space:]]*:[[:space:]]*{[^}]*\"$field\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

write_config

"$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!

for _ in $(seq 1 50); do
    kill -0 "$server_pid" 2>/dev/null || break
    metrics >/dev/null 2>&1 && break
    sleep 0.1
done

if ! kill -0 "$server_pid" 2>/dev/null; then
    printf 'h3 ipv6: server did not start (see %s/server.log)\n' "$WORK_DIR" >&2
    cat "$WORK_DIR/server.log" >&2
    exit 1
fi

# ---- 1: TCP over IPv6, and the vhost it selects ----

body=$(get '[::1]' --http1.1)
if [ "$body" = "served over ipv6" ]; then
    printf 'ok: HTTP/1.1 over IPv6 is served by the IPv6 vhost\n'
else
    fail "HTTP/1.1 over IPv6 returned '$body'"
fi

body=$(get '[::1]' --http2)
if [ "$body" = "served over ipv6" ]; then
    printf 'ok: HTTP/2 over IPv6 is served by the IPv6 vhost\n'
else
    fail "HTTP/2 over IPv6 returned '$body'"
fi

# ---- 2: HTTP/3 over IPv6, confirmed by the server's own counters ----

handshakes_before=$(metric quic 'handshakes_completed')

# Without -q, so the body is printed and can be compared: which vhost answered
# is the whole point, and "a 200 arrived" would not show it.
if "$CLIENT" ::1 "$PORT" -a localhost --timeout 5000 \
        > "$WORK_DIR/h3.txt" 2>&1 &&
   grep -q 'served over ipv6' "$WORK_DIR/h3.txt"; then
    printf 'ok: HTTP/3 over IPv6 completed and returned the IPv6 vhost body\n'
else
    cat "$WORK_DIR/h3.txt" >&2
    fail "the HTTP/3 request over IPv6 did not complete"
fi

handshakes_after=$(metric quic 'handshakes_completed')

# The client's own "OK" is its opinion; this is the server saying it.
if [ "$(( ${handshakes_after:-0} - ${handshakes_before:-0} ))" -ge 1 ]; then
    printf 'ok: the server counted an IPv6 QUIC handshake (%s -> %s)\n' \
        "${handshakes_before:-0}" "${handshakes_after:-0}"
else
    fail "handshakes_completed went ${handshakes_before:-missing} -> ${handshakes_after:-missing}"
fi

# ---- 3: migration, the one feature that rewrites the path address ----

if "$CLIENT" ::1 "$PORT" -a localhost -q --timeout 5000 --migrate \
        > "$WORK_DIR/migrate.txt" 2>&1; then
    printf 'ok: connection migration over IPv6\n'
else
    cat "$WORK_DIR/migrate.txt" >&2
    fail "migration over IPv6 failed"
fi

# ---- 4: the two families are two endpoints, not one ----

body=$(get 127.0.0.1 --http1.1)
if [ "$body" = "served over ipv4" ]; then
    printf 'ok: the IPv4 vhost on the same port still serves its own root over TCP\n'
else
    fail "HTTP/1.1 over IPv4 returned '$body' (the two families share a listener?)"
fi

if "$CLIENT" 127.0.0.1 "$PORT" -a localhost --timeout 5000 \
        > "$WORK_DIR/h3v4.txt" 2>&1 &&
   grep -q 'served over ipv4' "$WORK_DIR/h3v4.txt"; then
    printf 'ok: the IPv4 vhost on the same port still serves its own root over HTTP/3\n'
else
    cat "$WORK_DIR/h3v4.txt" >&2
    fail "HTTP/3 over IPv4 did not return the IPv4 vhost body (endpoints folded together?)"
fi

cleanup
server_pid=

# ---- 5: a malformed address rejects the config ----

sed 's/"ip": "::1"/"ip": "::1x"/' "$WORK_DIR/config.json" > "$WORK_DIR/bad.json"

# Synchronous on purpose: the server returns instead of serving, which is the
# rejection. Its exit status is not the signal -- cwfr exits 0 on a config error,
# which is its own matter -- so what is asserted is that it came back at all and
# said which value it refused.
"$SERVER" -c "$WORK_DIR/bad.json" > "$WORK_DIR/bad.log" 2>&1

if grep -q 'not a valid IPv4 or IPv6 address: ::1x' "$WORK_DIR/bad.log"; then
    printf 'ok: a malformed ip rejects the config, naming the value\n'
else
    cat "$WORK_DIR/bad.log" >&2
    fail "a malformed ip did not produce the address error"
fi

if curl -ksS --max-time 2 --resolve "localhost:$PORT:[::1]" \
        "https://localhost:$PORT/" >/dev/null 2>&1; then
    fail "something is still serving on the port after the config was refused"
else
    printf 'ok: nothing was bound for the refused config\n'
fi

exit "$failed"
