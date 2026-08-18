#!/usr/bin/env bash

# A quiet connection must outlive the idle timeout when keep-alive is on.
#
# This is the defect that reached production: with no PING, a QUIC session dies
# after ~30 s of silence, and the server drops it without saying so (RFC 9000
# §10.1 -- an idle timeout is not signalled). The browser goes on believing the
# session is usable, sends its next navigation into it, waits out its own
# timers, and only then retries over TCP. The user sees a multi-second stall
# ending on HTTP/2, and every failed QUIC attempt also marks the alternative
# service broken, so it stays on HTTP/2 afterwards.
#
# The unit tests cover quicconn_keepalive_interval and the stand drives the
# timer on a virtual clock; neither can catch a PING that is computed correctly
# and never reaches the wire. Only a real socket and a real wait can.
#
# The instrument matters as much as the assertion. `--idle` pumps the client's
# event loop without sending anything of its own, which is what an open browser
# tab does; sleeping instead (--pause-after-handshake) models a *dead* peer, and
# a dead peer kills the connection whatever the server does -- the server's PING
# is ack-eliciting, and it is the peer's acknowledgement that restarts the
# server's idle timer. A sleep-based test reports "keep-alive is broken" against
# a server whose keep-alive works.
#
# Both arms are run for that reason: without the keep-alive-off arm, a test that
# passes proves only that the wait was too short.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_keepalive.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-keepalive}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
PORT=${KEEPALIVE_PORT:-18499}

# Longer than the 30 s default idle timeout, and long enough that a keep-alive
# clamped to half of it has to fire more than once.
IDLE_MS=${KEEPALIVE_IDLE_MS:-40000}

for binary in "$SERVER" "$CLIENT"; do
    if [ ! -x "$binary" ]; then
        printf 'h3 keepalive: %s is missing\n' "$binary" >&2
        exit 2
    fi
done

mkdir -p "$WORK_DIR/www"
printf 'alive\n' > "$WORK_DIR/www/index.html"

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

write_config() {
    cat > "$WORK_DIR/ka$1.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": false, "level": "error" },
        "env": { "http3_keepalive_sec": $1 }
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
            "http3": { "enabled": true, "port": $PORT }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON
}

# $1 keep-alive seconds, $2 "survives" | "dies"
run_arm() {
    local seconds=$1 expected=$2 pid status

    write_config "$seconds"

    "$SERVER" -c "$WORK_DIR/ka$seconds.json" -f > "$WORK_DIR/server.$seconds.log" 2>&1 &
    pid=$!
    sleep 1

    if ! kill -0 "$pid" 2>/dev/null; then
        cat "$WORK_DIR/server.$seconds.log" >&2
        fail "the server did not start with http3_keepalive_sec=$seconds"
        return
    fi

    timeout 120 "$CLIENT" 127.0.0.1 "$PORT" -a localhost -p / -q \
        --idle "$IDLE_MS" --timeout 15000 > "$WORK_DIR/client.$seconds.log" 2>&1
    status=$?

    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    if [ "$expected" = survives ]; then
        if [ "$status" -eq 0 ] && grep -q 'status:  *200' "$WORK_DIR/client.$seconds.log"; then
            printf 'ok: http3_keepalive_sec=%s keeps a connection through %s ms of silence\n' \
                   "$seconds" "$IDLE_MS"
        else
            cat "$WORK_DIR/client.$seconds.log" >&2
            fail "http3_keepalive_sec=$seconds did not survive $IDLE_MS ms of silence"
        fi
    else
        if [ "$status" -ne 0 ]; then
            printf 'ok: and without it the same connection is gone (the control)\n'
        else
            fail "the connection survived $IDLE_MS ms with keep-alive off; the wait proves nothing"
        fi
    fi
}

run_arm 10 survives
run_arm 0  dies

exit "$failed"
