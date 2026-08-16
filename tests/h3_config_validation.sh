#!/usr/bin/env bash

# Invalid HTTP/3 policy must reject startup instead of being silently clamped.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_config_validation.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-config-validation}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"

mkdir -p "$WORK_DIR/www"
printf 'validation\n' > "$WORK_DIR/www/index.html"

run_invalid() {
    local name=$1 value=$2
    __write_config "$name" "\"$name\": $value"
    __expect_rejected "$name"
}

# Some settings are only invalid in combination, so the fixture takes a whole
# env body rather than one key.
run_invalid_env() {
    local name=$1 env=$2
    __write_config "$name" "$env"
    __expect_rejected "$name"
}

__expect_rejected() {
    local name=$1
    "$SERVER" -c "$WORK_DIR/$name.json" -f > "$WORK_DIR/$name.log" 2>&1
    local status=$?
    if [ "$status" -eq 0 ]; then
        printf 'config validation: %s was not rejected as expected (status %d)\n' \
            "$name" "$status" >&2
        return 1
    fi
}

__write_config() {
    local name=$1 env=$2
    local config="$WORK_DIR/$name.json"

    cat > "$config" <<JSON
{
    "main": {
        "workers": 1, "threads": 1, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": { $env }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"], "ip": "127.0.0.1", "port": 18458,
            "root": "$WORK_DIR/www", "index": "index.html",
            "tls": {
                "fullchain": "$CORE_DIR/tests/data/quic_test_cert.pem",
                "private": "$CORE_DIR/tests/data/quic_test_key.pem",
                "ciphers": "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
            },
            "http3": { "enabled": true, "port": 18458 }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON
}

ok=1
run_invalid http3_idle_timeout_sec 0 || ok=0
run_invalid http3_max_streams_uni '"three"' || ok=0
run_invalid http3_pacing 2 || ok=0
run_invalid http3_rx_batch 257 || ok=0
run_invalid http3_so_rcvbuf -1 || ok=0
run_invalid http3_handshake_rate -1 || ok=0
run_invalid http3_stateless_reset_burst 0 || ok=0
run_invalid http3_retry_threshold 4000001 || ok=0
run_invalid http3_token_lifetime_sec 0 || ok=0
run_invalid http3_new_token 1 || ok=0
run_invalid http3_max_field_section_size 1073741825 || ok=0
run_invalid http3_abort_rate -1 || ok=0
run_invalid http3_abort_burst 0 || ok=0
run_invalid http3_ctrl_rate '"fast"' || ok=0
run_invalid http3_ctrl_burst 0 || ok=0
run_invalid http3_cc '"quadratic"' || ok=0

# BBR sends at a measured rate and keeps a window deliberately wider than that
# rate; without the pacer it would send the whole window at line rate and then
# measure the queue it built. The pair is refused rather than corrected --
# either setting could be the one the operator meant.
run_invalid_env http3_cc_bbr_needs_pacing \
    '"http3_cc": "bbr", "http3_pacing": false' || ok=0

[ "$ok" -eq 1 ] || exit 1

# Reload uses the same validation before the current generation receives
# shutdown. An invalid candidate must leave its Server worker serving.
ACTIVE_CONFIG="$WORK_DIR/reload.json"
sed 's/"http3_pacing": 2/"http3_pacing": true/' \
    "$WORK_DIR/http3_pacing.json" > "$ACTIVE_CONFIG"

SERVER_PID=
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"$SERVER" -c "$ACTIVE_CONFIG" -f > "$WORK_DIR/reload.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 50); do
    if curl -ksS --max-time 1 -o /dev/null https://127.0.0.1:18458/; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    printf 'config validation: valid reload fixture did not start\n' >&2
    exit 1
fi

WORKER_TID=
for task in "/proc/$SERVER_PID/task/"*; do
    [ -r "$task/comm" ] || continue
    IFS= read -r comm < "$task/comm"
    if [ "$comm" = "Server worker" ]; then
        WORKER_TID=${task##*/}
        break
    fi
done
if [ -z "$WORKER_TID" ]; then
    printf 'config validation: Server worker TID not found\n' >&2
    exit 1
fi

sed 's/"http3_pacing": true/"http3_pacing": 2/' \
    "$ACTIVE_CONFIG" > "$ACTIVE_CONFIG.new"
mv "$ACTIVE_CONFIG.new" "$ACTIVE_CONFIG"
kill -USR1 "$SERVER_PID"
sleep 0.5

if ! kill -0 "$SERVER_PID" 2>/dev/null ||
   [ ! -r "/proc/$SERVER_PID/task/$WORKER_TID/comm" ] ||
   ! curl -ksS --max-time 2 -o /dev/null https://127.0.0.1:18458/; then
    printf 'config validation: invalid reload stopped the current generation\n' >&2
    exit 1
fi

cleanup
SERVER_PID=
trap - EXIT INT TERM

printf 'config validation: invalid startup and reload candidates rejected\n'
