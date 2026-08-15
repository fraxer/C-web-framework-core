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
    local config="$WORK_DIR/$name.json"
    local log="$WORK_DIR/$name.log"

    cat > "$config" <<JSON
{
    "main": {
        "workers": 1, "threads": 1, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": { "$name": $value }
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

    "$SERVER" -c "$config" -f > "$log" 2>&1
    local status=$?
    if [ "$status" -eq 0 ]; then
        printf 'config validation: %s was not rejected as expected (status %d)\n' \
            "$name" "$status" >&2
        return 1
    fi
}

ok=1
run_invalid http3_idle_timeout_sec 0 || ok=0
run_invalid http3_max_streams_uni '"three"' || ok=0
run_invalid http3_pacing 2 || ok=0

[ "$ok" -eq 1 ] || exit 1

printf 'config validation: invalid HTTP/3 types and ranges rejected\n'
