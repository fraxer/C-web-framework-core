#!/usr/bin/env bash

# Root static routes and fallback requests count missing files too.
set -euo pipefail

BUILD_DIR=${1:?usage: tests/root_ratelimit.sh BUILD_DIR}
SERVER="$BUILD_DIR/exec/cwfr"
PORT=${ROOT_RATELIMIT_PORT:-18512}
BASE="http://127.0.0.1:$PORT"

if [ ! -x "$SERVER" ]; then
    printf 'root ratelimit: server is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d /tmp/cwfr-root-ratelimit.XXXXXX)
SERVER_PID=
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    cat "$WORK_DIR/server.log" >&2
    exit 1
}

printf 'from root\n' > "$WORK_DIR/index.html"
cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "$WORK_DIR", "gzip": [], "env": {},
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "limited": {
            "domains": ["limited.local"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR", "index": "index.html",
            "ratelimits": {
                "test": { "burst": 2, "rate": 1 },
                "route": { "burst": 2, "rate": 1 },
                "off": { "burst": 2, "rate": 0 }
            },
            "http": {
                "ratelimit": "test",
                "routes": {
                    "/inherited/(.*)": { "GET": { "static_file": "{1}", "cache_control": "public, max-age=60" } },
                    "/own/(.*)": { "GET": { "static_file": "{1}", "ratelimit": "route", "cache_control": "public, max-age=60" } },
                    "/off/(.*)": { "GET": { "static_file": "{1}", "ratelimit": "off" } }
                }
            }
        },
        "route_only": {
            "domains": ["route.local"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR", "index": "index.html",
            "ratelimits": { "test": { "burst": 2, "rate": 1 } },
            "http": {
                "routes": {
                    "/own/(.*)": { "GET": { "static_file": "{1}", "ratelimit": "test" } },
                    "/plain/(.*)": { "GET": { "static_file": "{1}" } }
                }
            }
        },
        "disabled": {
            "domains": ["disabled.local"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR", "index": "index.html",
            "ratelimits": { "test": { "burst": 2, "rate": 0 } },
            "http": { "ratelimit": "test" }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON

"$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!

# Probe the disabled vhost so readiness does not spend limited tokens.
ready=0
for ((attempt = 0; attempt < 100; attempt++)); do
    kill -0 "$SERVER_PID" 2>/dev/null || fail 'server exited during startup'
    if body=$(curl --noproxy '*' -fsS --max-time 1 -H 'Host: disabled.local' \
        "$BASE/index.html" 2>/dev/null) && [ "$body" = 'from root' ]; then
        ready=1
        break
    fi
    sleep 0.1
done
[ "$ready" = 1 ] || fail 'server did not start'

expect() {
    local path=$1 expected=$2 host=${3:-limited.local} code
    code=$(curl --noproxy '*' -sS --max-time 5 -D "$WORK_DIR/headers" \
        -o /dev/null -w '%{http_code}' -H "Host: $host" "$BASE$path") \
        || fail "request failed: $path"
    [ "$code" = "$expected" ] || fail "$host$path: got $code, expected $expected"
    if [ "$expected" = 429 ]; then
        tr -d '\r' < "$WORK_DIR/headers" | grep -qi '^Retry-After: 1$' \
            || fail "$path: missing Retry-After: 1"
        if grep -qi '^Cache-Control:.*max-age=60' "$WORK_DIR/headers"; then
            fail "$path: rate-limit refusal has the route's Cache-Control"
        fi
    fi
}

expect /missing-first 404
expect /inherited/index.html 200
expect /missing-second 429
expect /index.html 429
expect /inherited/missing 429
expect /inherited/index.html 429
# The route's own bucket remains available after the shared bucket is exhausted.
expect /own/missing 404
expect /own/index.html 200
expect /own/missing-again 429
expect /own/index.html 429
expect /off/missing 404
expect /off/index.html 200
# Per-route limits also work without http.ratelimit; unassigned routes stay open.
expect /own/missing 404 route.local
expect /own/index.html 200 route.local
expect /own/missing-again 429 route.local
expect /own/index.html 429 route.local
for ((attempt = 0; attempt < 3; attempt++)); do
    expect /plain/missing 404 route.local
    expect /plain/index.html 200 route.local
done
sleep 1.1
expect /missing-after-refill 404
expect /missing-again 429
for ((attempt = 0; attempt < 3; attempt++)); do
    expect /missing 404 disabled.local
    expect /index.html 200 disabled.local
done
printf 'ok: root statics count missing files; inherited and own limits, refill and rate=0 work\n'
