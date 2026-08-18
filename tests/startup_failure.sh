#!/usr/bin/env bash

# A server that did not start must say so in its exit status.
#
# Two defects, both of which made `cwfr -c config.json && ...` behave as if a
# server that never came up had come up:
#
#   1. a Release build detached with daemon(1, 1) *before* reading the config, so
#      the parent returned 0 while the child parsed it, failed, printed the reason
#      and exited 1 where nobody was looking;
#   2. module_loader_init returns once the worker threads are created, and each
#      worker binds its own sockets afterwards. A bind that failed took the worker
#      down and it asked the others to shut down -- but the main thread was parked
#      in sigwait() and nothing woke it, so the process stayed alive, listened on
#      nothing, and never exited at all.
#
# So both start modes are exercised, and both kinds of failure: one the config
# loader catches, one only a worker can discover. The unbindable address is
# 192.0.2.1 (TEST-NET-1, RFC 5737) rather than a privileged port, because whether
# a low port is privileged depends on net.ipv4.ip_unprivileged_port_start -- on a
# machine where that is 80, binding port 80 as a normal user succeeds and the
# fixture would silently test nothing.
#
# Each case also asserts that no process is left behind. "Exited non-zero" and
# "did not linger" are different claims, and defect 2 was a process that lingered.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/startup_failure.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-startup-failure}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
PORT=${STARTUP_PORT:-18496}

if [ ! -x "$SERVER" ]; then
    printf 'startup failure: server is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf 'started\n' > "$WORK_DIR/www/index.html"

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

# $1 name, $2 listen address, $3 extra env body (may be empty)
write_config() {
    local name=$1 address=$2 env=${3:-}

    cat > "$WORK_DIR/$name.json" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" }
        $env
    },
    "servers": {
        "s1": {
            "domains": ["localhost"], "ip": "$address", "port": $PORT,
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

# Run one config in one start mode and report on the status and on what is left
# running. $1 name, $2 human description, $3... extra server arguments.
expect_failure() {
    local name=$1 what=$2
    shift 2

    local mode='daemonising'
    [ "$#" -eq 0 ] || mode='foreground'

    # timeout, because the defect this replaces was a process that never
    # returned: without it a regression hangs the gate instead of failing it.
    timeout 30 "$SERVER" -c "$WORK_DIR/$name.json" "$@" \
        > "$WORK_DIR/$name.$mode.log" 2>&1
    local status=$?

    if [ "$status" -eq 124 ]; then
        fail "$what ($mode) never returned"
    elif [ "$status" -eq 0 ]; then
        cat "$WORK_DIR/$name.$mode.log" >&2
        fail "$what ($mode) exited 0"
    else
        printf 'ok: %s (%s) exits %d\n' "$what" "$mode" "$status"
    fi

    # A detached child outlives the parent's return, so give it a moment before
    # concluding that nothing was left behind.
    sleep 0.5

    if pgrep -f "cwfr -c $WORK_DIR/$name.json" > /dev/null; then
        pkill -f "cwfr -c $WORK_DIR/$name.json"
        fail "$what ($mode) left a process running"
    else
        printf 'ok: %s (%s) left nothing running\n' "$what" "$mode"
    fi
}

# ---- 1: the config loader refuses the configuration ----
#
# An address that is not an address at all. inet_addr used to report the failure
# as (in_addr_t)-1, which is also a valid 255.255.255.255.

write_config badvalue '10.0.0.300'
expect_failure badvalue 'a malformed listen address'
expect_failure badvalue 'a malformed listen address' -f

# ---- 2: the configuration is valid and a worker cannot bind it ----
#
# This one gets past every check the main thread makes: the address parses, the
# config is complete, the threads start. Only bind(2) knows.

write_config unbindable '192.0.2.1'
expect_failure unbindable 'a listen address that is not on this machine'
expect_failure unbindable 'a listen address that is not on this machine' -f

# ---- 3: and the same configuration on a usable address still starts ----
#
# The control. Without it every check above would also pass on a server that
# refused to start under all circumstances.

write_config good '127.0.0.1'

timeout 30 "$SERVER" -c "$WORK_DIR/good.json" > "$WORK_DIR/good.log" 2>&1
status=$?

if [ "$status" -ne 0 ]; then
    cat "$WORK_DIR/good.log" >&2
    fail "a valid configuration exited $status"
else
    printf 'ok: a valid configuration exits 0\n'
fi

if curl -ksS --max-time 5 --retry 3 --retry-connrefused \
        --resolve "localhost:$PORT:127.0.0.1" "https://localhost:$PORT/" \
        2>/dev/null | grep -q started; then
    printf 'ok: and the detached server is serving by the time it returned\n'
else
    fail "the detached server was not serving when its parent returned"
fi

pkill -f "cwfr -c $WORK_DIR/good.json"

exit "$failed"
