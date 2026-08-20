#!/usr/bin/env bash

# Repeatable HTTP/3 performance regression check against a runner-local baseline.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/h3_benchmark.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-h3-benchmark}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
CLIENT="$BUILD_DIR/exec/quicclient"
H2LOAD=${H2LOAD_H3:-}
if [ -z "$H2LOAD" ] && [ -x /opt/nghttp2-http3/bin/h2load ]; then
    H2LOAD=/opt/nghttp2-http3/bin/h2load
fi
if [ -z "$H2LOAD" ]; then
    H2LOAD=$(command -v h2load || true)
fi
PORT=${H3_BENCH_PORT:-18461}
RUNS=${BENCH_RUNS:-5}
BASELINE=${BENCH_BASELINE:-}
RECORD=${BENCH_RECORD:-}
REQUIRE=${REQUIRE_BENCHMARK:-0}
MAX_REGRESSION=${BENCH_MAX_REGRESSION_PERCENT:-5}

# The representative profile can have c*m = 3000 static responses in flight,
# each with its own descriptor. A runner's common 1024 soft limit benchmarks
# EMFILE handling (and used to manufacture fast 404s), not HTTP/3 throughput.
if [ "$(ulimit -n)" -lt 8192 ] && ! ulimit -n 8192; then
    printf 'h3 benchmark: need RLIMIT_NOFILE >= 8192 for the c=100 profile\n' >&2
    [ "$REQUIRE" = 1 ] && exit 1 || exit 77
fi

if [ ! -x "$SERVER" ] || [ ! -x "$CLIENT" ]; then
    printf 'h3 benchmark: server or quicclient unavailable\n' >&2
    [ "$REQUIRE" = 1 ] && exit 1 || exit 77
fi
if [ "$RUNS" -lt 3 ] || [ $((RUNS % 2)) -eq 0 ]; then
    printf 'h3 benchmark: BENCH_RUNS must be an odd number >= 3\n' >&2
    exit 2
fi

mkdir -p "$WORK_DIR/www"
printf 'benchmark\n' > "$WORK_DIR/www/small.txt"
dd if=/dev/zero of="$WORK_DIR/www/representative.bin" bs=57074 count=1 status=none
dd if=/dev/zero of="$WORK_DIR/www/large.bin" bs=1M count=64 status=none

cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 2, "threads": 2, "reload": "soft",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": [],
        "log": { "enabled": true, "level": "error" },
        "env": {
            "metrics": true,
            "http3_buffer_memory_limit": 134217728,
            "http3_handshake_rate": 0,
            "http3_max_streams_bidi": 1000,
            "http3_so_rcvbuf": 4194304
        }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/www", "index": "small.txt",
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
        "text/plain": ["txt"],
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
    if "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /small.txt \
            --timeout 2000 > "$WORK_DIR/warmup.log" 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    printf 'h3 benchmark: server did not become ready\n' >&2
    exit 1
fi

# What the kernel dropped into a *receiving* socket for want of room. It is a
# host-wide counter, so it does not name the socket -- but on a loopback
# benchmark, with the server given its own 4 MB receive buffer, the one that
# overflows is h2load's: a single-process client at 90 % of a core stops
# draining for a few milliseconds and 208 KB of default buffer (about 140
# datagrams) is gone. The server then retransmits, and every number in the run
# describes loss recovery instead of throughput (docs/http3/08 §16a).
udp_rcvbuf_errors() {
    sed -n '/^Udp:/{n;p}' /proc/net/snmp | head -1 | awk '{ print $6 }'
}

median() {
    sort -n "$1" | awk '{ v[NR]=$1 } END { if (NR) print v[(NR+1)/2] }'
}

: > "$WORK_DIR/short.values"
: > "$WORK_DIR/representative.values"
: > "$WORK_DIR/throughput.values"
: > "$WORK_DIR/gso.values"

short_mode=quicclient
if [ -n "$H2LOAD" ] && [ -x "$H2LOAD" ] &&
   "$H2LOAD" --alpn-list=h3 --connect-to="127.0.0.1:$PORT" --sni=localhost \
        -n 100 -c 10 -m 10 "https://localhost:$PORT/small.txt" \
        > "$WORK_DIR/h2load-probe.log" 2>&1 &&
   grep -Eq 'requests: 100 total, 100 started, 100 done, 100 succeeded' \
        "$WORK_DIR/h2load-probe.log"; then
    short_mode=h2load
else
    printf 'h3 benchmark: h2load has no usable h3; using multiplexed quicclient\n'
fi

# Bring CPU frequency, OpenSSL and filesystem page cache to the same state in
# which samples run. A single readiness request left the first fallback sample
# 2–3x below the following invocation on an ondemand CPU governor.
if [ "$short_mode" = quicclient ]; then
    for _ in $(seq 1 20); do
        "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /small.txt -n 50 \
            --timeout 15000 > /dev/null 2>&1 || exit 1
    done
fi
"$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /large.bin --timeout 30000 \
    > /dev/null 2>&1 || exit 1

for i in $(seq 1 "$RUNS"); do
    short_log="$WORK_DIR/short-$i.log"
    if [ "$short_mode" = h2load ]; then
        if ! "$H2LOAD" --alpn-list=h3 --connect-to="127.0.0.1:$PORT" \
                --sni=localhost -n 20000 -c 10 -m 30 \
                "https://localhost:$PORT/small.txt" > "$short_log" 2>&1 ||
           ! grep -Eq 'requests: 20000 total, 20000 started, 20000 done, 20000 succeeded' \
                "$short_log"; then
            printf 'h3 benchmark: h2load did not complete every request\n' >&2
            exit 1
        fi
        value=$(sed -n 's/.*finished in.*, \([0-9][0-9.]*\) req\/s.*/\1/p' \
            "$short_log" | tail -1)
    else
        start_ns=$(date +%s%N)
        : > "$short_log"
        for _ in $(seq 1 20); do
            if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /small.txt \
                    -n 50 --timeout 15000 >> "$short_log" 2>&1; then
                printf 'h3 benchmark: quicclient short run failed\n' >&2
                exit 1
            fi
        done
        elapsed_ns=$(( $(date +%s%N) - start_ns ))
        value=$(awk -v ns="$elapsed_ns" 'BEGIN { if (ns > 0) printf "%.2f", 1000000000000/ns }')
    fi
    if [ -z "$value" ]; then
        printf 'h3 benchmark: could not parse req/s from h2load\n' >&2
        [ "$REQUIRE" = 1 ] && exit 1 || exit 77
    fi
    printf '%s\n' "$value" >> "$WORK_DIR/short.values"

    if [ "$short_mode" = h2load ]; then
        representative_log="$WORK_DIR/representative-$i.log"
        representative_requests="$WORK_DIR/representative-$i.tsv"
        curl -fsk --resolve "localhost:$PORT:127.0.0.1" \
            "https://localhost:$PORT/metrics?reset=1" > /dev/null || exit 1
        rcvbuf_before=$(udp_rcvbuf_errors)
        if ! "$H2LOAD" --alpn-list=h3 --connect-to="127.0.0.1:$PORT" \
                --sni=localhost --log-file="$representative_requests" \
                -n 10000 -c 100 -m 30 \
                "https://localhost:$PORT/representative.bin" \
                > "$representative_log" 2>&1 ||
           ! grep -Eq 'requests: 10000 total, 10000 started, 10000 done, 10000 succeeded' \
                "$representative_log" ||
           ! grep -Eq 'status codes: 10000 2xx, 0 3xx, 0 4xx, 0 5xx' \
                "$representative_log"; then
            printf 'h3 benchmark: representative c=100 run did not complete every request as 2xx\n' >&2
            exit 1
        fi
        value=$(sed -n 's/.*finished in.*, \([0-9][0-9.]*\) req\/s.*/\1/p' \
            "$representative_log" | tail -1)
        if [ -z "$value" ]; then
            printf 'h3 benchmark: could not parse representative req/s\n' >&2
            exit 1
        fi
        printf '%s\n' "$value" >> "$WORK_DIR/representative.values"

        rcvbuf_after=$(udp_rcvbuf_errors)
        printf '%s %s\n' rcvbuf_errors \
            "$(( ${rcvbuf_after:-0} - ${rcvbuf_before:-0} ))" >> "$WORK_DIR/gso.values"

        metrics_log="$WORK_DIR/representative-$i-metrics.json"
        curl -fsk --resolve "localhost:$PORT:127.0.0.1" \
            "https://localhost:$PORT/metrics" > "$metrics_log" || exit 1
        for key in datagrams_sent send.batch_calls send.messages \
                   send.gso_messages send.gso_segments send.gso_fallbacks \
                   send.partial packets_lost; do
            metric=$(sed -n "s/.*\"$key\":[[:space:]]*\([0-9][0-9]*\).*/\1/p" \
                "$metrics_log")
            if [ -z "$metric" ]; then
                printf 'h3 benchmark: missing quic.%s in metrics snapshot\n' "$key" >&2
                exit 1
            fi
            printf '%s %s\n' "$key" "$metric" >> "$WORK_DIR/gso.values"
        done
    fi

    throughput_log="$WORK_DIR/throughput-$i.log"
    if ! "$CLIENT" 127.0.0.1 "$PORT" -q -a localhost -p /large.bin \
            --timeout 30000 > "$throughput_log" 2>&1; then
        printf 'h3 benchmark: throughput run failed\n' >&2
        exit 1
    fi
    value=$(sed -n 's/.*(\([0-9][0-9.]*\) MB\/s).*/\1/p' \
        "$throughput_log" | tail -1)
    if [ -z "$value" ]; then
        printf 'h3 benchmark: could not parse throughput\n' >&2
        exit 1
    fi
    printf '%s\n' "$value" >> "$WORK_DIR/throughput.values"
done

short_median=$(median "$WORK_DIR/short.values")
representative_median=0
if [ "$short_mode" = h2load ]; then
    representative_median=$(median "$WORK_DIR/representative.values")
fi
throughput_median=$(median "$WORK_DIR/throughput.values")
printf 'h3 benchmark: median short=%s req/s representative=%s req/s throughput=%s MB/s (%s runs)\n' \
    "$short_median" "$representative_median" "$throughput_median" "$RUNS"
if [ "$short_mode" = h2load ]; then
    metric_sum() { awk -v key="$1" '$1 == key { n += $2 } END { print n + 0 }' "$WORK_DIR/gso.values"; }
    dgrams=$(metric_sum datagrams_sent)
    calls=$(metric_sum send.batch_calls)
    messages=$(metric_sum send.messages)
    gso_messages=$(metric_sum send.gso_messages)
    gso_segments=$(metric_sum send.gso_segments)
    fallbacks=$(metric_sum send.gso_fallbacks)
    partial=$(metric_sum send.partial)
    lost=$(metric_sum packets_lost)
    rcvbuf=$(metric_sum rcvbuf_errors)
    awk -v d="$dgrams" -v c="$calls" -v m="$messages" -v gm="$gso_messages" \
        -v gs="$gso_segments" -v f="$fallbacks" -v p="$partial" \
        'BEGIN { printf "h3 benchmark: tx datagrams=%d batch_calls=%d messages=%d avg_batch=%.2f gso_messages=%d gso_segments=%d avg_gso=%.2f fallbacks=%d partial=%d\n", d, c, m, c ? d/c : 0, gm, gs, gm ? gs/gm : 0, f, p }'
    awk -v l="$lost" -v d="$dgrams" -v r="$rcvbuf" \
        'BEGIN { printf "h3 benchmark: loss declared=%d (%.3f%% of datagrams) client rcvbuf_errors=%d\n", l, d ? 100*l/d : 0, r }'
    # Said out loud rather than folded into a threshold: a loopback path drops
    # nothing on its own, so this is the stand's own client falling behind, and
    # the sample above measures loss recovery. The counter is host-wide, so it
    # is a warning and not a failure -- unrelated UDP traffic lands in it too.
    if [ "$rcvbuf" -gt 0 ]; then
        printf 'h3 benchmark: WARNING the client dropped datagrams for want of socket buffer;\n'
        printf '              this sample measures loss recovery (docs/http3/08 §16a).\n'
        printf '              Give the client more processes or raise net.core.rmem_default.\n'
    fi
fi

if [ -n "$RECORD" ]; then
    mkdir -p "$(dirname "$RECORD")"
    printf '{"short_rps":%s,"representative_rps":%s,"throughput_mbps":%s,"runs":%s,"short_client":"%s"}\n' \
        "$short_median" "$representative_median" "$throughput_median" "$RUNS" "$short_mode" > "$RECORD"
    printf 'h3 benchmark: baseline recorded in %s\n' "$RECORD"
fi

if [ -z "$BASELINE" ] || [ ! -r "$BASELINE" ]; then
    printf 'h3 benchmark: no readable BENCH_BASELINE; comparison skipped\n'
    [ -n "$RECORD" ] && exit 0
    [ "$REQUIRE" = 1 ] && exit 1 || exit 77
fi

baseline_short=$(sed -n 's/.*"short_rps"[[:space:]]*:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' "$BASELINE")
baseline_representative=$(sed -n 's/.*"representative_rps"[[:space:]]*:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' "$BASELINE")
baseline_throughput=$(sed -n 's/.*"throughput_mbps"[[:space:]]*:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' "$BASELINE")
baseline_client=$(sed -n 's/.*"short_client"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BASELINE")
if [ -z "$baseline_short" ] || [ -z "$baseline_representative" ] ||
   [ -z "$baseline_throughput" ] ||
   [ "$baseline_client" != "$short_mode" ]; then
        printf 'h3 benchmark: malformed or method-incompatible baseline %s\n' "$BASELINE" >&2
    exit 1
fi

regressed=0
awk -v a="$short_median" -v b="$baseline_short" -v p="$MAX_REGRESSION" \
    'BEGIN { exit !(a < b * (100-p) / 100) }' && regressed=1
awk -v a="$representative_median" -v b="$baseline_representative" -v p="$MAX_REGRESSION" \
    'BEGIN { exit !(a < b * (100-p) / 100) }' && regressed=1
awk -v a="$throughput_median" -v b="$baseline_throughput" -v p="$MAX_REGRESSION" \
    'BEGIN { exit !(a < b * (100-p) / 100) }' && regressed=1

if [ "$regressed" -ne 0 ]; then
    printf 'h3 benchmark: regression exceeds %s%% (baseline short=%s representative=%s req/s, %s MB/s)\n' \
        "$MAX_REGRESSION" "$baseline_short" "$baseline_representative" "$baseline_throughput" >&2
    exit 1
fi

printf 'h3 benchmark: within %s%% of baseline (short=%s representative=%s req/s, %s MB/s)\n' \
    "$MAX_REGRESSION" "$baseline_short" "$baseline_representative" "$baseline_throughput"
