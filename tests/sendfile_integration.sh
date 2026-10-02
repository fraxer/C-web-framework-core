#!/usr/bin/env bash

# Real TCP/TLS sendfile tests and optional Release benchmarks.
# Bash owns fixtures, server lifetime, tracing and wrk. The embedded Python
# wire client preserves exact HTTP framing, pipelining, RST and in-flight inode
# checks that curl cannot express. No production config or binary is changed.

set -euo pipefail

usage() {
    printf 'usage: %s BUILD_DIR [WORK_DIR] [--work-dir DIR] [--trace] [--benchmark] [--repeats N] [--duration SEC]\n' "$0"
}
die() { printf 'sendfile integration: %s\n' "$*" >&2; exit 1; }

BUILD_DIR=
WORK_DIR=
TRACE=0
BENCHMARK=0
REPEATS=3
DURATION=3
while [ "$#" -gt 0 ]; do
    case "$1" in
        --trace) TRACE=1; shift ;;
        --benchmark) BENCHMARK=1; shift ;;
        --work-dir|--repeats|--duration)
            [ "$#" -ge 2 ] || die "missing value for $1"
            case "$1" in
                --work-dir) WORK_DIR=$2 ;;
                --repeats) REPEATS=$2 ;;
                --duration) DURATION=$2 ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; die "unknown option: $1" ;;
        *)
            if [ -z "$BUILD_DIR" ]; then BUILD_DIR=$1
            elif [ -z "$WORK_DIR" ]; then WORK_DIR=$1
            else usage >&2; die "unexpected argument: $1"
            fi
            shift ;;
    esac
done
[ -n "$BUILD_DIR" ] || { usage >&2; exit 2; }
[[ "$REPEATS" =~ ^[1-9][0-9]*$ && "$DURATION" =~ ^[1-9][0-9]*$ ]] \
    || die '--repeats and --duration must be positive integers'
for tool in python3 gcc openssl curl gzip jq setsid; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done
if [ "$TRACE" -eq 1 ]; then command -v strace >/dev/null || die 'missing tool: strace'; fi
if [ "$BENCHMARK" -eq 1 ]; then command -v wrk >/dev/null || die 'missing tool: wrk'; fi
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
[ -x "$SERVER" ] || die "server is missing in $BUILD_DIR"
if [ -z "$WORK_DIR" ]; then WORK_DIR=$(mktemp -d /tmp/cwfr-sendfile-integration-XXXXXX); fi
mkdir -p "$WORK_DIR/www"
WORK_DIR=$(cd "$WORK_DIR" && pwd)

SERVER_PID=
LOAD_PID=
stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill -TERM -- "-$SERVER_PID" 2>/dev/null || true
        for ((attempt=0; attempt<100; attempt++)); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
}
cleanup() {
    if [ -n "$LOAD_PID" ]; then
        kill -TERM -- "-$LOAD_PID" 2>/dev/null || true
        wait "$LOAD_PID" 2>/dev/null || true
    fi
    stop_server
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Keep the original fixtures so earlier Release measurements remain comparable.
for ((byte=0; byte<256; byte++)); do
    printf -v octal '\\%03o' "$byte"
    printf '%b' "$octal"
done > "$WORK_DIR/pattern.bin"
# Double the 256-byte pattern sixteen times to produce the original 16 MiB file.
for ((step=0; step<16; step++)); do
    cat "$WORK_DIR/pattern.bin" "$WORK_DIR/pattern.bin" > "$WORK_DIR/pattern.next.bin"
    mv "$WORK_DIR/pattern.next.bin" "$WORK_DIR/pattern.bin"
done
mv "$WORK_DIR/pattern.bin" "$WORK_DIR/www/large.bin"
printf '%1024s' '' | tr ' ' s > "$WORK_DIR/www/small.txt"
for filename in dynamic.txt compressed.txt; do
    awk 'BEGIN {for (i=0; i<16384; i++) print "compressible text"}' > "$WORK_DIR/www/$filename"
done
gzip -nc "$WORK_DIR/www/compressed.txt" > "$WORK_DIR/www/compressed.txt.gz"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$WORK_DIR/key.pem" -out "$WORK_DIR/cert.pem" > "$WORK_DIR/openssl.log" 2>&1
cat > "$WORK_DIR/buffered.c" <<'C'
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
ssize_t sendfile(int out, int in, off_t* offset, size_t count) {
    (void)out; (void)in; (void)offset; (void)count;
    errno = ENOSYS;
    return -1;
}
C
gcc -shared -fPIC "$WORK_DIR/buffered.c" -o "$WORK_DIR/buffered.so"
jq -n --arg build "$BUILD_DIR" --arg work "$WORK_DIR" \
    '{build_dir:$build, work_dir:$work, functional:[], benchmarks:{}}' > "$WORK_DIR/results.json"

start_server() {
    local scheme=$1 buffered=$2 trace=$3 tls='null'
    LABEL="$scheme-sendfile"
    [ "$buffered" -eq 0 ] || LABEL="$scheme-buffered"
    PORT=$(python3 - <<'PY_PORT'
import socket
with socket.socket() as reserve:
    reserve.bind(('127.0.0.1', 0))
    print(reserve.getsockname()[1])
PY_PORT
)
    if [ "$scheme" = https ]; then
        tls=$(jq -n --arg work "$WORK_DIR" '{
            fullchain:($work+"/cert.pem"), private:($work+"/key.pem"),
            ciphers:"TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
        }')
    fi
    jq -n --arg work "$WORK_DIR" --argjson port "$PORT" --argjson tls "$tls" '{
        main:{workers:1, threads:2, reload:"hard", buffer_size:16384,
              client_max_body_size:1048576, tmp:$work, gzip:["text/plain"],
              env:{gzip_static:true, http2_shutdown_grace_sec:1},
              log:{enabled:true, level:"error"}},
        servers:{s1:({domains:["localhost","127.0.0.1"], ip:"127.0.0.1", port:$port,
                      root:($work+"/www"), index:"small.txt"} +
                     if $tls == null then {} else {tls:$tls} end)},
        mimetypes:{"text/plain":["txt"], "application/octet-stream":["bin"]}
    }' > "$WORK_DIR/$LABEL.json"
    local -a command=("$SERVER" -c "$WORK_DIR/$LABEL.json" -f)
    if [ "$trace" -eq 1 ]; then
        command=(strace -f -o "$WORK_DIR/$LABEL.strace" -e "trace=sendfile,pread64,sendto" "${command[@]}")
    fi
    if [ "$buffered" -eq 1 ]; then command=(env "LD_PRELOAD=$WORK_DIR/buffered.so" "${command[@]}"); fi
    setsid "${command[@]}" > "$WORK_DIR/$LABEL.log" 2>&1 &
    SERVER_PID=$!
    local code
    for ((attempt=0; attempt<100; attempt++)); do
        kill -0 "$SERVER_PID" 2>/dev/null || die "server startup failed; see $WORK_DIR/$LABEL.log"
        code=$(curl --noproxy '*' -ksS --http1.1 --max-time 1 -o /dev/null -w '%{http_code}' \
            "$scheme://127.0.0.1:$PORT/small.txt" 2>/dev/null) || code=000
        [ "$code" != 200 ] || return 0
        sleep 0.05
    done
    die "server readiness timeout; see $WORK_DIR/$LABEL.log"
}

functional() {
    python3 - "$PORT" "$WORK_DIR" "$1" <<'PY_CLIENT'
import email.parser
from pathlib import Path
import socket
import ssl
import sys
import time

def check(condition, message):
    if not condition:
        raise AssertionError(message)


def exact(stream, size):
    chunks = []
    while size:
        data = stream.read(min(size, 65536))
        check(data, "premature EOF")
        chunks.append(data)
        size -= len(data)
    return b"".join(chunks)


def head(stream):
    line = stream.readline()
    check(line.startswith(b"HTTP/1.1 "), f"invalid status: {line!r}")
    status = int(line.split()[1])
    headers = {}
    while True:
        line = stream.readline()
        if line == b"\r\n":
            return status, headers
        check(line, "EOF inside headers")
        key, value = line.decode("latin1").split(":", 1)
        check(key.lower() not in headers, f"duplicate header: {key}")
        headers[key.lower()] = value.strip()


def body(stream, headers, method="GET", status=200):
    if method == "HEAD" or status in (204, 304):
        return b""
    if headers.get("transfer-encoding") == "chunked":
        check("content-length" not in headers, "chunked with Content-Length")
        chunks = []
        while True:
            size = int(stream.readline().split(b";", 1)[0], 16)
            if not size:
                check(stream.readline() == b"\r\n", "invalid final chunk")
                return b"".join(chunks)
            chunks.append(exact(stream, size))
            check(exact(stream, 2) == b"\r\n", "invalid chunk delimiter")
    return exact(stream, int(headers["content-length"]))


def connection(port, tls=False):
    sock = socket.create_connection(("127.0.0.1", port), timeout=15)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # generated local fixture only
        ctx.set_alpn_protocols(["http/1.1"])
        sock = ctx.wrap_socket(sock, server_hostname="localhost")
    return sock


def request_bytes(path, method="GET", headers=None, close=False):
    fields = {"Host": "localhost", "Connection": "close" if close else "keep-alive"}
    fields.update(headers or {})
    return (f"{method} {path} HTTP/1.1\r\n" +
            "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n").encode()


def fetch(port, path, tls=False, method="GET", headers=None):
    with connection(port, tls) as sock, sock.makefile("rb") as stream:
        sock.sendall(request_bytes(path, method, headers, close=True))
        status, fields = head(stream)
        data = body(stream, fields, method, status)
        return status, fields, data


def multipart(fields, data, source, spans):
    check(int(fields["content-length"]) == len(data), "multipart Content-Length")
    message = email.parser.BytesParser().parsebytes(
        f'Content-Type: {fields["content-type"]}\r\nMIME-Version: 1.0\r\n\r\n'.encode() + data)
    check(message.is_multipart(), "multipart Content-Type")
    parts = message.get_payload()
    check(len(parts) == len(spans), "multipart part count")
    for part, (start, end) in zip(parts, spans):
        check(part["Content-Range"] == f"bytes {start}-{end}/{len(source)}", "part Content-Range")
        check(part.get_payload(decode=True) == source[start:end + 1], "part bytes/order")
    boundary = message.get_boundary().encode()
    check(data.endswith(b"\r\n--" + boundary + b"--\r\n"), "closing boundary")


def functional(port, work, source, tls):
    count = 0
    def get(path="/large.bin", method="GET", headers=None):
        nonlocal count
        count += 1
        return fetch(port, path, tls, method, headers)
    status, fields, data = get()
    check(status == 200 and data == source, "whole file")
    check(int(fields["content-length"]) == len(source), "whole length")
    for specification, start, end in [("777-1049000", 777, 1049000), ("1000-", 1000, len(source)-1),
                                       ("-97", len(source)-97, len(source)-1)]:
        status, fields, data = get(headers={"Range": "bytes=" + specification})
        check(status == 206 and data == source[start:end+1], "single range")
        check(fields["content-range"] == f"bytes {start}-{end}/{len(source)}", "single Content-Range")
    spans = [(0, 31), (777, 1049000), (1049100, 1049150)]
    range_value = "bytes=" + ",".join(f"{a}-{b}" for a,b in spans)
    status, fields, data = get(headers={"Range": range_value})
    check(status == 206, f"multipart status: {status}, {fields}, {data[:100]!r}")
    multipart(fields, data, source, spans)
    # The existing wire parser ignores ranges in descending order, before the
    # response filter can select sendfile. Record its current full-200 behavior.
    status, _, data = get(headers={"Range": "bytes=777-1049000,0-31"})
    check(status == 200 and data == source, "descending ranges ignored by wire parser")
    for headers in ({}, {"Range": "bytes=777-1049000"}, {"Range": range_value}):
        status, fields, data = get(method="HEAD", headers=headers)
        check(status in (200, 206) and not data and int(fields["content-length"]) > 0, "HEAD")
    status, fields, data = get(headers={"Range": f"bytes={len(source)}-"})
    check(status == 416 and not data and fields["content-range"] == f"bytes */{len(source)}", "416")
    status, _, data = get(headers={"Range": range_value, "If-Range": '"outdated"'})
    check(status == 200 and data == source, "If-Range full representation")
    status, _, data = get(headers={"If-None-Match": fields.get("etag", "")})
    check(status == 304 and not data, "conditional 304")
    import gzip
    for path in ("/dynamic.txt", "/compressed.txt"):
        status, fields, data = get(path, headers={"Accept-Encoding": "gzip"})
        check(status == 200 and fields["content-encoding"] == "gzip", "gzip response")
        check(gzip.decompress(data) == (work / "www" / path[1:]).read_bytes(), "gzip bytes")
    # Three requests already queued on a single TCP/TLS connection.
    with connection(port, tls) as sock, sock.makefile("rb") as stream:
        sock.sendall(request_bytes("/large.bin", headers={"Range": range_value}) +
                     request_bytes("/large.bin", headers={"Range": "bytes=2-5"}) +
                     request_bytes("/small.txt", close=True))
        status, fields = head(stream)
        check(status == 206, "pipeline multipart status")
        multipart(fields, body(stream, fields), source, spans)
        status, fields = head(stream)
        check(status == 206 and body(stream, fields) == source[2:6], "pipeline second range")
        status, fields = head(stream)
        check(status == 200 and body(stream, fields) == (work / "www/small.txt").read_bytes(), "pipeline third answer")
    count += 3
    # Slow consumer keeps a large response outstanding while small ones progress.
    with connection(port, tls) as slow, slow.makefile("rb") as stream:
        slow.sendall(request_bytes("/large.bin"))
        _, fields = head(stream)
        first = exact(stream, 1024)
        time.sleep(.15)
        status, _, small = get("/small.txt")
        check(status == 200 and len(small) == 1024, "small request while slow client waits")
        check(first + body(stream, {"content-length": str(len(source)-1024)}) == source, "slow client's bytes")
    count += 1
    # TCP RST interrupts a file response; the next request must still work.
    import struct
    with connection(port, tls) as sock:
        sock.sendall(request_bytes("/large.bin"))
        check(sock.recv(1024), "response began before disconnect")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    check(get("/small.txt")[0] == 200, "server survives reset")
    count += 1
    # Atomic replacement leaves an in-flight descriptor on the original inode.
    mutable = work / "www/mutable.bin"
    mutable.write_bytes(source)
    replacement = b"Z" * len(source)
    with connection(port, tls) as sock, sock.makefile("rb") as stream:
        sock.sendall(request_bytes("/mutable.bin"))
        status, fields = head(stream)
        first = exact(stream, 1024)
        staging = work / "www/replacement.bin"
        staging.write_bytes(replacement)
        staging.replace(mutable)
        check(status == 200 and first + body(stream, {"content-length": str(len(source)-1024)}) == source,
              "in-flight atomic replacement preserves original bytes")
    check(get("/mutable.bin")[2] == replacement, "new request sees replacement")
    return count + 1


port = int(sys.argv[1])
work = Path(sys.argv[2])
source = (work / "www/large.bin").read_bytes()
print(functional(port, work, source, sys.argv[3] == "https"))
PY_CLIENT
}

cpu_seconds() {
    # The fields after comm start at field 3; utime/stime are fields 14/15.
    awk -v ticks="$(getconf CLK_TCK)" '{sub(/^.*\) /, ""); printf "%.9f\n", ($12+$13)/ticks}' \
        "/proc/$SERVER_PID/stat"
}

benchmark() {
    local path concurrency repeat before_cpu before_time after_cpu after_time output row
    local requests transferred p99 connect read_errors write_errors status_errors timeouts
    local elapsed cpu
    local -a report
    printf '[]\n' > "$WORK_DIR/benchmark.json"
    cat > "$WORK_DIR/stats.lua" <<'LUA'
done = function(summary, latency, requests)
    print(string.format("REPORT %d %d %.0f %d %d %d %d %d", summary.requests,
        summary.bytes, latency:percentile(99), summary.errors.connect,
        summary.errors.read, summary.errors.write, summary.errors.status, summary.errors.timeout))
end
LUA
    for path in /small.txt /large.bin; do
        concurrency=16
        [ "$path" != /large.bin ] || concurrency=8
        for ((repeat=1; repeat<=REPEATS; repeat++)); do
            output="$WORK_DIR/$LABEL-$(basename "$path")-$repeat.wrk"
            before_cpu=$(cpu_seconds)
            before_time=$(date +%s%N)
            setsid wrk -t2 "-c$concurrency" "-d${DURATION}s" --latency -s "$WORK_DIR/stats.lua" \
                "http://127.0.0.1:$PORT$path" > "$output" 2>&1 &
            LOAD_PID=$!
            if [ "$path" = /large.bin ]; then
                python3 - "$PORT" "$WORK_DIR" "$LOAD_PID" <<'PY_PROBE'
import http.client
import json
from pathlib import Path
import sys
import time
port, work = int(sys.argv[1]), Path(sys.argv[2])
load_stat = Path(f'/proc/{int(sys.argv[3])}/stat')
def running():
    try:
        return load_stat.read_text().rsplit(')', 1)[1].split()[0] not in ('Z', 'X')
    except FileNotFoundError:
        return False
client = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
latency = []
try:
    while running():
        start = time.monotonic()
        client.request('GET', '/small.txt', headers={'Host':'localhost'})
        response = client.getresponse()
        if response.status != 200 or len(response.read()) != 1024:
            raise AssertionError('mixed probe')
        latency.append((time.monotonic()-start)*1000)
        time.sleep(.01)
finally:
    client.close()
latency.sort()
if not latency:
    raise AssertionError('no mixed probe samples')
(work / 'probe.json').write_text(json.dumps({
    'small_probe_p99_ms':round(latency[min(len(latency)-1, int(len(latency)*.99))], 3),
    'small_probe_samples':len(latency)}))
PY_PROBE
            fi
            if ! wait "$LOAD_PID"; then LOAD_PID=; die "wrk failed; see $output"; fi
            LOAD_PID=
            after_time=$(date +%s%N)
            after_cpu=$(cpu_seconds)
            elapsed=$(awk -v a="$before_time" -v b="$after_time" 'BEGIN {printf "%.9f", (b-a)/1e9}')
            cpu=$(awk -v a="$before_cpu" -v b="$after_cpu" 'BEGIN {printf "%.9f", b-a}')
            mapfile -t report < <(sed -n 's/^REPORT //p' "$output")
            [ "${#report[@]}" -eq 1 ] || die "missing wrk summary; see $output"
            read -r requests transferred p99 connect read_errors write_errors status_errors timeouts <<< "${report[0]}"
            [ "$requests" -gt 0 ] && [ "$((connect+read_errors+write_errors+status_errors+timeouts))" -eq 0 ] \
                || die "wrk errors; see $output"
            row=$(jq -n --arg path "$path" --argjson requests "$requests" --argjson bytes "$transferred" \
                --argjson p99 "$p99" --argjson elapsed "$elapsed" --argjson cpu "$cpu" '{
                    path:$path, requests_per_sec:(($requests/$elapsed*10|round)/10),
                    MiB_per_sec:(($bytes/$elapsed/1048576*10|round)/10),
                    server_cpu_sec:(($cpu*1000|round)/1000), response_p99_ms:($p99/1000)
                }')
            if [ "$path" = /large.bin ]; then
                row=$(jq -n --argjson row "$row" --slurpfile probe "$WORK_DIR/probe.json" '$row + $probe[0]')
            fi
            jq --argjson row "$row" '. + [$row]' "$WORK_DIR/benchmark.json" > "$WORK_DIR/benchmark.next.json"
            mv "$WORK_DIR/benchmark.next.json" "$WORK_DIR/benchmark.json"
        done
    done
}

for mode in http-sendfile https-sendfile http-buffered; do
    scheme=${mode%%-*}
    buffered=0
    [ "$mode" != http-buffered ] || buffered=1
    start_server "$scheme" "$buffered" "$TRACE"
    count=$(functional "$scheme")
    stop_server
    row=$(jq -n --arg scheme "$scheme" --argjson buffered "$buffered" --argjson count "$count" \
        '{scheme:$scheme, buffered:($buffered==1), scenarios:$count, passed:true}')
    if [ "$TRACE" -eq 1 ]; then
        sendfile_calls=$(awk '/sendfile\(/ {n++} END {print n+0}' "$WORK_DIR/$LABEL.strace")
        pread_calls=$(awk '/pread64\(/ {n++} END {print n+0}' "$WORK_DIR/$LABEL.strace")
        if [ "$scheme" = https ]; then
            [ "$sendfile_calls" -eq 0 ] && [ "$pread_calls" -gt 0 ] || die 'TLS must use buffered path'
        elif [ "$buffered" -eq 0 ]; then
            [ "$sendfile_calls" -gt 0 ] || die 'TCP must use sendfile'
        fi
        row=$(jq --argjson sendfile "$sendfile_calls" --argjson pread "$pread_calls" \
            '. + {sendfile_calls:$sendfile, pread_calls:$pread}' <<< "$row")
    fi
    jq --argjson row "$row" '.functional += [$row]' "$WORK_DIR/results.json" > "$WORK_DIR/results.next.json"
    mv "$WORK_DIR/results.next.json" "$WORK_DIR/results.json"
    jq -c . <<< "$row"
done
if [ "$BENCHMARK" -eq 1 ]; then
    for buffered in 0 1; do
        start_server http "$buffered" 0
        benchmark
        stop_server
        label=sendfile
        [ "$buffered" -eq 0 ] || label=buffered
        jq --arg label "$label" --slurpfile rows "$WORK_DIR/benchmark.json" \
            '.benchmarks[$label] = $rows[0]' "$WORK_DIR/results.json" > "$WORK_DIR/results.next.json"
        mv "$WORK_DIR/results.next.json" "$WORK_DIR/results.json"
        printf '%s ' "$label"
        jq -c . "$WORK_DIR/benchmark.json"
    done
fi
printf 'PASS; results: %s/results.json\n' "$WORK_DIR"
