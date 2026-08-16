#!/usr/bin/env bash
#
# The gate of docs/http3/08-testing.md §8, as a script.
#
# There is no CI configuration in this repository, so "add it to CI" would have
# meant picking a CI. This runs the same list from anywhere -- a laptop, a hook,
# a runner -- and says plainly which stage failed. A CI job then reduces to
# calling it.
#
# Stages, in the order §8 lists them:
#
#   noh3     build with -DINCLUDE_HTTP3=no  + unit tests   (h3 broke nothing)
#   asan     build with h3, ASan            + unit tests
#   tsan     build with h3, TSan            + unit tests   (data races)
#   h3unit   QUIC / HTTP/3 / QPACK unit runner only
#   config   invalid HTTP/3 types/ranges reject startup
#   limits   process connection/memory exhaustion and drain
#   soak     sustained requests, impairment, migration and RSS drain
#   affinity a migrated connection follows its datagrams to the new worker
#   benchmark median req/s and throughput against a runner-local baseline
#   fuzz     build the fuzz targets         + FUZZ_SECONDS each
#   reload   hard reload with live QUIC      + old worker retirement
#   softreload shared UDP handoff             + old CID/config drain
#   h3spec   run a server, run h3spec against it           (RFC conformance)
#
# The interop matrix (§8.6) is deliberately absent: it needs docker and tens of
# minutes, and belongs to a schedule rather than to a gate.
#
# Usage:
#   tests/ci.sh                  # every stage
#   tests/ci.sh release          # every stage; h3spec must be installed
#   tests/ci.sh asan tsan        # a subset, in the order given
#   FUZZ_SECONDS=600 tests/ci.sh fuzz
#   CI_BUILD_DIR=/var/tmp/ci tests/ci.sh
#
# Environment:
#   CI_BUILD_DIR   where build trees go (default: a temp dir, kept between runs)
#   FUZZ_SECONDS   per fuzz target (default 60; §5 asks for 24h on a schedule)
#   H3SPEC         path to the h3spec binary (default: found on PATH)
#   REQUIRE_H3SPEC fail instead of skip when h3spec is unavailable (default 0)
#   SOAK_REQUESTS requests in the soak stage (default 1000; release 10000)
#   SOAK_RSS_GROWTH_KB allowed post-warmup RSS growth (default 16384)
#   BENCH_BASELINE benchmark JSON produced with BENCH_RECORD
#   REQUIRE_BENCHMARK fail instead of skip without a usable baseline
#   JOBS           parallel build jobs (default: nproc)

set -u -o pipefail

CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BACKEND_DIR=$(cd "$CORE_DIR/.." && pwd)

CI_BUILD_DIR=${CI_BUILD_DIR:-/tmp/cwfr-ci}
FUZZ_SECONDS=${FUZZ_SECONDS:-10}
JOBS=${JOBS:-$(nproc)}
H3SPEC=${H3SPEC:-$(command -v h3spec || true)}
REQUIRE_H3SPEC=${REQUIRE_H3SPEC:-0}

# Databases are off in every stage: the gate must run on a machine with none,
# and the database tests are a separate binary with their own requirements.
COMMON_CMAKE=(
    -DINCLUDE_POSTGRESQL=no -DINCLUDE_MYSQL=no
    -DINCLUDE_REDIS=no -DINCLUDE_SQLITE=no
)

# The fake stack turns an idle sanitised server into an apparent 4.5 KB/s leak
# (core/INSTALL.md), and every stage here either runs a server or a fuzzer.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_stack_use_after_return=0}"

mkdir -p "$CI_BUILD_DIR"

STAGES_RUN=()
STAGES_RESULT=()
FAILED=0

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }

record() {
    STAGES_RUN+=("$1")
    STAGES_RESULT+=("$2")
    [ "$2" = FAIL ] && FAILED=1
    return 0
}

# Configure + build one tree. Extra cmake arguments come after the directory.
build() {
    local dir=$1; shift
    local log="$CI_BUILD_DIR/$(basename "$dir").log"

    cmake -S "$BACKEND_DIR" -B "$dir" -G Ninja "${COMMON_CMAKE[@]}" "$@" > "$log" 2>&1 &&
        cmake --build "$dir" -j"$JOBS" >> "$log" 2>&1 && return 0

    note "build failed, see $log"
    tail -20 "$log" | sed 's/^/   | /'

    return 1
}

stage_noh3() {
    say "noh3: build without HTTP/3, then unit tests"

    if build "$CI_BUILD_DIR/noh3" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=no &&
       "$CI_BUILD_DIR/noh3/exec/runner" | tail -4 | sed 's/^/   /'; then
        record noh3 OK
    else
        record noh3 FAIL
    fi
}

stage_asan() {
    say "asan: HTTP/3 unit tests and both reload modes (ASan+LSan)"

    if build "$CI_BUILD_DIR/asan" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes &&
       "$CI_BUILD_DIR/asan/exec/runner" | tail -4 | sed 's/^/   /' &&
       H3_RELOAD_PORT=18454 "$CORE_DIR/tests/h3_hard_reload.sh" \
             "$CI_BUILD_DIR/asan" "$CI_BUILD_DIR/h3-hard-reload-asan" &&
       H3_RELOAD_PORT=18455 "$CORE_DIR/tests/h3_soft_reload.sh" \
             "$CI_BUILD_DIR/asan" "$CI_BUILD_DIR/h3-soft-reload-asan"; then
        record asan OK
    else
        record asan FAIL
    fi
}

stage_tsan() {
    say "tsan: HTTP/3 unit tests and both reload modes (ThreadSanitizer)"

    # TSan cannot be linked alongside ASan, hence its own tree -- and its own
    # ASAN_OPTIONS-free environment.
    if ASAN_OPTIONS= build "$CI_BUILD_DIR/tsan" -DCMAKE_BUILD_TYPE=Debug \
             -DBUILD_TESTS=yes -DINCLUDE_HTTP3=yes -DSANITIZE=thread &&
       ASAN_OPTIONS= TSAN_OPTIONS="halt_on_error=1" \
             "$CI_BUILD_DIR/tsan/exec/runner" | tail -4 | sed 's/^/   /' &&
       ASAN_OPTIONS= TSAN_OPTIONS="halt_on_error=1" H3_RELOAD_PORT=18456 \
             "$CORE_DIR/tests/h3_hard_reload.sh" "$CI_BUILD_DIR/tsan" \
             "$CI_BUILD_DIR/h3-hard-reload-tsan" &&
       ASAN_OPTIONS= TSAN_OPTIONS="halt_on_error=1" H3_RELOAD_PORT=18457 \
             "$CORE_DIR/tests/h3_soft_reload.sh" "$CI_BUILD_DIR/tsan" \
             "$CI_BUILD_DIR/h3-soft-reload-tsan"; then
        record tsan OK
    else
        record tsan FAIL
    fi
}

stage_h3unit() {
    say "h3unit: isolated QUIC / HTTP/3 / QPACK unit tests"
    if build "$CI_BUILD_DIR/h3unit" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes &&
       "$CI_BUILD_DIR/h3unit/exec/h3_runner" | tail -4 | sed 's/^/   /'; then
        record h3unit OK
    else
        record h3unit FAIL
    fi
}

stage_limits() {
    say "limits: process-wide QUIC connection and memory budgets"
    if build "$CI_BUILD_DIR/limits" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes -DSANITIZE=none &&
       H3_LIMITS_PORT=18459 "$CORE_DIR/tests/h3_resource_limits.sh" \
             "$CI_BUILD_DIR/limits" "$CI_BUILD_DIR/h3-resource-limits"; then
        record limits OK
    else
        record limits FAIL
    fi
}

stage_soak() {
    say "soak: sustained HTTP/3 requests, impairment, migration and RSS drain"
    local requests=${SOAK_REQUESTS:-1000}
    if build "$CI_BUILD_DIR/limits" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes -DSANITIZE=none &&
       SOAK_REQUESTS="$requests" H3_SOAK_PORT=18460 "$CORE_DIR/tests/h3_soak.sh" \
             "$CI_BUILD_DIR/limits" "$CI_BUILD_DIR/h3-soak"; then
        record soak OK
    else
        record soak FAIL
    fi
}

stage_affinity() {
    say "affinity: a migrated connection follows its datagrams to the new worker"
    if ! build "$CI_BUILD_DIR/limits" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
               -DINCLUDE_HTTP3=yes -DSANITIZE=none; then
        record affinity FAIL
        return
    fi

    H3_AFFINITY_PORT=18462 "$CORE_DIR/tests/h3_affinity.sh" \
        "$CI_BUILD_DIR/limits" "$CI_BUILD_DIR/h3-affinity"
    local status=$?
    if [ "$status" -eq 0 ]; then
        record affinity OK
    elif [ "$status" -eq 77 ]; then
        # Every migrated 4-tuple hashed back to its own worker. Rare, and not a
        # failure: there was nothing for the mechanism to do.
        record affinity SKIP
    else
        record affinity FAIL
    fi
}

stage_earlydata() {
    say "early data: 0-RTT accepted, counted, and not dispatched before the handshake"
    if build "$CI_BUILD_DIR/limits" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes -DSANITIZE=none &&
       H3_EARLY_PORT=18461 "$CORE_DIR/tests/h3_early_data.sh" \
             "$CI_BUILD_DIR/limits" "$CI_BUILD_DIR/h3-early-data"; then
        record earlydata OK
    else
        record earlydata FAIL
    fi
}

stage_benchmark() {
    say "benchmark: median HTTP/3 req/s and throughput regression"
    if ! build "$CI_BUILD_DIR/limits" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
              -DINCLUDE_HTTP3=yes -DSANITIZE=none; then
        record benchmark FAIL
        return
    fi

    REQUIRE_BENCHMARK="${REQUIRE_BENCHMARK:-0}" \
    BENCH_BASELINE="${BENCH_BASELINE:-}" BENCH_RECORD="${BENCH_RECORD:-}" \
    H3_BENCH_PORT=18461 "$CORE_DIR/tests/h3_benchmark.sh" \
        "$CI_BUILD_DIR/limits" "$CI_BUILD_DIR/h3-benchmark"
    local status=$?
    if [ "$status" -eq 0 ]; then
        record benchmark OK
    elif [ "$status" -eq 77 ]; then
        record benchmark SKIP
    else
        record benchmark FAIL
    fi
}

stage_config() {
    say "config: invalid HTTP/3 policy rejects startup"

    if build "$CI_BUILD_DIR/h3unit" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes &&
       "$CORE_DIR/tests/h3_config_validation.sh" "$CI_BUILD_DIR/h3unit" \
             "$CI_BUILD_DIR/h3-config-validation"; then
        record config OK
    else
        record config FAIL
    fi
}

stage_fuzz() {
    say "fuzz: $FUZZ_SECONDS s per target (§5 asks 24h per target on a schedule)"

    if ! build "$CI_BUILD_DIR/fuzz" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=yes \
               -DINCLUDE_HTTP3=yes -DBUILD_FUZZERS=yes; then
        record fuzz FAIL
        return
    fi

    local crashes="$CI_BUILD_DIR/crashes"
    mkdir -p "$crashes"

    local ok=1
    local fuzz_names=(
        quic_packet quic_frame quic_tp h3_frame
        qpack_decode qpack_streams huffman
    )
    local fuzz_name target
    for fuzz_name in "${fuzz_names[@]}"; do
        target="$CI_BUILD_DIR/fuzz/exec/fuzz_$fuzz_name"
        if [ ! -x "$target" ]; then
            note "fuzz_$fuzz_name is missing or not executable"
            ok=0
            continue
        fi

        local name=$(basename "$target")
        local corpus="$CORE_DIR/tests/fuzz/corpus/${name#fuzz_}"

        # The corpus in the tree is the seed set; found inputs go to the build
        # dir, so a gate run never writes to the working copy.
        local work="$CI_BUILD_DIR/corpus/${name#fuzz_}"
        mkdir -p "$work"
        [ -d "$corpus" ] && cp -n "$corpus"/* "$work"/ 2>/dev/null

        local log="$CI_BUILD_DIR/$name.log"
        if "$target" -seconds="$FUZZ_SECONDS" -artifacts="$crashes" "$work" \
                > "$log" 2>&1; then
            note "$(tail -1 "$CI_BUILD_DIR/$name.log")"
        elif grep -Eq 'LeakSanitizer.*(does not work|not supported)|LSan.*(does not work|not supported)' "$log"; then
            note "$name: LeakSanitizer unavailable; retrying with leak detection disabled"
            if ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0" \
                    "$target" -seconds="$FUZZ_SECONDS" -artifacts="$crashes" "$work" \
                    >> "$log" 2>&1; then
                note "$(tail -1 "$log")"
            else
                note "$name CRASHED after the LSan fallback -- input in $crashes, log in $log"
                ok=0
            fi
        else
            note "$name CRASHED -- input in $crashes, log in $CI_BUILD_DIR/$name.log"
            ok=0
        fi
    done

    [ "$ok" = 1 ] && record fuzz OK || record fuzz FAIL
}

stage_reload() {
    say "reload: hard reload retires old HTTP/3 workers"

    if build "$CI_BUILD_DIR/rel" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes &&
       "$CORE_DIR/tests/h3_hard_reload.sh" "$CI_BUILD_DIR/rel" \
             "$CI_BUILD_DIR/h3-hard-reload"; then
        record reload OK
    else
        record reload FAIL
    fi
}

stage_softreload() {
    say "softreload: old HTTP/3 CID survives config handoff"

    if build "$CI_BUILD_DIR/rel" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
             -DINCLUDE_HTTP3=yes &&
       "$CORE_DIR/tests/h3_soft_reload.sh" "$CI_BUILD_DIR/rel" \
             "$CI_BUILD_DIR/h3-soft-reload"; then
        record softreload OK
    else
        record softreload FAIL
    fi
}

stage_h3spec() {
    say "h3spec: RFC conformance against a running server"

    if [ -z "$H3SPEC" ] || [ ! -x "$H3SPEC" ]; then
        note "h3spec binary not found (set H3SPEC=/path/to/h3spec)."
        note "Releases: github.com/kazu-yamamoto/h3spec -- take the binary, do"
        note "not build Haskell."
        if [ "$REQUIRE_H3SPEC" = 1 ]; then
            note "REQUIRE_H3SPEC=1: absence is a release-gate failure."
            record h3spec FAIL
        else
            record h3spec SKIP
        fi
        return
    fi

    if ! build "$CI_BUILD_DIR/rel" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=yes \
               -DINCLUDE_HTTP3=yes; then
        record h3spec FAIL
        return
    fi

    # A server of its own, so the stage needs nothing configured on the machine.
    # The certificate is the committed test one (tests/data), which is what the
    # unit tests use for the same reason.
    local root="$CI_BUILD_DIR/www"
    mkdir -p "$root"
    echo '<html><body>ci</body></html>' > "$root/index.html"

    local config="$CI_BUILD_DIR/h3spec.json"
    cat > "$config" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576, "tmp": "/tmp",
        "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" },
        "env": { "http3_so_rcvbuf": 4194304 }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"],
            "ip": "127.0.0.1", "port": 18443,
            "root": "$root",
            "index": "index.html",
            "tls": {
                "fullchain": "$CORE_DIR/tests/data/quic_test_cert.pem",
                "private": "$CORE_DIR/tests/data/quic_test_key.pem",
                "ciphers": "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
            },
            "http3": { "enabled": true, "port": 18443 }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON

    "$CI_BUILD_DIR/rel/exec/cwfr" -c "$config" -f > "$CI_BUILD_DIR/h3spec-server.log" 2>&1 &
    local server=$!
    sleep 2

    if ! kill -0 "$server" 2>/dev/null; then
        note "server did not start, see $CI_BUILD_DIR/h3spec-server.log"
        record h3spec FAIL
        return
    fi

    # `-n` skips certificate validation: the test certificate is self-signed on
    # purpose. A dead port looks exactly like a non-conforming server here (48
    # failures out of 49), which is why the liveness check above is separate.
    local out="$CI_BUILD_DIR/h3spec.txt"
    "$H3SPEC" -n localhost 18443 > "$out" 2>&1
    kill "$server" 2>/dev/null
    wait "$server" 2>/dev/null

    note "$(tail -1 "$out")"

    if grep -q "0 failures" "$out"; then
        record h3spec OK
    else
        note "see $out"
        record h3spec FAIL
    fi
}

ALL_STAGES=(noh3 h3unit config limits soak affinity earlydata benchmark asan tsan fuzz reload softreload h3spec)
STAGES=("$@")
if [ ${#STAGES[@]} -eq 0 ]; then
    STAGES=("${ALL_STAGES[@]}")
elif [ ${#STAGES[@]} -eq 1 ] && [ "${STAGES[0]}" = release ]; then
    REQUIRE_H3SPEC=1
    REQUIRE_BENCHMARK=1
    SOAK_REQUESTS=${SOAK_REQUESTS:-10000}
    STAGES=("${ALL_STAGES[@]}")
fi

for stage in "${STAGES[@]}"; do
    case "$stage" in
    noh3)   stage_noh3 ;;
    asan)   stage_asan ;;
    tsan)   stage_tsan ;;
    h3unit) stage_h3unit ;;
    config) stage_config ;;
    limits) stage_limits ;;
    soak)    stage_soak ;;
    affinity) stage_affinity ;;
    earlydata) stage_earlydata ;;
    benchmark) stage_benchmark ;;
    fuzz)   stage_fuzz ;;
    reload) stage_reload ;;
    softreload) stage_softreload ;;
    h3spec) stage_h3spec ;;
    *)      echo "unknown stage: $stage" >&2; exit 2 ;;
    esac
done

say "summary"
for i in "${!STAGES_RUN[@]}"; do
    printf '   %-8s %s\n' "${STAGES_RUN[$i]}" "${STAGES_RESULT[$i]}"
done

exit "$FAILED"
