#!/usr/bin/env bash
# Run exactly the targets registered by this CMake configuration, including
# application targets, and fail when one that should be there is not.
#
#   tests/fuzz/run.sh BUILD_DIR [OUTPUT_DIR]
#
# The manifest (BUILD_DIR/fuzz-targets.txt) is written by cwfr_add_fuzzer() in
# cmake/fuzz.cmake, one line per target that was actually configured. It
# cannot tell a target that was dropped from one that never existed, so the
# list below is the independent half of the check: a core target missing from
# the manifest, or registered but not built, fails the run.
#
# All mutable state stays under OUTPUT_DIR, never in the seed directories:
#   OUTPUT_DIR/run.txt               parameters of this run
#   OUTPUT_DIR/summary.txt           one line per target
#   OUTPUT_DIR/<target>/corpus/      seeds plus everything found (kept between runs)
#   OUTPUT_DIR/<target>/artifacts/   failing inputs
#   OUTPUT_DIR/<target>/run.log      the engine's output
#   OUTPUT_DIR/<target>/command.txt  the exact command line
#   OUTPUT_DIR/<target>/replay.log   a failing input run on its own, to show it
#                                    reproduces without the run that found it
#
# Environment:
#   FUZZ_PROFILE  smoke  10 s per target, inputs up to 8 KiB   (every change)
#                 long   24 h per target, inputs up to 256 KiB (on a schedule)
#                 large  120 s per target, inputs up to 1 MiB  (big-input pass)
#   FUZZ_SECONDS  override the time per target
#   FUZZ_MAX_LEN  override the input size limit
#   FUZZ_TIMEOUT  seconds one input may take before it counts as a hang (5)
#   FUZZ_SEED     PRNG seed; smoke defaults to 1 so a gate run is repeatable,
#                 long and large to a fresh one that run.txt records
#   FUZZ_JOBS     targets run in parallel (default: nproc)
#   FUZZ_EXPECT_EXTRA  space-separated targets the caller also requires, e.g.
#                 application targets: FUZZ_EXPECT_EXTRA=fuzz_feedback
#   FUZZ_ONLY     space-separated targets to run; the rest are skipped (the
#                 expected-target check still covers the whole manifest)
set -euo pipefail

build_dir=${1:?Usage: run.sh BUILD_DIR [OUTPUT_DIR]}
output_dir=${2:-$build_dir/fuzz-results}
profile=${FUZZ_PROFILE:-smoke}
case "$profile" in
    smoke) default_seconds=10;    default_max_len=8192;    default_seed=1 ;;
    long)  default_seconds=86400; default_max_len=262144;  default_seed= ;;
    large) default_seconds=120;   default_max_len=1048576; default_seed= ;;
    *) echo "Unknown FUZZ_PROFILE: $profile" >&2; exit 2 ;;
esac
seconds=${FUZZ_SECONDS:-$default_seconds}
max_len=${FUZZ_MAX_LEN:-$default_max_len}
input_timeout=${FUZZ_TIMEOUT:-5}
seed=${FUZZ_SEED:-${default_seed:-$(( ($(date +%s) ^ $$) & 0x7fffffff | 1 ))}}
parallel=${FUZZ_JOBS:-$(nproc)}
for value in "$seconds" "$max_len" "$input_timeout" "$seed" "$parallel"; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo "Fuzz limits must be positive integers" >&2; exit 2; }
done

manifest="$build_dir/fuzz-targets.txt"
[[ -s $manifest ]] || { echo "Missing or empty fuzz manifest: $manifest" >&2; exit 1; }

# The core's own targets, kept in step with tests/CMakeLists.txt on purpose.
expected=(fuzz_huffman fuzz_hpack fuzz_h2_frame fuzz_json fuzz_cookie
          fuzz_urlencoded fuzz_multipart fuzz_request fuzz_request_sequence
          fuzz_websocket fuzz_websocket_sequence fuzz_ws_deflate fuzz_h2_session
          fuzz_h2_connection fuzz_http_response fuzz_smtp_response fuzz_jwt)
if grep -Eq '^INCLUDE_HTTP3:[A-Z]+=yes$' "$build_dir/CMakeCache.txt" 2>/dev/null; then
    expected+=(fuzz_quic_packet fuzz_quic_frame fuzz_quic_tp fuzz_h3_frame
               fuzz_qpack_decode fuzz_qpack_streams fuzz_h3_priority fuzz_qpack_dynamic
               fuzz_qpack_session fuzz_quic_stream fuzz_h3_request)
fi
read -r -a extra <<< "${FUZZ_EXPECT_EXTRA:-}"
expected+=("${extra[@]}")

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
cp "$manifest" "$output_dir/manifest.txt"
printf 'profile=%s seconds=%s max_len=%s timeout=%s seed=%s jobs=%s\n' \
    "$profile" "$seconds" "$max_len" "$input_timeout" "$seed" "$parallel" > "$output_dir/run.txt"
: > "$output_dir/summary.txt"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}halt_on_error=1:abort_on_error=1:print_stacktrace=1"

failed=0
for name in "${expected[@]}"; do
    if ! cut -d'|' -f1 "$manifest" | grep -qx "$name"; then
        echo "$name: expected but not registered in $manifest" >&2
        echo "$name|MISSING" >> "$output_dir/summary.txt"
        failed=1
    fi
done

# Runs one target; the verdict goes to $work/status, the rest to files, so that
# parallel runs do not interleave their output.
run_target() {
    local name=$1 executable=$2 seeds=$3 dictionary=$4 engine=$5 leaks=$6
    local work="$output_dir/$name"
    mkdir -p "$work/corpus" "$work/artifacts"
    rm -f "$work/status" "$work/replay.log"

    # Never overwrite a corpus discovered by an earlier run.
    cp -n "$seeds"/* "$work/corpus/" 2>/dev/null || true

    local args=("-max_len=$max_len" "-timeout=$input_timeout" "-seed=$seed")
    case "$engine" in
        gcc) args+=("-seconds=$seconds" "-artifacts=$work/artifacts") ;;
        libfuzzer) args+=("-max_total_time=$seconds" "-artifact_prefix=$work/artifacts/") ;;
    esac
    [[ ! -f $dictionary ]] || args+=("-dict=$dictionary")
    args+=("$work/corpus")

    local asan=${ASAN_OPTIONS:-}
    [[ $leaks == 1 ]] || asan="${asan:+$asan:}detect_leaks=0"
    printf 'ASAN_OPTIONS=%q ' "$asan" > "$work/command.txt"
    printf '%q ' "$executable" "${args[@]}" >> "$work/command.txt"
    printf '\n' >> "$work/command.txt"

    local before
    before=$(find "$work/artifacts" -type f | wc -l)
    if ASAN_OPTIONS=$asan "$executable" "${args[@]}" > "$work/run.log" 2>&1; then
        echo "OK" > "$work/status"
        return
    fi

    if grep -Eq 'LeakSanitizer has encountered a fatal error|LeakSanitizer.*(does not work|not supported)' "$work/run.log"; then
        echo "[run.sh] LeakSanitizer unavailable; retrying with detect_leaks=0" >> "$work/run.log"
        asan="${asan:+$asan:}detect_leaks=0"
        if ASAN_OPTIONS=$asan "$executable" "${args[@]}" >> "$work/run.log" 2>&1; then
            echo "OK (no LSan)" > "$work/status"
            return
        fi
    fi

    # The run failed. Replay the newest saved input on its own: a failure that
    # a stored input does not reproduce is a failure nobody can fix.
    local artifact
    artifact=$(find "$work/artifacts" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    if [[ -n $artifact && $(find "$work/artifacts" -type f | wc -l) -gt $before ]]; then
        if ASAN_OPTIONS=$asan "$executable" "-max_len=$max_len" "-timeout=$input_timeout" "$artifact" \
                > "$work/replay.log" 2>&1; then
            echo "FAILED; saved input did NOT reproduce: $artifact" > "$work/status"
        else
            echo "FAILED; reproduces with: $executable -max_len=$max_len $artifact" > "$work/status"
        fi
    else
        echo "FAILED; no input saved (leak at exit or engine error)" > "$work/status"
    fi
}

names=()
declare -A leak_check=()
while IFS='|' read -r name executable seeds dictionary engine leaks; do
    [[ $name =~ ^fuzz_[a-z0-9_]+$ ]] || { echo "Invalid manifest entry: $name" >&2; exit 1; }
    leaks=${leaks:-1}
    if [[ -n ${FUZZ_ONLY:-} && " $FUZZ_ONLY " != *" $name "* ]]; then
        continue
    fi
    case "$engine" in gcc|libfuzzer) ;; *) echo "$name: unknown fuzz engine: $engine" >&2; exit 1 ;; esac
    if [[ ! -x $executable ]]; then
        echo "$name: missing executable: $executable" >&2
        echo "$name|NOT BUILT" >> "$output_dir/summary.txt"
        failed=1
        continue
    fi
    if [[ ! -d $seeds ]] || [[ -z $(ls -A "$seeds") ]]; then
        echo "$name: missing or empty seed corpus: $seeds" >&2
        echo "$name|NO SEEDS" >> "$output_dir/summary.txt"
        failed=1
        continue
    fi

    while (( $(jobs -rp | wc -l) >= parallel )); do wait -n || true; done
    run_target "$name" "$executable" "$seeds" "$dictionary" "$engine" "$leaks" &
    names+=("$name")
    leak_check[$name]=$leaks
done < "$manifest"
wait

for name in "${names[@]}"; do
    work="$output_dir/$name"
    status=$(cat "$work/status" 2>/dev/null || echo "FAILED; no status")
    last=$(grep -E 'runs|Done|exec/s' "$work/run.log" 2>/dev/null | tail -1 | sed 's/^.*\/\(fuzz_[a-z0-9_]*\) */\1 /' || true)
    note=""
    [[ ${leak_check[$name]} == 1 ]] || note=" [leaks off]"
    case "$status" in
        OK*) echo "$name: $status$note -- $last" ;;
        *)   echo "$name: $status (log: $work/run.log)" >&2; failed=1 ;;
    esac
    echo "$name|$status$note|$last" >> "$output_dir/summary.txt"
done

exit "$failed"
