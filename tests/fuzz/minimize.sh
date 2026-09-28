#!/usr/bin/env bash
# Bring back what a long run found, and no more of it than it takes.
#
#   tests/fuzz/minimize.sh BUILD_DIR [RESULTS_DIR] [--apply]
#
# For every target in the manifest whose RESULTS_DIR/<target>/corpus exists
# (run.sh keeps one per target, grown across runs), the driver's -minimize
# mode keeps the smallest inputs that reach something the seed corpus does not
# reach, into RESULTS_DIR/<target>/minimized/. With --apply they are copied
# into the target's seed directory under tests/fuzz/corpus/, named by content
# (id-<hash>), so the hand-named seeds and regressions stay as they are.
#
# GCC builds only: libFuzzer has its own -merge=1 for the same job.
set -euo pipefail

build_dir=${1:?Usage: minimize.sh BUILD_DIR [RESULTS_DIR] [--apply]}
shift
results_dir=$build_dir/fuzz-results
apply=0
for arg in "$@"; do
    case "$arg" in
        --apply) apply=1 ;;
        *) results_dir=$arg ;;
    esac
done

manifest="$build_dir/fuzz-targets.txt"
[[ -s $manifest ]] || { echo "Missing or empty fuzz manifest: $manifest" >&2; exit 1; }
[[ -d $results_dir ]] || { echo "No results directory: $results_dir" >&2; exit 1; }

status=0
while IFS='|' read -r name executable seeds _dictionary engine _leaks; do
    corpus="$results_dir/$name/corpus"
    [[ -d $corpus ]] || continue
    if [[ $engine != gcc ]]; then
        echo "$name: engine $engine, skipped (use libFuzzer's -merge=1)"
        continue
    fi

    out="$results_dir/$name/minimized"
    rm -rf "$out"
    mkdir -p "$out"
    if ! "$executable" "-minimize=$out" "-base=$seeds" "-artifacts=$results_dir/$name/artifacts" \
            "$corpus" > "$results_dir/$name/minimize.log" 2>&1; then
        echo "$name: FAILED (log: $results_dir/$name/minimize.log)" >&2
        status=1
        continue
    fi
    echo "$name: $(grep '^minimised' "$results_dir/$name/minimize.log" | sed 's/^minimised [^:]*: //')"

    if (( apply )) && [[ -n $(ls -A "$out") ]]; then
        cp -n "$out"/* "$seeds/"
    fi
done < "$manifest"

exit "$status"
