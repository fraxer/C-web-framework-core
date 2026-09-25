#!/usr/bin/env bash
# Line coverage of the core reached by the fuzz targets, per file and per
# directory, so "what is not fuzzed" is a table rather than a guess.
#
#   tests/fuzz/coverage.sh BUILD_DIR [OUTPUT_DIR]
#
# BUILD_DIR is a fuzzing build compiled with --coverage (tests/readme.md,
# "Coverage"). The targets run through tests/fuzz/run.sh, so they get the same
# seeds, dictionaries and manifest check as any other run, and a corpus kept in
# OUTPUT_DIR from an earlier run -- a long one especially -- is replayed first.
# The counters are reset before the run: the numbers are this run's alone.
#
#   OUTPUT_DIR/coverage-files.txt  uncovered lines, lines, percent, file
#   OUTPUT_DIR/coverage-dirs.txt   the same summed per directory
#
# Both are sorted by uncovered lines, largest first. Environment is run.sh's;
# FUZZ_SECONDS defaults to 30 here.
set -euo pipefail

build_dir=${1:?Usage: coverage.sh BUILD_DIR [OUTPUT_DIR]}
output_dir=${2:-$build_dir/fuzz-coverage}
here=$(cd "$(dirname "$0")" && pwd)

command -v gcov > /dev/null || { echo "gcov not found" >&2; exit 2; }
if ! find "$build_dir" -name '*.gcno' -print -quit | grep -q .; then
    echo "$build_dir has no .gcno files: configure it with --coverage" >&2
    exit 2
fi

find "$build_dir" -name '*.gcda' -delete
mkdir -p "$output_dir"

status=0
FUZZ_SECONDS=${FUZZ_SECONDS:-30} bash "$here/run.sh" "$build_dir" "$output_dir" || status=$?

# The core's own objects only: not the tests, the fuzz targets or the apps.
files="$output_dir/coverage-files.txt"
: > "$files.tmp"
while IFS= read -r notes; do
    gcov -n "$notes" 2> /dev/null | awk -v src="/$(basename "$notes" .gcno)'" '
        /^File / && index($0, src) { found = 1; path = $2; next }
        found && /^Lines executed/ {
            split($2, a, ":"); sub("%", "", a[2]);
            gsub("\047", "", path); sub(".*/core/", "", path);
            printf "%d %d %.1f%% %s\n", $4 - a[2] * $4 / 100 + 0.5, $4, a[2], path;
            exit
        }' >> "$files.tmp"
done < <(find "$build_dir/core" -name '*.c.gcno' \
             -not -path '*/tests/*' -not -path '*/apps/*')
sort -rn "$files.tmp" | awk '{ printf "%6d %6d %6s  %s\n", $1, $2, $3, $4 }' > "$files"
rm -f "$files.tmp"

awk '{ dir = $4; sub("/[^/]*$", "", dir); gap[dir] += $1; all[dir] += $2 }
     END { for (d in all)
               printf "%6d %6d %5.1f%%  %s\n", gap[d], all[d],
                      all[d] ? 100 * (all[d] - gap[d]) / all[d] : 0, d }' "$files" |
    sort -rn > "$output_dir/coverage-dirs.txt"

awk '{ gap += $1; all += $2 }
     END { printf "core: %d of %d lines reached (%.1f%%)\n", all - gap, all,
                  all ? 100 * (all - gap) / all : 0 }' "$files"
echo "per file: $files"
echo "per directory: $output_dir/coverage-dirs.txt"

exit "$status"
