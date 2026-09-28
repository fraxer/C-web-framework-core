#!/usr/bin/env bash
# The scheduled fuzzing run: the long profile of tests/ci.sh fuzz, both
# builds, then the grown corpora minimised against the seeds, and a message
# when anything failed.
#
#   tests/fuzz/schedule/scheduled.sh
#
# Meant for a timer (cwfr-fuzz.timer here) or cron on a build server. Every
# setting comes from the environment -- the systemd unit reads it from
# /etc/cwfr-fuzz.env (fuzz.env.example):
#
#   CI_BUILD_DIR         build trees and results; kept between runs, which is
#                        what lets the corpus grow (default /var/lib/cwfr-fuzz)
#   FUZZ_SECONDS         time per target (default 3600: with ~50 targets and
#                        FUZZ_JOBS=nproc that is a few hours of a night)
#   FUZZ_JOBS            targets in parallel (default: nproc)
#   FUZZ_NOTIFY_COMMAND  run with the report on stdin when the run fails
#                        (default: logger -t cwfr-fuzz)
#
# The minimised inputs are left in $CI_BUILD_DIR/fuzz*-results/<target>/
# minimized/ for a person to look at and bring back with
# tests/fuzz/minimize.sh ... --apply: a schedule that commits to the
# repository by itself is not one anybody reviews.
set -uo pipefail

core=$(cd "$(dirname "$0")/../../.." && pwd)
export CI_BUILD_DIR=${CI_BUILD_DIR:-/var/lib/cwfr-fuzz}
export FUZZ_PROFILE=long
export FUZZ_SECONDS=${FUZZ_SECONDS:-3600}
mkdir -p "$CI_BUILD_DIR"

log="$CI_BUILD_DIR/scheduled-$(date +%Y%m%d-%H%M%S).log"
status=0

"$core/tests/ci.sh" fuzz > "$log" 2>&1 || status=1

for tree in fuzz fuzz-noh3; do
    [[ -d $CI_BUILD_DIR/$tree-results ]] || continue
    "$core/tests/fuzz/minimize.sh" "$CI_BUILD_DIR/$tree" "$CI_BUILD_DIR/$tree-results" >> "$log" 2>&1 || status=1
done

if (( status != 0 )); then
    "$core/tests/fuzz/schedule/notify.sh" "$log" || true
fi
exit "$status"
