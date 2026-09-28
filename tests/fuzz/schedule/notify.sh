#!/usr/bin/env bash
# The failure report of a scheduled run, handed to $FUZZ_NOTIFY_COMMAND on
# stdin (logger by default): which targets failed, how each reproduces, where
# the log is.
#
#   tests/fuzz/schedule/notify.sh LOG
#
# FUZZ_NOTIFY_COMMAND is run by the shell, so a mail pipe or a webhook both
# fit, e.g. 'mail -s "cwfr fuzzing failed" dev@example.com' or
# 'curl -fsS -X POST --data-binary @- https://hooks.example.com/fuzz'.
set -uo pipefail

log=${1:?Usage: notify.sh LOG}
command=${FUZZ_NOTIFY_COMMAND:-logger -t cwfr-fuzz}

{
    echo "cwfr scheduled fuzzing failed on $(hostname) at $(date -Is)"
    echo "log: $log"
    echo
    grep -E 'FAILED|MISSING|NOT BUILT|NO SEEDS|fuzz +FAIL' "$log" || echo "(no target line; see the log)"
} | sh -c "$command"
