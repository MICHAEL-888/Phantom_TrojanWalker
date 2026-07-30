#!/usr/bin/env bash

set -u

pids=()

shutdown() {
    trap - TERM INT
    if ((${#pids[@]} > 0)); then
        kill -TERM "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
    fi
}

trap shutdown TERM INT

python module/ghidra_mcp/main.py &
pids+=("$!")
python module/ghidra_pipe/main.py &
pids+=("$!")

# Keep the container alive while both services run. If either exits, stop the
# sibling so the container does not remain partially healthy.
wait -n "${pids[@]}"
status=$?
shutdown
exit "$status"
