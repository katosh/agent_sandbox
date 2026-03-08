#!/usr/bin/env bash
# srun-sandbox.sh — Drop-in srun that wraps commands in bwrap on the compute node
#
# Accepts the same arguments as real srun. Separates srun flags from the
# command, then runs:  /usr/bin/srun [flags] bwrap [args] -- command
#
# Works with or without a -- separator:
#   srun-sandbox.sh -n 4 python train.py
#   srun-sandbox.sh -n 4 -- python train.py

set -euo pipefail

REAL_SRUN="${REAL_SRUN:-/usr/bin/srun}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/sandbox-lib.sh"

PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ── Known srun flags that consume a value argument ──────────────
# (flags using --flag=value don't need to be listed here)
SRUN_VALUE_FLAGS=(
    -A --account -c --cpus-per-task -D --chdir -d --dependency
    -e --error -J --job-name -n --ntasks -N --nodes -o --output
    -p --partition -t --time -G --gpus -m --distribution -w --nodelist
    -x --exclude
    --mem --mem-per-cpu --mem-per-gpu --gres --constraint --export
    --mpi --cpu-bind --gpu-bind --gpus-per-node --gpus-per-task
    --ntasks-per-node --cpus-per-gpu --signal --switches
    --threads-per-core --network --begin --nice --priority --qos
    --reservation --wckey --comment --mail-type --mail-user
)

is_value_flag() {
    local flag="$1"
    for vf in "${SRUN_VALUE_FLAGS[@]}"; do
        [[ "$flag" == "$vf" ]] && return 0
    done
    return 1
}

# ── Parse arguments ─────────────────────────────────────────────
SRUN_FLAGS=()
USER_CMD=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --)
            # Explicit separator — everything after is the command
            shift
            USER_CMD=("$@")
            break
            ;;
        -*)
            SRUN_FLAGS+=("$1")
            # If this flag takes a separate value arg (not --flag=val)
            if [[ "$1" != *=* ]] && is_value_flag "$1"; then
                if [[ $# -gt 1 ]]; then
                    shift
                    SRUN_FLAGS+=("$1")
                fi
            fi
            shift
            ;;
        *)
            # First non-flag argument = start of user command
            USER_CMD=("$@")
            break
            ;;
    esac
done

if [[ ${#USER_CMD[@]} -eq 0 ]]; then
    # No command — pass through to real srun (will show usage/error)
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}"
fi

build_bwrap_args "$PROJECT_DIR"

exec "$REAL_SRUN" "${SRUN_FLAGS[@]}" \
    "$BWRAP" "${BWRAP_ARGS[@]}" -- "${USER_CMD[@]}"
