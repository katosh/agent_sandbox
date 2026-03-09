#!/usr/bin/env bash
# srun-sandbox.sh — Drop-in srun that wraps commands in the sandbox on the compute node
#
# Accepts the same arguments as real srun. Separates srun flags from the
# command, then runs:  /usr/bin/srun [flags] sandbox-exec.sh -- command
#
# Works with or without a -- separator:
#   srun-sandbox.sh -n 4 python train.py
#   srun-sandbox.sh -n 4 -- python train.py

set -euo pipefail

# Inside the sandbox, the real srun may be at a relocated path (bwrap)
# or at its original location (landlock).
if [[ "${SANDBOX_ACTIVE:-}" == "1" ]]; then
    if [[ "${SANDBOX_BACKEND:-bwrap}" == "bwrap" ]]; then
        REAL_SRUN="${REAL_SRUN:-/tmp/.sandbox-slurm-real/srun}"
    else
        REAL_SRUN="${REAL_SRUN:-/usr/bin/srun}"
    fi
else
    REAL_SRUN="${REAL_SRUN:-/usr/bin/srun}"
fi
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/sandbox-lib.sh"

PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ── Known srun flags that consume a value argument ──────────────
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
            shift
            USER_CMD=("$@")
            break
            ;;
        -*)
            SRUN_FLAGS+=("$1")
            if [[ "$1" != *=* ]] && is_value_flag "$1"; then
                if [[ $# -gt 1 ]]; then
                    shift
                    SRUN_FLAGS+=("$1")
                fi
            fi
            shift
            ;;
        *)
            USER_CMD=("$@")
            break
            ;;
    esac
done

if [[ ${#USER_CMD[@]} -eq 0 ]]; then
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}"
fi

detect_backend
backend_prepare "$PROJECT_DIR"

if [[ "$SANDBOX_BACKEND" == "bwrap" ]]; then
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}" \
        "$BWRAP" "${BWRAP_ARGS[@]}" -- "${USER_CMD[@]}"
else
    # For landlock: run sandbox-exec.sh on the compute node
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}" \
        "$SCRIPT_DIR/sandbox-exec.sh" --project-dir "$PROJECT_DIR" -- "${USER_CMD[@]}"
fi
