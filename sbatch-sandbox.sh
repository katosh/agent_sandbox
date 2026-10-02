#! /bin/bash --
# sbatch-sandbox.sh — Submit Slurm jobs that run inside the sandbox
#
# Drop-in replacement for sbatch. The job itself executes inside the
# sandbox on the compute node (using whichever backend is available).
#
# Usage:
#   sbatch-sandbox.sh [sbatch-flags] --wrap="command"
#   sbatch-sandbox.sh [sbatch-flags] script.sh [script-args]
#
# Since sandbox scripts live on NFS, they're available on every compute
# node without extra setup.
#
# Flag parsing: this script only looks for --wrap (which it must
# intercept) and the job script (the first bare positional argument that
# exists as a file). Flag values are consumed by peeking ahead; the only
# list kept is of flags that NEVER take a separate-word value (value-less
# flags and optional-argument long flags, which need `=`), so e.g.
# `--exclusive job.sh` does not swallow the script name.
#
# DEPRECATED: inside the sandbox, plain `sbatch` goes through the
# chaperon. This wrapper is kept for old setups only.

set -euo pipefail

REAL_SBATCH="${REAL_SBATCH:-/usr/bin/sbatch}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"

# Project dir: inherit from sandbox env, or use $PWD
PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ── Parse arguments ─────────────────────────────────────────────
# Strategy: collect all arguments, looking only for --wrap (which we
# must intercept). Everything else is kept in order. After the scan,
# if there's no --wrap, we find the job script by walking the collected
# arguments with flag-value awareness:
#   - --long=value forms are self-contained (one arg)
#   - -x or --long followed by a non-flag arg: the next arg is consumed
#     as the flag's value (skip it)
#   - The first bare positional (not consumed as a flag value) that
#     exists as a regular file is the job script
# This avoids maintaining a list of which flags consume a value.

ALL_ARGS=()
WRAP_CMD=""

# sbatch flags that never consume the following word as their value:
# value-less flags, plus long flags whose argument is optional (Slurm
# only accepts an optional argument attached with `=`).
_NOVALUE_FLAGS=" -h --help --usage -V --version -v --verbose -Q --quiet
  -H --hold -O --overcommit -s --oversubscribe -W --wait --parsable
  --test-only --requeue --no-requeue --contiguous --reboot --spread-job
  --use-min-nodes --ignore-pbs --exclusive --no-kill --get-user-env
  --propagate --nice "
_takes_no_value() {
    [[ "$_NOVALUE_FLAGS" == *[[:space:]]"$1"[[:space:]]* ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wrap=*)
            WRAP_CMD="${1#--wrap=}"
            shift
            ;;
        --wrap)
            WRAP_CMD="${2:-}"
            shift 2
            ;;
        *)
            ALL_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -n "$WRAP_CMD" ]]; then
    # --wrap mode: wrap the command in sandbox.
    # Use printf %q to safely escape the wrap command for shell evaluation.
    _escaped_cmd=$(printf '%q' "$WRAP_CMD")
    exec "$REAL_SBATCH" "${ALL_ARGS[@]}" \
        --wrap="$SANDBOX_EXEC --project-dir $(printf '%q' "$PROJECT_DIR") -- sh -c $_escaped_cmd"

else
    # Script mode: find the job script among the collected arguments.
    SBATCH_FLAGS=()
    SCRIPT_PATH=""
    SCRIPT_ARGS=()
    skip_next=false

    for ((i=0; i<${#ALL_ARGS[@]}; i++)); do
        arg="${ALL_ARGS[$i]}"

        if $skip_next; then
            # This argument is consumed as the previous flag's value
            SBATCH_FLAGS+=("$arg")
            skip_next=false
            continue
        fi

        case "$arg" in
            --*=*)
                # Long option with inline value (e.g., --mem=4G)
                SBATCH_FLAGS+=("$arg")
                ;;
            -[!-]?*)
                # Short option with its value attached (e.g. -pgpu, -N2).
                SBATCH_FLAGS+=("$arg")
                ;;
            -*)
                # Flag that may consume the next argument as its value.
                # If the next arg doesn't start with -, assume it's this
                # flag's value (skips values like "-o output.log" or
                # "-p gpu") — unless the flag is known to take none.
                SBATCH_FLAGS+=("$arg")
                if ! _takes_no_value "$arg" \
                   && [[ $((i+1)) -lt ${#ALL_ARGS[@]} && "${ALL_ARGS[$((i+1))]}" != -* ]]; then
                    skip_next=true
                fi
                ;;
            *)
                # Bare positional argument not consumed as a flag value.
                if [[ -f "$arg" ]]; then
                    SCRIPT_PATH="$arg"
                    SCRIPT_ARGS=("${ALL_ARGS[@]:$((i+1))}")
                    break
                else
                    SBATCH_FLAGS+=("$arg")
                fi
                ;;
        esac
    done

    if [[ -z "$SCRIPT_PATH" ]]; then
        echo "Error: No --wrap command or script specified." >&2
        echo "Usage:" >&2
        echo "  sbatch-sandbox.sh [sbatch-flags] --wrap='command'" >&2
        echo "  sbatch-sandbox.sh [sbatch-flags] script.sh [args]" >&2
        exit 1
    fi

    SCRIPT_PATH="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)/$(basename "$SCRIPT_PATH")"

    # Extract #SBATCH directives from the original script
    SBATCH_DIRECTIVES=$(grep '^#SBATCH' "$SCRIPT_PATH" || true)

    # How to run the script on the compute node. sbatch does not require
    # the script to be executable (it runs it via its #! line), so a
    # non-executable script is started through its interpreter instead of
    # failing with "Permission denied" inside the sandbox.
    RUN_CMD=("$SCRIPT_PATH")
    if [[ ! -x "$SCRIPT_PATH" ]]; then
        _shebang=""
        IFS= read -r _shebang < "$SCRIPT_PATH" || true
        if [[ "$_shebang" == '#!'* ]]; then
            _shebang="${_shebang#\#!}"
            _shebang="${_shebang#"${_shebang%%[![:space:]]*}"}"   # ltrim
            _shebang="${_shebang%"${_shebang##*[![:space:]]}"}"   # rtrim
            _interp="${_shebang%%[[:space:]]*}"
            _iarg="${_shebang#"$_interp"}"
            _iarg="${_iarg#"${_iarg%%[![:space:]]*}"}"
            RUN_CMD=("$_interp")
            # Linux passes everything after the interpreter as ONE argument.
            [[ -n "$_iarg" ]] && RUN_CMD+=("$_iarg")
            RUN_CMD+=("$SCRIPT_PATH")
        else
            RUN_CMD=(/bin/bash "$SCRIPT_PATH")
        fi
    fi

    WRAPPER=$(mktemp "${TMPDIR:-/tmp}/sbatch-sandbox-XXXXXX.sh")
    # Not exec'ing sbatch below, so this trap actually runs. sbatch copies
    # the script at submission; removing it afterwards is safe.
    trap 'rm -f -- "$WRAPPER"' EXIT

    # Use a quoted heredoc to prevent expansion of SBATCH directive
    # contents (defense against $(cmd) in #SBATCH --comment="$(cmd)").
    # Variables for the exec line are written via printf.
    {
        printf '#!/bin/bash --\n'
        printf '%s\n' "$SBATCH_DIRECTIVES"
        printf '\n# --- Sandbox wrapper (auto-generated) ---\n'
        printf 'exec %q --project-dir %q --' "$SANDBOX_EXEC" "$PROJECT_DIR"
        for _sa in "${RUN_CMD[@]}"; do
            printf ' %q' "$_sa"
        done
        for _sa in "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}"; do
            printf ' %q' "$_sa"
        done
        printf '\n'
    } > "$WRAPPER"

    chmod +x "$WRAPPER"
    _rc=0
    "$REAL_SBATCH" "${SBATCH_FLAGS[@]+"${SBATCH_FLAGS[@]}"}" "$WRAPPER" || _rc=$?
    exit "$_rc"
fi
