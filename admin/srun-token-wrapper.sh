#!/usr/bin/env bash
# srun-token-wrapper.sh — System-wide srun wrapper enforcing sandbox on agent jobs
#
# Replaces /usr/bin/srun (or shadows it via PATH). Tries to read the
# eBPF-protected bypass token:
#   - Token readable  → normal user, exec real srun directly
#   - Token not readable → sandboxed process, wrap command in sandbox-exec.sh
#
# Unlike sbatch (which has a server-side job submit plugin), srun has no
# server-side enforcement. This wrapper is the only defense-in-depth layer
# for srun beyond the in-sandbox PATH shadowing.
#
# Deployment — see sandbox-wrapper.conf for path configuration.
#
#   sudo mkdir -p /usr/libexec/slurm
#   sudo mv /usr/bin/srun /usr/libexec/slurm/srun
#   sudo cp srun-token-wrapper.sh /usr/bin/srun
#   sudo chmod +x /usr/bin/srun
#   sudo cp sandbox-wrapper.conf /etc/slurm/sandbox-wrapper.conf

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Source configuration (check next to script, then /etc/slurm)
if [[ -f "$SCRIPT_DIR/sandbox-wrapper.conf" ]]; then
    source "$SCRIPT_DIR/sandbox-wrapper.conf"
elif [[ -f /etc/slurm/sandbox-wrapper.conf ]]; then
    source /etc/slurm/sandbox-wrapper.conf
fi

# Defaults if not set by config
TOKEN_FILE="${TOKEN_FILE:-/etc/slurm/.sandbox-bypass-token}"
REAL_SRUN="${REAL_SRUN:-/usr/libexec/slurm/srun}"
SANDBOX_EXEC="${SANDBOX_EXEC:-/app/sandbox/sandbox-exec.sh}"

# Fall back to /usr/bin/srun if relocated binary doesn't exist
if [[ ! -x "$REAL_SRUN" ]]; then
    REAL_SRUN=/usr/bin/srun
fi

# Guard against infinite loop: if REAL_SRUN points back to this script
# (e.g., admin forgot to move the real binary), bail out with a clear error.
_self="$(readlink -f "${BASH_SOURCE[0]}")"
_target="$(readlink -f "$REAL_SRUN" 2>/dev/null || echo "")"
if [[ "$_self" == "$_target" ]]; then
    echo "FATAL: srun-token-wrapper.sh would exec itself (infinite loop)." >&2
    echo "  REAL_SRUN=$REAL_SRUN resolves to this script." >&2
    echo "  Did you forget to move the real srun binary?" >&2
    echo "  Expected: sudo mv /usr/bin/srun /usr/libexec/slurm/srun" >&2
    exit 1
fi

# Warn if sandbox-exec.sh is not found (srun wrapper needs it for sandboxing)
if [[ ! -x "$SANDBOX_EXEC" ]]; then
    echo "WARNING: SANDBOX_EXEC not found: $SANDBOX_EXEC" >&2
    echo "  Sandboxed srun commands will fail. Check sandbox-wrapper.conf." >&2
fi

# Runtime check: warn if eBPF token protection is not loaded.
if [[ ! -d /sys/fs/bpf/token_protect ]]; then
    echo "WARNING: eBPF token protection not loaded. Sandbox enforcement is weakened." >&2
    echo "  Run: sudo admin/load-token-protect.sh" >&2
fi

# Inode drift check: warn if the token file's identity has changed.
if [[ -f "${TOKEN_FILE}.identity" && -f "$TOKEN_FILE" ]]; then
    _cur_dev=$(python3 -c "import os; st=os.stat('$TOKEN_FILE'); print((os.major(st.st_dev)<<20)|os.minor(st.st_dev))" 2>/dev/null || echo "")
    _cur_ino=$(stat -c %i "$TOKEN_FILE" 2>/dev/null || echo "")
    _expected=$(cat "${TOKEN_FILE}.identity" 2>/dev/null || echo "")
    if [[ -n "$_cur_dev" && -n "$_cur_ino" && "$_expected" != "$_cur_dev $_cur_ino" ]]; then
        echo "WARNING: Token file identity changed since eBPF was loaded." >&2
        echo "  Re-run: sudo admin/load-token-protect.sh" >&2
    fi
fi

# If already inside a sandbox, just pass through — no need to nest.
if [[ "${SANDBOX_ACTIVE:-}" == "1" ]]; then
    exec "$REAL_SRUN" "$@"
fi

# Try to read the token. Succeeds for normal users, fails for sandboxed
# processes (eBPF returns EACCES when no_new_privs is set).
TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null) || true

if [[ -n "$TOKEN" ]]; then
    # Token readable — normal user. Pass through to real srun unchanged.
    exec "$REAL_SRUN" "$@"
fi

# Token not readable — sandboxed process (but SANDBOX_ACTIVE not set,
# e.g. agent cleared it). Separate srun flags from the user command
# so we can insert sandbox-exec.sh before the command.

# Known srun flags that consume a value argument (through Slurm 24.x).
# Kept in sync with srun-sandbox.sh.
_SRUN_VALUE_FLAGS=" \
  -A --account -c --cpus-per-task -D --chdir -d --dependency \
  -e --error -J --job-name -n --ntasks -N --nodes -o --output \
  -p --partition -t --time -G --gpus -m --distribution -w --nodelist \
  -x --exclude -W --wait \
  --mem --mem-per-cpu --mem-per-gpu --gres --constraint --export \
  --mpi --cpu-bind --gpu-bind --gpus-per-node --gpus-per-task \
  --ntasks-per-node --cpus-per-gpu --signal --switches \
  --threads-per-core --network --begin --nice --priority --qos \
  --reservation --wckey --comment --mail-type --mail-user \
  --cpu-freq --deadline --delay-boot --epilog --prolog \
  --task-epilog --task-prolog --input --kill-on-bad-exit \
  --label --mcs-label --open-mode --profile --propagate \
  --quit-on-interrupt --slurmd-debug --tmp --bcast \
"

_is_value_flag() {
    [[ "$_SRUN_VALUE_FLAGS" == *" $1 "* ]]
}

SRUN_FLAGS=()
USER_CMD=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --)
            shift
            USER_CMD=("$@")
            break
            ;;
        --*=*)
            # Long option with inline value (e.g., --nodes=4)
            SRUN_FLAGS+=("$1")
            shift
            ;;
        -*)
            SRUN_FLAGS+=("$1")
            if [[ "$1" != *=* ]] && _is_value_flag "$1"; then
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
    # No user command — pass through (e.g., srun --pty bash)
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}"
fi

# Wrap the user command in sandbox-exec.sh
PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"
exec "$REAL_SRUN" "${SRUN_FLAGS[@]}" \
    "$SANDBOX_EXEC" --project-dir "$PROJECT_DIR" -- "${USER_CMD[@]}"
