#!/usr/bin/env bash
# sbatch-token-wrapper.sh — System-wide sbatch wrapper enforcing sandbox on agent jobs
#
# Replaces /usr/bin/sbatch (or shadows it via PATH). Reads the eBPF-
# protected bypass token and injects it as an environment variable so
# the job submit plugin lets the job through unsandboxed. Sandboxed
# processes cannot read the token, so the plugin sandboxes their jobs.
#
# The token is never passed as a CLI argument (invisible in /proc/*/cmdline).
# Any _SANDBOX_BYPASS in --export= flags is stripped.
#
# Deployment — see sandbox-wrapper.conf for path configuration.
#
#   sudo mkdir -p /usr/libexec/slurm
#   sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch
#   sudo cp sbatch-token-wrapper.sh /usr/bin/sbatch
#   sudo chmod +x /usr/bin/sbatch
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
REAL_SBATCH="${REAL_SBATCH:-/usr/libexec/slurm/sbatch}"

# Fall back to /usr/bin/sbatch if relocated binary doesn't exist
if [[ ! -x "$REAL_SBATCH" ]]; then
    REAL_SBATCH=/usr/bin/sbatch
fi

# Guard against infinite loop: if REAL_SBATCH points back to this script
# (e.g., admin forgot to move the real binary), bail out with a clear error.
_self="$(readlink -f "${BASH_SOURCE[0]}")"
_target="$(readlink -f "$REAL_SBATCH" 2>/dev/null || echo "")"
if [[ "$_self" == "$_target" ]]; then
    echo "FATAL: sbatch-token-wrapper.sh would exec itself (infinite loop)." >&2
    echo "  REAL_SBATCH=$REAL_SBATCH resolves to this script." >&2
    echo "  Did you forget to move the real sbatch binary?" >&2
    echo "  Expected: sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch" >&2
    exit 1
fi

# Strip any _SANDBOX_BYPASS from --export flags (prevent manual injection
# via command line, which would be visible in the process table).
# Handles both --export=VAL and --export VAL (space-separated) forms.
_strip_bypass() {
    local val="$1"
    val=$(echo "$val" | sed 's/,\?_SANDBOX_BYPASS=[^,]*//g' | sed 's/^,//')
    echo "$val"
}

ARGS=()
_next_is_export=false
for arg in "$@"; do
    if $_next_is_export; then
        _next_is_export=false
        _cleaned=$(_strip_bypass "$arg")
        if [[ -n "$_cleaned" ]]; then
            ARGS+=("--export=$_cleaned")
        fi
        continue
    fi
    case "$arg" in
        --export=*)
            _cleaned=$(_strip_bypass "${arg#--export=}")
            if [[ -n "$_cleaned" ]]; then
                ARGS+=("--export=$_cleaned")
            fi
            ;;
        --export)
            _next_is_export=true
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

# Clear any _SANDBOX_BYPASS from the inherited environment
unset _SANDBOX_BYPASS

# Runtime check: warn if eBPF token protection is not loaded.
# Without it, sandboxed processes can read the token and bypass enforcement.
if [[ ! -d /sys/fs/bpf/token_protect ]]; then
    echo "WARNING: eBPF token protection not loaded. Sandbox enforcement is weakened." >&2
    echo "  Run: sudo slurm-enforce/load-token-protect.sh" >&2
fi

# Inode drift check: warn if the token file's identity has changed since
# the eBPF program was loaded (e.g., token was regenerated).
if [[ -f "${TOKEN_FILE}.identity" && -f "$TOKEN_FILE" ]]; then
    _cur_dev=$(python3 -c "import os,sys; st=os.stat(sys.argv[1]); print((os.major(st.st_dev)<<20)|os.minor(st.st_dev))" "$TOKEN_FILE" 2>/dev/null || echo "")
    _cur_ino=$(stat -c %i "$TOKEN_FILE" 2>/dev/null || echo "")
    _expected=$(cat "${TOKEN_FILE}.identity" 2>/dev/null || echo "")
    if [[ -n "$_cur_dev" && -n "$_cur_ino" && "$_expected" != "$_cur_dev $_cur_ino" ]]; then
        echo "FATAL: Token file identity changed since eBPF was loaded." >&2
        echo "  eBPF protects the old inode, not the current file." >&2
        echo "  Re-run: sudo slurm-enforce/load-token-protect.sh" >&2
        exit 1
    fi
fi

# Try to read the token. Succeeds for normal users, fails for sandboxed
# processes (eBPF returns EACCES when no_new_privs is set).
TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null) || true

if [[ -n "$TOKEN" ]]; then
    export _SANDBOX_BYPASS="$TOKEN"
fi

exec "$REAL_SBATCH" "${ARGS[@]}"
