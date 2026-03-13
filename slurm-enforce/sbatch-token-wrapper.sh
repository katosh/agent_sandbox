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
# Deployment:
#   sudo mkdir -p /usr/libexec/slurm
#   sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch
#   sudo cp sbatch-token-wrapper.sh /usr/bin/sbatch
#   sudo chmod +x /usr/bin/sbatch
#
# Config: sandbox-wrapper.conf, or the admin sandbox config (one file
# for both sandbox + Slurm enforcement). Change _ADMIN_CONF below if
# the admin sandbox is installed to a different path.

set -euo pipefail

# Log to syslog (daemon.warning) so admins see issues without confusing users.
# Falls back to stderr only if logger is unavailable.
_log() {
    local level="$1"; shift
    logger -t sandbox-sbatch -p "daemon.${level}" -- "$*" 2>/dev/null || true
}

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Admin config path. Change during deployment if using a different location.
# Not read from environment (an agent could redirect it to a controlled dir).
_ADMIN_CONF="/app/lib/agent-sandbox/sandbox.conf"
_ADMIN_DIR="${_ADMIN_CONF%/*}"

# Clear env vars an agent could pre-set to influence config defaults
unset TOKEN_FILE SANDBOX_BYPASS_TOKEN

# Source configuration (check: next to script → admin sandbox config)
if [[ -f "$SCRIPT_DIR/sandbox-wrapper.conf" ]]; then
    source "$SCRIPT_DIR/sandbox-wrapper.conf"
elif [[ -f "$_ADMIN_CONF" ]]; then
    source "$_ADMIN_CONF"
fi

# Defaults if not set by config
TOKEN_FILE="${TOKEN_FILE:-$_ADMIN_DIR/.sandbox-bypass-token}"
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
    _log err "FATAL: sbatch-token-wrapper.sh would exec itself (REAL_SBATCH=$REAL_SBATCH). Move the real binary: sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch"
    echo "sbatch: internal configuration error (see syslog)" >&2
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

# Skip eBPF and identity checks inside a sandbox — mount namespaces change
# device/inode numbers, causing false positives. Inside the sandbox, the
# eBPF + filesystem hiding already prevent token reads; these checks are
# only useful on the host.
if [[ "${SANDBOX_ACTIVE:-}" != "1" ]]; then
    # Runtime check: warn if eBPF token protection is not loaded.
    if [[ ! -d /sys/fs/bpf/token_protect ]]; then
        _log warning "eBPF token protection not loaded — sandbox enforcement weakened. Run: sudo slurm-enforce/load-token-protect.sh"
    fi

    # Inode drift check: token file regenerated but eBPF map not updated.
    if [[ -f "${TOKEN_FILE}.identity" && -f "$TOKEN_FILE" ]]; then
        _cur_dev=$(python3 -c "import os,sys; st=os.stat(sys.argv[1]); print((os.major(st.st_dev)<<20)|os.minor(st.st_dev))" "$TOKEN_FILE" 2>/dev/null || echo "")
        _cur_ino=$(stat -c %i "$TOKEN_FILE" 2>/dev/null || echo "")
        _expected=$(cat "${TOKEN_FILE}.identity" 2>/dev/null || echo "")
        if [[ -n "$_cur_dev" && -n "$_cur_ino" && "$_expected" != "$_cur_dev $_cur_ino" ]]; then
            _log err "Token file identity changed since eBPF was loaded (expected: $_expected, got: $_cur_dev $_cur_ino). Re-run: sudo slurm-enforce/load-token-protect.sh"
            # Don't exit — still submit the job. The eBPF protects the old
            # inode; the new token is unprotected but jobs still work.
        fi
    fi
fi

# Token file missing — all jobs will be sandboxed (log, don't tell user)
if [[ ! -f "$TOKEN_FILE" ]]; then
    _log warning "TOKEN_FILE not found: $TOKEN_FILE — all jobs will be sandboxed"
fi

# Try to read the token. Succeeds for normal users, fails for sandboxed
# processes (eBPF returns EACCES when no_new_privs is set).
TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null) || true

if [[ -n "$TOKEN" ]]; then
    export _SANDBOX_BYPASS="$TOKEN"
fi

exec "$REAL_SBATCH" "${ARGS[@]}"
