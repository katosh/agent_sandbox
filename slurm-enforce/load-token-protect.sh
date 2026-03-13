#!/usr/bin/env bash
# load-token-protect.sh — Load the eBPF token protection program
#
# Loads the pre-compiled token_protect.bpf.o, attaches it to the LSM
# file_open hook, and populates the map with the token file's identity.
#
# Usage:
#   sudo ./load-token-protect.sh
#
# Reads TOKEN_FILE from the admin sandbox config or sandbox-wrapper.conf.
#
# For /etc/rc.local or a systemd unit, use an absolute path:
#   /path/to/slurm-enforce/load-token-protect.sh
#
# To recompile first (after editing token_protect.bpf.c), see the build
# commands in slurm-enforce/README.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Admin config path. Change during deployment if using a different location.
_ADMIN_CONF="/opt/claude-sandbox/sandbox.conf"
_ADMIN_DIR="${_ADMIN_CONF%/*}"

# Source config (check: next to script → admin sandbox config)
if [[ -f "$SCRIPT_DIR/sandbox-wrapper.conf" ]]; then
    source "$SCRIPT_DIR/sandbox-wrapper.conf"
elif [[ -f "$_ADMIN_CONF" ]]; then
    source "$_ADMIN_CONF"
fi
TOKEN_FILE="${TOKEN_FILE:-$_ADMIN_DIR/.sandbox-bypass-token}"
BPF_OBJ="$SCRIPT_DIR/token_protect.bpf.o"
BPF_PIN="/sys/fs/bpf/token_protect"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "error: $BPF_OBJ not found — compile first (see slurm-enforce/README.md)" >&2
    exit 1
fi

if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "error: token file not found: $TOKEN_FILE" >&2
    exit 1
fi

if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q bpf; then
    echo "error: 'bpf' not in active LSM list" >&2
    exit 1
fi

# Remove previous program if reloading
[ -e "$BPF_PIN" ] && rm -rf "$BPF_PIN"

# Load and auto-attach to the LSM file_open hook
bpftool prog loadall "$BPF_OBJ" "$BPF_PIN" autoattach

# Populate the map with the token file's device + inode.
# stat(2) uses an old dev_t encoding; the kernel's s_dev uses new_encode_dev.
TOKEN_DEV=$(python3 -c "
import os; st = os.stat('$TOKEN_FILE')
print((os.major(st.st_dev) << 20) | os.minor(st.st_dev))
")
TOKEN_INO=$(stat -c %i "$TOKEN_FILE")
MAP_ID=$(bpftool map show | grep -E 'protected_file' | head -1 | awk '{print $1}' | tr -d ':')
if [[ -z "$MAP_ID" ]]; then
    echo "error: could not find the protected_file map — is the .bpf.o up to date?" >&2
    exit 1
fi

DEV_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_DEV)))")
INO_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
bpftool map update id "$MAP_ID" key 0x00 0x00 0x00 0x00 value $DEV_BYTES $INO_BYTES

# Write a sidecar file so other components can detect stale state.
# If the token file is regenerated (new inode), the wrappers can compare.
echo "$TOKEN_DEV $TOKEN_INO" > "${TOKEN_FILE}.identity"
chmod 0644 "${TOKEN_FILE}.identity"

echo "token_protect: loaded (dev=$TOKEN_DEV ino=$TOKEN_INO file=$TOKEN_FILE)"

# Self-test: verify the eBPF actually blocks token reads for sandboxed
# processes.  Catches misconfiguration (wrong dev encoding, wrong inode,
# program not attached, etc.) at load time rather than in production.
if python3 -c "
import ctypes, sys
# Set no_new_privs (what all sandbox backends do)
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)
try:
    open('$TOKEN_FILE').read()
    sys.exit(1)  # readable = eBPF not working
except PermissionError:
    sys.exit(0)  # blocked = working
" 2>/dev/null; then
    echo "token_protect: self-test PASSED (no_new_privs process blocked)"
else
    echo "ERROR: self-test FAILED — token is readable despite eBPF" >&2
    echo "  The map may have incorrect device/inode values." >&2
    echo "  Map contents:" >&2
    bpftool map dump id "$MAP_ID" 2>&1 | head -10 >&2
    exit 1
fi
