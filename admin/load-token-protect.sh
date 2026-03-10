#!/usr/bin/env bash
# load-token-protect.sh — Load the eBPF token protection program
#
# Loads the pre-compiled token_protect.bpf.o, attaches it to the LSM
# file_open hook, and populates the map with the token file's identity.
#
# Usage:
#   sudo ./load-token-protect.sh [TOKEN_FILE]
#
# TOKEN_FILE defaults to /etc/slurm/.sandbox-bypass-token.
#
# For /etc/rc.local or a systemd unit, use an absolute path:
#   /path/to/admin/load-token-protect.sh
#
# To recompile first (after editing token_protect.bpf.c), see the build
# commands in admin/README.md.

set -euo pipefail

TOKEN_FILE="${1:-/etc/slurm/.sandbox-bypass-token}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BPF_OBJ="$SCRIPT_DIR/token_protect.bpf.o"
BPF_PIN="/sys/fs/bpf/token_protect"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

if [[ ! -f "$BPF_OBJ" ]]; then
    echo "error: $BPF_OBJ not found — compile first (see admin/README.md)" >&2
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
MAP_ID=$(bpftool map show | grep protected_file | head -1 | awk '{print $1}' | tr -d ':')

DEV_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_DEV)))")
INO_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
bpftool map update id "$MAP_ID" key 0x00 0x00 0x00 0x00 value $DEV_BYTES $INO_BYTES

echo "token_protect: loaded (dev=$TOKEN_DEV ino=$TOKEN_INO file=$TOKEN_FILE)"
