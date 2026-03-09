# Admin Hardening: Sandbox-by-Default Slurm Submission

This directory contains the components for Section 1 of
[ADMIN_HARDENING.md](../ADMIN_HARDENING.md) — a Slurm job submit plugin
that sandboxes all jobs by default, with an eBPF LSM program that protects
the bypass token from sandboxed processes.

Tested on Ubuntu 24.04 (kernel 6.8, Slurm 23.11, Landlock backend).

## Components

| File | Purpose |
|---|---|
| `job_submit.lua` | Slurm job submit plugin — wraps jobs in `sandbox-exec.sh` unless a valid bypass token is provided |
| `token_protect.bpf.c` | eBPF LSM program — denies read access to the token file for processes with `no_new_privs` set |

## Setup

### Prerequisites

- Slurm with Lua plugin support (`slurm-wlm` on Ubuntu includes it)
- Kernel >= 5.7 with `CONFIG_BPF_LSM=y`
- `bpf` in the active LSM list (add to boot params: `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`)
- Build tools: `clang`, `llvm`, `libbpf-dev`, `bpftool`

### 1. Generate bypass token

```bash
sudo head -c 32 /dev/urandom | base64 > /etc/slurm/.sandbox-bypass-token
sudo chmod 0644 /etc/slurm/.sandbox-bypass-token
```

### 2. Deploy the job submit plugin

```bash
# Edit SANDBOX_EXEC in job_submit.lua to match your sandbox install path
sudo cp job_submit.lua /etc/slurm/job_submit.lua

# Add to slurm.conf:
#   JobSubmitPlugins=lua

sudo scontrol reconfigure
```

### 3. Build and load the eBPF program

```bash
# Generate BTF header
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile (adjust -D__TARGET_ARCH_ for your platform)
clang -g -O2 -target bpf -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
    -I. -I/usr/include/bpf \
    -c token_protect.bpf.c -o token_protect.bpf.o

# Load and auto-attach to the LSM file_open hook
sudo bpftool prog loadall token_protect.bpf.o /sys/fs/bpf/token_protect autoattach

# Set the protected inode
TOKEN_INO=$(stat -c %i /etc/slurm/.sandbox-bypass-token)
MAP_ID=$(sudo bpftool map show | grep protected_inode | awk '{print $1}' | tr -d ':')
BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
sudo bpftool map update id $MAP_ID key 0x00 0x00 0x00 0x00 value $BYTES
```

To persist across reboots, add the load/attach commands to a systemd unit or
`/etc/rc.local`.

## Verification

```bash
# Normal process can read the token
cat /etc/slurm/.sandbox-bypass-token  # should succeed

# Process with no_new_privs cannot
python3 -c "
import ctypes
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
open('/etc/slurm/.sandbox-bypass-token').read()
"  # should raise PermissionError

# Job without token gets sandboxed
sbatch --wrap='echo test'  # plugin prepends sandbox-exec.sh

# Job with valid token runs unsandboxed
TOKEN=$(cat /etc/slurm/.sandbox-bypass-token)
sbatch --export=ALL,_SANDBOX_BYPASS="$TOKEN" --wrap='echo test'
```
