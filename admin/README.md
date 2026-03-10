# Admin Hardening: Enforce Sandbox on Agent-Submitted Slurm Jobs

This directory contains the components for Section 1 of
[ADMIN_HARDENING.md](../ADMIN_HARDENING.md) — system-wide Slurm wrappers
that ensure agent-submitted Slurm jobs stay sandboxed, a job submit plugin for server-side
enforcement, and an eBPF LSM program that protects the bypass token from
sandboxed processes.

End-to-end tested on Ubuntu 24.04 (kernel 6.8, Slurm 23.11, Landlock backend) with a single-node Slurm cluster (slurmctld + slurmd + slurmdbd + MariaDB). All components — eBPF token protection, job submit plugin wrapping, and combined sandbox enforcement flow — verified working.

## Components

| Source | Deploys to | Purpose |
|---|---|---|
| `admin/sandbox-wrapper.conf` | `/etc/slurm/sandbox-wrapper.conf` | Single source of truth — token path, real binary locations, sandbox-exec.sh path |
| `admin/sbatch-token-wrapper.sh` | `/usr/bin/sbatch` | System-wide sbatch wrapper — auto-injects bypass token; strips manual `_SANDBOX_BYPASS` from CLI |
| `admin/srun-token-wrapper.sh` | `/usr/bin/srun` | System-wide srun wrapper — passes through for normal users, wraps in sandbox-exec.sh for sandboxed processes |
| `admin/job_submit.lua` | `/etc/slurm/job_submit.lua` | Slurm job submit plugin — server-side enforcement for sbatch (wraps jobs unless valid token is present) |
| `admin/token_protect.bpf.c` | `/sys/fs/bpf/token_protect` (compiled) | eBPF LSM program — denies read access to the token file for processes with `no_new_privs` set |
| `admin/load-token-protect.sh` | `/etc/rc.local` or systemd unit | Loads the compiled eBPF program and populates its map — run at boot |

## Setup

### Prerequisites

- Slurm with Lua plugin support (`slurm-wlm` on Ubuntu includes it)
- Kernel >= 5.7 with `CONFIG_BPF_LSM=y`
- `bpf` in the active LSM list (add to boot params: `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`)
- Build tools: `clang`, `llvm`, `libbpf-dev`, `bpftool`

### 1. Generate bypass token

The token must be on a **shared filesystem** accessible from both submit
nodes (where the wrappers run) and the controller (where `job_submit.lua`
runs). On clusters where `/etc/slurm/` is node-local, use a shared path
instead — e.g. alongside the sandbox install under `/app`.

Set `TOKEN_FILE` in `sandbox-wrapper.conf` to the chosen path — all other
components (wrappers, plugin, loader script) read it from there.

```bash
# Generate the token at the path configured in sandbox-wrapper.conf:
sudo head -c 32 /dev/urandom | base64 > /app/sandbox/.sandbox-bypass-token
sudo chmod 0644 /app/sandbox/.sandbox-bypass-token
```

### 2. Build and load the eBPF program

```bash
cd admin/

# Generate kernel BTF header and compile
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf \
    -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
    -I. -I/usr/include/bpf \
    -c token_protect.bpf.c -o token_protect.bpf.o

# Load and auto-attach to the LSM file_open hook
# (if reloading after an update, remove the old pins first:)
# [ -e /sys/fs/bpf/token_protect ] && rm -rf /sys/fs/bpf/token_protect
bpftool prog loadall token_protect.bpf.o /sys/fs/bpf/token_protect autoattach

# Tell the program which file to protect.
# Read TOKEN_FILE from sandbox-wrapper.conf (same config the wrappers use):
source /etc/slurm/sandbox-wrapper.conf
# stat(2) uses an old dev_t encoding; the kernel's s_dev uses new_encode_dev:
TOKEN_DEV=$(python3 -c "
import os; st = os.stat('$TOKEN_FILE')
print((os.major(st.st_dev) << 20) | os.minor(st.st_dev))
")
TOKEN_INO=$(stat -c %i "$TOKEN_FILE")
MAP_ID=$(bpftool map show | grep protected_file | head -1 | awk '{print $1}' | tr -d ':')

DEV_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_DEV)))")
INO_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
bpftool map update id $MAP_ID key 0x00 0x00 0x00 0x00 value $DEV_BYTES $INO_BYTES
```

`load-token-protect.sh` wraps the load + map-update steps for use at boot:

```bash
# Test it manually first
sudo ./load-token-protect.sh

# Then add to /etc/rc.local or a systemd unit to persist across reboots
```

### 3. Deploy the job submit plugin

```bash
# Edit SANDBOX_EXEC in job_submit.lua to match your sandbox install path
sudo cp job_submit.lua /etc/slurm/job_submit.lua

# Add to slurm.conf:
#   JobSubmitPlugins=lua

sudo scontrol reconfigure
```

### 4. Configure and deploy the Slurm wrappers

Edit `sandbox-wrapper.conf` to match your environment:

```bash
# Review paths in sandbox-wrapper.conf (all components read from this file):
#   TOKEN_FILE   — path to the bypass token (set in step 1)
#   REAL_SBATCH  — where the real sbatch binary will be moved to
#   REAL_SRUN    — where the real srun binary will be moved to
#   SANDBOX_EXEC — path to sandbox-exec.sh (used by srun wrapper)

sudo cp sandbox-wrapper.conf /etc/slurm/sandbox-wrapper.conf
```

Then deploy the wrappers — move the real binaries and replace them:

```bash
sudo mkdir -p /usr/libexec/slurm
sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch
sudo mv /usr/bin/srun /usr/libexec/slurm/srun
sudo cp sbatch-token-wrapper.sh /usr/bin/sbatch
sudo cp srun-token-wrapper.sh /usr/bin/srun
sudo chmod +x /usr/bin/sbatch /usr/bin/srun
```

This ensures every `sbatch`/`srun` call goes through the wrappers — whether
by name, absolute path, or from scripts. The wrappers find the real binaries
at the `REAL_SBATCH`/`REAL_SRUN` paths configured in `sandbox-wrapper.conf`.

## How it works

The system enforces sandbox on agent-submitted jobs through three layers:

1. **System-wide Slurm wrappers** — replace `/usr/bin/sbatch` and
   `/usr/bin/srun`. Each wrapper tries to read the eBPF-protected token
   file. Normal users can read it; sandboxed processes cannot.

   - **sbatch wrapper:** injects the token as an environment variable (never
     in `/proc/*/cmdline`) → the job submit plugin lets the job through. Any
     `_SANDBOX_BYPASS` in `--export=` flags is stripped.
   - **srun wrapper:** token readable → exec real srun directly (no
     sandboxing). Token not readable → wraps the command in
     `sandbox-exec.sh`.

2. **Slurm job submit plugin** (`job_submit.lua`) — server-side enforcement
   for sbatch. Every batch job is wrapped in `sandbox-exec.sh` unless a
   valid `_SANDBOX_BYPASS` token is present in the job environment. The
   token is cleared after validation so it doesn't leak to the compute node.

3. **eBPF LSM** (`token_protect.bpf.c`) — prevents sandboxed processes from
   reading the token file. All sandbox backends set `PR_SET_NO_NEW_PRIVS`,
   so any process inside the sandbox gets `EACCES` when opening the token.

**The result:** users run `sbatch` and `srun` as usual with no workflow
change. The wrappers read the token (eBPF allows it) and either inject it
(sbatch) or pass through (srun). When a sandboxed agent runs these commands,
the wrappers cannot read the token — sbatch submits without it (plugin
sandboxes the job), srun wraps the command in the sandbox directly.

## Verification

No job submission required. The eBPF checks a single kernel property —
`PR_SET_NO_NEW_PRIVS` — which all sandbox backends set. We simulate it
directly with `prctl(38, 1)`. The plugin logs distinguish "bypass token
valid" from "wrapping job".

```bash
source /etc/slurm/sandbox-wrapper.conf

# 1. eBPF: normal process can read the token
cat "$TOKEN_FILE"
# → prints the token

# 2. eBPF: process with no_new_privs cannot (simulates any sandbox backend)
python3 -c "
import ctypes, sys
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)
try:
    open('$TOKEN_FILE').read()
    print('FAIL: token was readable', file=sys.stderr); sys.exit(1)
except PermissionError:
    print('OK: eBPF blocked read (EACCES)')
"

# 3. Normal user sbatch: plugin sees valid token (--test-only, no queuing)
sbatch --test-only --wrap='echo hello'
sudo grep 'job_submit/sandbox' /var/log/slurm/slurmctld.log | tail -1
# → "bypass token valid"

# 4. Simulated sandboxed sbatch: plugin wraps the job
python3 -c "
import ctypes, subprocess
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)
subprocess.run(['sbatch', '--test-only', '--wrap=echo hello'])
"
sudo grep 'job_submit/sandbox' /var/log/slurm/slurmctld.log | tail -1
# → "wrapping job from uid ..."

# 5. srun works normally for non-sandboxed users
srun --help | head -1
# → shows real srun help (wrapper passed through)
```
