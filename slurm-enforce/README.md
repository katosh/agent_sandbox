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
| `sbatch-token-wrapper.sh` | `/usr/bin/sbatch` | System-wide sbatch wrapper — auto-injects bypass token; strips manual `_SANDBOX_BYPASS` from CLI |
| `srun-token-wrapper.sh` | `/usr/bin/srun` | System-wide srun wrapper — passes through for normal users, wraps in sandbox-exec.sh for sandboxed processes |
| `job_submit.lua` | `/etc/slurm/job_submit.lua` | Slurm job submit plugin — server-side enforcement for sbatch (wraps jobs unless valid token is present) |
| `token_protect.bpf.c` | `/sys/fs/bpf/token_protect` (compiled) | eBPF LSM program — denies read access to the token file for processes with `no_new_privs` set |
| `load-token-protect.sh` | `/etc/rc.local` or systemd unit | Loads the compiled eBPF program and populates its map — run at boot |

## Configuration

Each script has an `_ADMIN_CONF` variable at the top (defaults to `/app/lib/agent-sandbox/sandbox.conf`). This is **not** read from environment variables — an agent could redirect it to a controlled directory. Change the variable during deployment if using a different location.

Config search order (same across all components):

1. `sandbox-wrapper.conf` next to the script (development/testing)
2. `_ADMIN_CONF` path (admin sandbox config)

**If you also deploy [Section 2](../ADMIN_INSTALL.md) (admin-owned sandbox installation),** add the Slurm enforcement variables directly to your admin `sandbox.conf` — one config file drives both the sandbox and the Slurm enforcement layer. See the [example admin config](../ADMIN_INSTALL.md#example-admin-config) for the Slurm variables.

**If you only deploy Section 1,** place `sandbox-wrapper.conf` next to the deployed wrapper scripts or set `_ADMIN_CONF` to point to it.

The key variables (used by all components):

| Variable | Used by | Default |
|---|---|---|
| `TOKEN_FILE` / `SANDBOX_BYPASS_TOKEN` | All components | `$_ADMIN_DIR/.sandbox-bypass-token` |
| `REAL_SBATCH` | sbatch wrapper | `/usr/libexec/slurm/sbatch` |
| `REAL_SRUN` | srun wrapper | `/usr/libexec/slurm/srun` |
| `SANDBOX_EXEC` | srun wrapper, job submit plugin | `$_ADMIN_DIR/sandbox-exec.sh` |

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
instead — e.g. alongside the sandbox install under `/app/lib/agent-sandbox/`.

```bash
# Generate the token
sudo head -c 32 /dev/urandom | base64 > /app/lib/agent-sandbox/.sandbox-bypass-token
sudo chmod 0644 /app/lib/agent-sandbox/.sandbox-bypass-token
```

Set `TOKEN_FILE` (or `SANDBOX_BYPASS_TOKEN`) in your config to the chosen path.

### 2. Build and load the eBPF program

```bash
cd slurm-enforce/

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
```

`load-token-protect.sh` wraps the load + map-update steps:

```bash
# Test it manually first
sudo ./load-token-protect.sh

# Then add to /etc/rc.local or a systemd unit to persist across reboots
```

### 3. Deploy the job submit plugin

```bash
sudo cp job_submit.lua /etc/slurm/job_submit.lua

# Add to slurm.conf:
#   JobSubmitPlugins=lua

sudo scontrol reconfigure
```

### 4. Deploy the Slurm wrappers

Move the real binaries and replace them with the wrappers:

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
at the `REAL_SBATCH`/`REAL_SRUN` paths in the config.

## How it works

### Why a token? Why not just check the process flag?

All sandbox backends set the kernel's `PR_SET_NO_NEW_PRIVS` flag, which is
irreversible and inherited by all descendants. This flag is the ground truth
for "is this process sandboxed?" — but it's a **process-local kernel
property**, not something Slurm can see.

The job submit plugin runs server-side in `slurmctld`, which is a separate
process (often on a different machine). The sbatch client sends job
parameters over an RPC — script, environment variables, resource requests —
but **process-level kernel flags like `no_new_privs` are not part of the
Slurm protocol.** The plugin only sees `job_desc` fields and `submit_uid`;
it has no access to the submitter's process state.

Slurm does have a `cli_filter` plugin that runs client-side (and could check
the flag), but the [Slurm documentation explicitly warns](https://slurm.schedmd.com/cli_filter_plugins.html)
it "must not be relied upon for security purposes" since users can bypass it
with an alternate `slurm.conf`.

This means some form of client-side signal that survives the RPC boundary is
unavoidable. The **token** is that signal — and the **eBPF LSM** makes it
unforgeable: a sandboxed process cannot read the token file, so it cannot
present it to the plugin. Without eBPF protection, the agent could simply
read the token and call the real sbatch directly, bypassing the wrapper.

### Three-layer enforcement

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

Each layer is necessary: the **wrapper** bridges the client-side
`no_new_privs` check to the server-side plugin via the token. The **plugin**
provides server-side enforcement that cannot be bypassed by skipping the
wrapper. The **eBPF** ensures the token is unreadable to sandboxed processes,
so it cannot be forged.

**The result:** users run `sbatch` and `srun` as usual with no workflow
change. The wrappers read the token (eBPF allows it) and either inject it
(sbatch) or pass through (srun). When a sandboxed agent runs these commands,
the wrappers cannot read the token — sbatch submits without it (plugin
sandboxes the job), srun wraps the command in the sandbox directly.

## Logging

The wrappers are silent toward users. All warnings and errors go to **syslog**
(`daemon.*` facility, tags `sandbox-sbatch` / `sandbox-srun`) so admins can
monitor issues without cluttering user-visible output.

| Severity | Condition | Message (excerpt) |
|----------|-----------|-------------------|
| `err` | Wrapper would exec itself (infinite loop) | `sbatch-token-wrapper.sh would exec itself …` |
| `err` | Token file inode changed since eBPF load | `Token file identity changed …` |
| `warning` | eBPF program not loaded | `eBPF token protection not loaded …` |
| `warning` | Token file missing | `TOKEN_FILE not found …` |
| `warning` | `sandbox-exec.sh` not found (srun only) | `SANDBOX_EXEC not found …` |

The only message a user ever sees is `"sbatch: internal configuration error
(see syslog)"` in the infinite-loop case — a misconfiguration that prevents
the job from running at all.

**Viewing logs:**

```bash
# journald
sudo journalctl -t sandbox-sbatch -t sandbox-srun --since "1 hour ago"

# traditional syslog
sudo grep -E 'sandbox-s(batch|run)' /var/log/syslog | tail -20
```

## Verification

No job submission required. The eBPF checks a single kernel property —
`PR_SET_NO_NEW_PRIVS` — which all sandbox backends set. We simulate it
directly with `prctl(38, 1)`. The plugin logs distinguish "bypass token
valid" from "wrapping job".

```bash
# 1. eBPF: normal process can read the token
cat /app/lib/agent-sandbox/.sandbox-bypass-token
# → prints the token

# 2. eBPF: process with no_new_privs cannot (simulates any sandbox backend)
python3 -c "
import ctypes, sys
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)
try:
    open('/app/lib/agent-sandbox/.sandbox-bypass-token').read()
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

## Tested

End-to-end tested on Ubuntu 24.04 (kernel 6.8, Slurm 23.11) with a single-node Slurm cluster (slurmctld + slurmd + slurmdbd + MariaDB):

- **eBPF LSM** — normal processes read the token; `no_new_privs` processes get `EACCES`
- **Job submit plugin** — jobs without token are wrapped; valid `_SANDBOX_BYPASS` passes through; token cleared after validation
- **Combined flow** — verified with bwrap, firejail, and Landlock. Sandboxed jobs show `SANDBOX_ACTIVE=1`, hidden `~/.ssh`, `EACCES` on token file. Unsandboxed jobs see all files normally.
- **Test suite** — 119 passed, 0 failed, 7 skipped (backend-specific features). Admin wrapper tests are dry-run (no job submission).
