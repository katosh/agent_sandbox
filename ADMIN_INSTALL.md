# Admin-Owned Sandbox Installation

An admin-owned installation solves two problems:

1. **Sandbox self-protection** — scripts are tamper-proof (the agent can't write to admin-owned paths). Without this, an agent could modify sandbox scripts to weaken future sessions. The current session is always safe (kernel rules are irrevocable once applied), but future sessions and submitted Slurm jobs are at risk.
2. **Policy enforcement** — the admin sets a security baseline that users cannot weaken. Users can customize within bounds (add data mounts, extra blocked paths) but cannot remove admin-enforced protections.

## Quick Setup

```bash
# 1. Install scripts to a root-owned path
sudo cp -r agent_sandbox /opt/claude-sandbox
sudo chown -R root:root /opt/claude-sandbox
sudo chmod -R 755 /opt/claude-sandbox

# 2. Edit the admin config
sudo $EDITOR /opt/claude-sandbox/sandbox.conf

# 3. Users symlink to the admin-managed copy
ln -sf /opt/claude-sandbox ~/.claude/sandbox
```

Users get sandboxing without managing or misconfiguring policy. The agent cannot tamper with the scripts, `sandbox.conf`, or Slurm wrappers — even across sessions. The `CLAUDE.md` and `settings.json` overlays are not affected — they live in a per-session config directory (`CLAUDE_CONFIG_DIR`) rebuilt on each sandbox start from the user's real `~/.claude/` config.

## Config Hierarchy

The sandbox loads config in layers, each adding to the previous:

```
1. Defaults           (built into sandbox-lib.sh)
2. Admin config       (/opt/claude-sandbox/sandbox.conf)     ← security baseline
3. User config        (~/.claude/sandbox/user.conf)          ← additive customization
4. Per-project config (conf.d/*.conf)                        ← project-specific additions
```

Without an admin config at `/opt/claude-sandbox/sandbox.conf`, the sandbox loads a single `sandbox.conf` from `$SANDBOX_DIR` — identical to the user-only install.

### What users can customize

| Setting | User can add entries | User can remove admin entries |
|---|---|---|
| `READONLY_MOUNTS` | Yes — mount more data read-only | N/A (additive) |
| `EXTRA_WRITABLE_PATHS` | Yes — add writable directories | N/A (additive) |
| `HOME_READONLY` | Yes — expose more dotfiles | N/A (additive) |
| `HOME_WRITABLE` | Yes (but not items in admin's `HOME_READONLY`) | N/A (additive) |
| `BLOCKED_FILES` | Yes — block more files | **No — hard error** |
| `BLOCKED_ENV_VARS` | Yes — block more env vars | **No — hard error** |
| `EXTRA_BLOCKED_PATHS` | Yes — block more paths | **No — hard error** |
| `PRIVATE_TMP` | Yes | Yes |
| `BIND_DEV_PTS` | Yes | Yes |
| `FILTER_PASSWD` | Yes | Yes |
| `SANDBOX_BACKEND` | Yes | Yes |

### Post-merge validation

After loading each config layer, the sandbox validates that all admin-enforced entries are still present. If a user or project config removes an admin entry or escalates a read-only path to writable, the sandbox **refuses to start** with a clear error:

```
Error: User config violates admin-enforced security policy:
  - BLOCKED_ENV_VARS: admin entry 'GITHUB_TOKEN' was removed
  - HOME_READONLY→HOME_WRITABLE: admin read-only entry '.gnupg' moved to writable

Admin config: /opt/claude-sandbox/sandbox.conf
User config:  /home/alice/.claude/sandbox/user.conf
```

A hard error (not a warning) is necessary — if the admin blocked a path for security reasons, silently allowing a user to unblock it would defeat the purpose.

## Example Admin Config

The admin config at `/opt/claude-sandbox/sandbox.conf` sets the security baseline. It uses the same format as the standard `sandbox.conf`:

```bash
# /opt/claude-sandbox/sandbox.conf — Admin security baseline
# Users can ADD to these arrays via ~/.claude/sandbox/user.conf
# but CANNOT remove entries set here.

ALLOWED_PROJECT_PARENTS=(
    "/fh/fast"
    "/fh/scratch"
    "$HOME"
)

READONLY_MOUNTS=(
    "/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc"
    "/app"
)

# These entries are enforced — users cannot remove them
BLOCKED_FILES=(
    ".claude/settings.json"
)

BLOCKED_ENV_VARS=(
    "GITHUB_PAT" "GITHUB_TOKEN" "GH_TOKEN"
    "OPENAI_API_KEY" "ANTHROPIC_API_KEY"
    "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"
)

EXTRA_BLOCKED_PATHS=(
    "/fh/fast/mylab/clinical_restricted"
)

HOME_READONLY=(
    ".bashrc" ".bash_profile" ".profile"
    ".gitconfig"
    ".linuxbrew"
)

HOME_WRITABLE=(
    ".claude"
    ".claude.json"
)

PRIVATE_TMP=true
FILTER_PASSWD=true
```

## Example User Config

Users create `~/.claude/sandbox/user.conf` to add project-specific mounts and tools:

```bash
# ~/.claude/sandbox/user.conf — User customization
# Adds to admin baseline. Cannot remove admin-enforced entries.

# Additional data I need
READONLY_MOUNTS+=(
    "/shared/reference_genomes"
)

# My editor config
HOME_READONLY+=(
    ".vimrc"
    ".vim"
)

# Extra scratch space
EXTRA_WRITABLE_PATHS+=(
    "/fh/scratch/delete30/mylab/pipeline-output"
)
```

Note the `+=` syntax — this appends to the admin's arrays. Using `=()` to replace an enforced array triggers a validation error.

## Per-Project Overrides

Per-project configs in `conf.d/*.conf` work the same way as in user-only installs. In an admin-owned installation, the `conf.d/` directory is at `/opt/claude-sandbox/conf.d/` and is admin-controlled.

Users can request the admin to add project-specific overrides, or the admin can create configs that conditionally activate based on project path:

```bash
# /opt/claude-sandbox/conf.d/genomics.conf
[[ "$_PROJECT_DIR" == /fh/fast/mylab/genomics/* ]] || return 0

READONLY_MOUNTS+=(
    "/fh/fast/shared/reference_genomes"
)
EXTRA_WRITABLE_PATHS+=(
    "/fh/scratch/delete30/mylab/pipeline-output"
)
```

These configs also go through admin enforcement validation — they cannot remove admin-set entries.

---

## Choosing a Backend on Ubuntu 24.04+

On Ubuntu 24.04+, AppArmor blocks unprivileged user namespaces, so bwrap doesn't work out of the box. The admin has three options:

| Option | Effort | Result |
|---|---|---|
| **Enable bwrap via AppArmor** | Low | Strongest backend — mount namespace, PID namespace, `/tmp` isolation, self-protection |
| **Install firejail** | Low | Strong — setuid binary bypasses AppArmor; mount namespace, PID namespace, seccomp |
| **Do nothing** | None | Sandbox falls back to Landlock (weakest — see [Landlock fallback](#landlock-fallback) below) |

**Recommendation:** Enable bwrap. It provides the strongest isolation, is fully unprivileged (no setuid binary on the system), and has a significantly better security track record (4 CVEs with zero root exploits vs firejail's 18 CVEs with 12 root exploits). Firejail is a fallback if bwrap's AppArmor profile is not desired, but installing it adds a setuid-root binary to every node. See the [full CVE comparison](APPTAINER_COMPARISON.md#security-track-record) for details.

### Enabling bwrap via AppArmor profile

Create an AppArmor profile that allows bwrap to create user namespaces:

```bash
# Find bwrap path (may be /usr/bin/bwrap or ~/.linuxbrew/bin/bwrap)
BWRAP_PATH=$(command -v bwrap)

cat > /etc/apparmor.d/bwrap-sandbox << EOF
abi <abi/4.0>,
include <tunables/global>

profile bwrap $BWRAP_PATH flags=(unconfined) {
  userns,
}
EOF

apparmor_parser -r /etc/apparmor.d/bwrap-sandbox
```

This allows bwrap (and only bwrap) to create user namespaces. Other programs remain restricted. The profile survives reboots. Verify with:

```bash
# As a regular user — should work after the profile is loaded
bwrap --ro-bind / / -- id
```

The sandbox auto-detects bwrap from `$PATH`, or admins can set `BWRAP=/path/to/bwrap` in `sandbox.conf` to pin a specific binary. Without admin intervention, users can install bwrap themselves via [Homebrew](https://brew.sh/) (`brew install bubblewrap`), which places it at `~/.linuxbrew/bin/bwrap`.

**Hardening note:** The AppArmor profile grants `userns` permission only to the binary at the exact path specified. If the admin installs bwrap to a controlled location and uses that path in the profile, users cannot gain user namespace access by compiling or installing their own copy elsewhere. This is stronger than per-user Homebrew installs, where each user controls the binary.

### Firejail backend (alternative to bwrap)

[Firejail](https://firejail.wordpress.com/) installs **setuid root**, so it can create mount namespaces regardless of AppArmor settings. The sandbox auto-detects firejail when bwrap is unavailable (priority: bwrap > firejail > landlock).

```bash
# 1. Install firejail
sudo apt install firejail

# 2. The sandbox auto-detects firejail — no user config needed.
#    Force firejail for testing:
SANDBOX_BACKEND=firejail ./sandbox-exec.sh -- bash
```

The sandbox uses `--allusers` to disable firejail's built-in `/etc/passwd` filtering, which would otherwise remove UIDs >= `UID_MIN` (typically 1000) and break Slurm if the `slurm` user has a UID in that range. User enumeration prevention is handled separately by `FILTER_PASSWD=true` (default), which blocks NSS daemon sockets to prevent LDAP/AD enumeration. **Caveat:** on LDAP/AD clusters where the current user exists only in LDAP (not in local `/etc/passwd`), `FILTER_PASSWD=true` breaks user resolution and should be set to `false`. The bwrap backend handles LDAP users correctly via `/etc/passwd` overlay.

**`/tmp` isolation** (`--private-tmp`): Enabled by default. Breaks MPI shared-memory transport (OpenMPI, MPICH) and NCCL inter-GPU sockets. Set `PRIVATE_TMP=false` in `sandbox.conf` for multi-rank MPI or multi-GPU workloads.

**Supplementary groups**: Preserved (no `--nogroups`). HPC file access relies on supplementary groups for lab data directories.

### bwrap vs firejail comparison

| Capability | bwrap | firejail |
|---|---|---|
| Privilege model | Unprivileged (user namespaces) | Setuid root binary |
| Mount namespace | ✓ | ✓ |
| PID namespace | ✓ | ✓ |
| `/tmp` isolation | ✓ (`--tmpfs /tmp`) | ✓ (`--private-tmp`) |
| Sandbox self-protection | ✓ (scripts read-only via bind mount) | ✓ (scripts hidden via mount namespace) |
| User enumeration filtering | ✓ (overlays `/etc/passwd` + `nsswitch.conf`, LDAP-safe) | Partial (blacklists NSS sockets, but breaks LDAP-only users) |
| Slurm binary relocation | ✓ (overlays `/usr/bin/sbatch` with redirector) | PATH-based only (no overlay) |
| Seccomp | Supported ([see below](#seccomp-for-bwrap)) | Built-in (`--seccomp` + `--caps.drop=all`) |
| Internal state exposure | None | `/run/firejail/mnt/seccomp/` readable (reveals BPF filter) |
| Attack surface | Minimal, no setuid | Setuid root binary on every node |
| CVE history | [4 CVEs](https://www.opencve.io/cve?search=bubblewrap), 0 root exploits, none since 2020 | [18 CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html), 12 local root exploits ([details](APPTAINER_COMPARISON.md#firejail-18-cves-12-are-local-root)) |
| AppArmor on Ubuntu 24.04+ | Requires admin AppArmor profile | Works without admin action |

---

## Seccomp Filter — HPC Compatibility

The Landlock and firejail backends include seccomp filters that block dangerous syscalls. bwrap does not include one by default but supports loading a custom BPF filter via `--seccomp FD`.

### What is blocked

The filters block `io_uring`, `userfaultfd`, and `kexec_load`/`kexec_file_load`. The `io_uring` block provides the main security value — it has a [large kernel attack surface](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html) and [Docker's default seccomp profile](https://github.com/moby/moby/pull/46762) blocks it since version 25.0.

| Tool | Uses `io_uring` | When blocked | Impact |
|---|---|---|---|
| [Node.js](https://nodejs.org/) / libuv | Yes — async file I/O ([libuv PR #3952](https://github.com/libuv/libuv/pull/3952)) | Falls back to epoll + threadpool | None — transparent fallback |
| [RocksDB](https://rocksdb.org/) | Yes — parallel SST reads ([io_posix.cc](https://github.com/facebook/rocksdb/blob/main/env/io_posix.cc)) | Falls back to synchronous `pread` | Minor — slightly slower bulk reads |
| [QEMU](https://www.qemu.org/) | Yes — block I/O backend ([block/io_uring.c](https://github.com/QEMU/qemu/blob/master/block/io_uring.c)) | Falls back to `aio=threads` | Minor — slightly slower disk I/O |
| Rust [tokio-uring](https://github.com/tokio-rs/tokio-uring) | Yes — io_uring-only runtime ([io-uring crate](https://github.com/tokio-rs/io-uring)) | **No fallback — fails** | **Breaking** — but standard tokio (epoll) is unaffected |
| DuckDB, SQLite | No | — | None |

`userfaultfd` lets a process intercept page faults in userspace, pausing the faulting kernel thread indefinitely. Attackers exploit this to create arbitrary-width race windows for TOCTOU and use-after-free exploits (e.g. [CVE-2021-22555](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22555), [CVE-2024-1086](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1086)). [Docker blocks it](https://github.com/moby/moby/commit/96896f2d), and the kernel restricts unprivileged access by default since 5.11 (`vm.unprivileged_userfaultfd=0`). No HPC tools use it — only QEMU postcopy live migration and CRIU lazy restore are affected, both of which fall back gracefully.

### What is intentionally allowed

| Syscall | Used by | Security risk (accepted) |
|---|---|---|
| `memfd_create` | [CUDA](https://developer.nvidia.com/cuda-toolkit) / [ROCm](https://rocm.docs.amd.com/) GPU drivers, [PyTorch](https://github.com/pytorch/pytorch/blob/main/aten/src/ATen/MapAllocator.cpp) shared memory, [Numba](https://numba.pydata.org/) JIT, [JAX](https://github.com/jax-ml/jax)/[XLA](https://openxla.org/xla) compiler, [OpenJDK ZGC](https://github.com/openjdk/jdk/blob/master/src/hotspot/os/linux/gc/z/zPhysicalMemoryBacking_linux.cpp) | Anonymous executable memory regions |
| `process_vm_readv/writev` | [OpenMPI](https://github.com/open-mpi/ompi/blob/main/opal/mca/smsc/cma/smsc_cma_module.c) CMA transport, [strace](https://github.com/strace/strace), [gdb](https://sourceware.org/gdb/) | Cross-process memory access (mitigated by PID namespace in bwrap/firejail) |

Blocking `memfd_create` would silently break CUDA, PyTorch DataLoader, Numba, and JAX/XLA. Docker's default seccomp profile also [allows it](https://github.com/moby/profiles/blob/main/seccomp/default.json). Blocking `process_vm_readv` would break MPI CMA shared-memory transport (Docker [allows it on kernel >= 4.8](https://github.com/moby/moby/commit/dca15781)). The filesystem sandbox remains the primary isolation mechanism; seccomp is defense-in-depth.

### Seccomp for bwrap

bwrap's mount namespace + PID namespace + `no_new_privs` already provide strong containment. A seccomp filter closes two remaining gaps:

| Syscall | Already mitigated by | Impact of blocking |
|---|---|---|
| `io_uring_setup` / `io_uring_enter` | Nothing — real attack surface reduction | Node.js falls back to epoll, RocksDB falls back to `pread`. tokio-uring (Rust) would fail, but standard tokio is unaffected |
| `userfaultfd` | Kernel restricts unprivileged use since 5.11, but user-mode faults still allowed | No HPC tools use it |
| `kexec_load` / `kexec_file_load` | `no_new_privs` (requires `CAP_SYS_BOOT`) | None — already ineffective without capabilities |

Adding a seccomp filter to bwrap is reasonable and aligns with Docker's precedent.

---

## Landlock Fallback

If neither bwrap nor firejail is available (e.g. Ubuntu 24.04+ without an AppArmor profile or firejail installed), the sandbox falls back to the Landlock backend. Landlock provides kernel-enforced filesystem isolation but lacks the mount namespace that bwrap and firejail use for stronger containment.

### Gaps compared to bwrap/firejail

| Gap | Impact |
|---|---|
| No mount namespace | Blocked paths return EACCES instead of ENOENT; no file overlays (passwd filtering, Slurm binary relocation) |
| No PID namespace | Host processes visible via `/proc`; agent can read `/proc/PID/environ` of same-UID processes |
| No `/tmp` isolation | Shared host `/tmp` — cross-session data leakage possible |
| No sandbox self-protection | Scripts writable under `~/.claude/` (admin-owned install mitigates this) |
| Unix socket `connect()` not blocked | `systemd-run --user` escape viable (see below) |
| User enumeration (LDAP) | Cannot overlay `/etc/passwd` or block NSS sockets |

### Disable systemd user instances

Landlock cannot block Unix domain socket `connect()` (not available in any Landlock ABI version as of kernel 6.11). A sandboxed process can connect to `/run/user/<UID>/systemd/private` and use `systemd-run --user` to execute commands outside the sandbox. Both bwrap and firejail are unaffected — they replace `/run` with a tmpfs.

**What is affected by disabling:** `gpg-agent` socket activation (users doing GPG signing would need to start `gpg-agent --daemon` manually) and `systemctl --user` commands.

```bash
# Option A: Mask the user@ template service (recommended)
systemctl mask user@.service

# Option B: Limit via logind
# /etc/systemd/logind.conf.d/no-user-sessions.conf
[Login]
UserTasksMax=0
KillUserProcesses=yes
```

Option A prevents the user systemd instance from starting at all. Verify with `systemd-run --user -- id` (should fail with "Failed to connect to bus").

---

## Complementary Hardening

An admin-owned installation pairs with:

- **[Slurm job enforcement](admin/README.md)** — ensures agent-submitted Slurm jobs inherit the sandbox
