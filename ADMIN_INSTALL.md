# Admin-Owned Sandbox Installation

An admin-owned installation solves two problems:

1. **Config protection** — the admin config is tamper-proof (root-owned, outside the user's sandbox dir). The sandbox scripts are also root-owned at `/app/lib/agent-sandbox/`, and `~/.config/agent-sandbox/` contains only user data (config, agent profiles), not scripts. With bwrap/firejail the scripts are additionally read-only inside the sandbox via mount namespace.
2. **Policy enforcement** — the admin sets a security baseline that users cannot weaken. Users can customize within bounds (add data mounts, extra blocked paths) but cannot remove admin-enforced protections.

## Quick Setup

A secure admin installation has two parts: a **root-owned config** (tamper-proof policy) and **protected scripts** (the code that enforces it). A root-owned config alone is not sufficient — if the agent can modify `sandbox-lib.sh`, it can bypass any config.

### Step 1: Install scripts and config

```bash
# Install to the default admin prefix (/app — matches _ADMIN_DIR
# in sandbox-lib.sh). Puts agent-sandbox in /app/bin/ and runtime
# files in /app/lib/agent-sandbox/.
sudo make install PREFIX=/app

# Start from the minimal admin skeleton (not the full user config).
# Only set what you want to ENFORCE — users control everything else.
sudo cp /app/lib/agent-sandbox/sandbox-admin.conf /app/lib/agent-sandbox/sandbox.conf
sudo $EDITOR /app/lib/agent-sandbox/sandbox.conf
```

The install ships three config files:

| File | Purpose |
|---|---|
| `sandbox.conf` | Admin enforcement baseline (replace with `sandbox-admin.conf` skeleton) |
| `sandbox.conf.template` | Full user config, auto-deployed to `~/.config/agent-sandbox/sandbox.conf` on first run. Never modified by admins — ensures users always get the complete documented config. |
| `sandbox-admin.conf` | Minimal skeleton with only enforcement knobs. Copy over `sandbox.conf` to use as admin baseline. |

The Makefile handles directory creation, permissions, and the `agent-sandbox` symlink. If your site uses a different prefix (e.g. `/usr/local`), change `_ADMIN_DIR` in `sandbox-lib.sh` to match.

On first run, users automatically get `sandbox.conf` (from `sandbox.conf.template`) and agent templates (`agent.md`, `settings.json`) in `~/.config/agent-sandbox/`. On upgrade, unmodified copies are silently updated; user-edited files are preserved with a message pointing to the new version. Users customize via `sandbox.conf`, `user.conf`, and `conf.d/*.conf`. Agent overlays run in subshells, so mutations to permission globals are structurally impossible — per-agent profiles cannot bypass admin-enforced policy.

Each agent profile directory (`agents/<name>/`) follows a file contract:

| File | Purpose |
|---|---|
| `config.conf` | **Declarative metadata only** — env vars, auth markers, and paths the agent uses. Read for startup warnings; MUST NOT modify sandbox permissions. |
| `overlay.sh` | Mechanical config merge (e.g., merge `CLAUDE.md`, create `settings.json`) and env-var exports. Runs in a subshell — mutations to permission globals cannot reach the parent. |
| `agent.md` | Sandbox-awareness instructions injected into the agent's context |
| `settings.json` | Agent-specific settings template (optional, agent-dependent) |

**Permissions live in the sandbox configuration layer.** `HOME_WRITABLE`, `HOME_READONLY`, `BLOCKED_FILES`, `BLOCKED_ENV_VARS`, and `ALLOWED_ENV_VARS` are set by the admin config (`/app/lib/agent-sandbox/sandbox.conf`), the user config (`~/.config/agent-sandbox/sandbox.conf` or `user.conf`), and per-project overrides (`conf.d/*.conf`) — each layer adds to the previous. Admin-enforced entries cannot be weakened by user config or by any agent profile.

### What this protects

| Component | bwrap/firejail | Landlock |
|---|---|---|
| **Admin config** (`/app/lib/agent-sandbox/sandbox.conf`) | Protected (root-owned, enforced via subprocess isolation) | Protected (root-owned, enforced via subprocess isolation) |
| **Sandbox scripts** (`sandbox-lib.sh`, backends/) | Protected (root-owned + read-only inside sandbox via mount namespace) | Protected (root-owned at `/app/lib/agent-sandbox/`). `~/.config/agent-sandbox/` contains only user data, not scripts. |
| **User config** (`user.conf`, `conf.d/`) | Cannot weaken admin policy (subprocess isolation + policy merge) | Cannot weaken admin policy (subprocess isolation + policy merge) |

The admin path is set in `_ADMIN_DIR` in `sandbox-lib.sh` (not configurable via environment variable). To use a different path, change this single line. The Slurm enforcement scripts (`slurm-enforce/`) have their own `_ADMIN_CONF` variable at the top of each script for the same reason.

## Config Hierarchy

The sandbox loads config in layers, each adding to the previous:

```
1. Defaults           (built into sandbox-lib.sh)
2. Admin config       (/app/lib/agent-sandbox/sandbox.conf)  ← security baseline (if present)
3. User config        (~/.config/agent-sandbox/user.conf)          ← additive customization
4. Per-project config (~/.config/agent-sandbox/conf.d/*.conf)      ← project-specific additions
```

Without an admin config, the sandbox loads a single `sandbox.conf` from `~/.config/agent-sandbox/`, identical to the user-only install (layers 2 and 3 collapse into one). When an admin config is present but the user has not yet created `user.conf`, the sandbox accepts `~/.config/agent-sandbox/sandbox.conf` as user config — this eases the transition when an admin install is deployed after users have already customized `sandbox.conf`.

### What users can customize

| Setting | User can add entries | User can remove admin entries |
|---|---|---|
| `ALLOWED_PROJECT_PARENTS` | Yes — add project prefixes | N/A (additive) |
| `READONLY_MOUNTS` | Yes — mount more data read-only | N/A (additive) |
| `EXTRA_WRITABLE_PATHS` | Yes — add writable directories (subject to `DENIED_WRITABLE_PATHS`) | N/A (additive) |
| `DENIED_WRITABLE_PATHS` | No | **No — admin-only deny-list** |
| `HOME_READONLY` | Yes — expose more dotfiles | N/A (additive) |
| `HOME_WRITABLE` | Yes (but not items in admin's `HOME_READONLY`) | N/A (additive) |
| `BLOCKED_FILES` | Yes — block more files | **No — restored with warning** |
| `BLOCKED_ENV_VARS` | Yes — block more env vars | **No — restored with warning** |
| `BLOCKED_ENV_PATTERNS` | Yes — add more glob patterns | **No — restored with warning** |
| `EXTRA_BLOCKED_PATHS` | Yes — block more paths | **No — restored with warning** |
| `TOKEN_FILE` / `SANDBOX_BYPASS_TOKEN` | No — would overwrite | **No — restored with warning** |
| `ALLOWED_ENV_VARS` | Yes — unblock specific env vars | N/A (additive) |
| `PRIVATE_TMP` | Yes | Yes |
| `BIND_DEV_PTS` | Yes | Yes |
| `FILTER_PASSWD` | Yes | Yes |
| `SANDBOX_BACKEND` | Yes | Yes |
| `SLURM_SCOPE` | Yes | Yes |
| `HOME_ACCESS` | Yes | Yes |

### Admin enforcement: subprocess isolation + policy merge

User configs (`user.conf`, `conf.d/*.conf`) are loaded in an **isolated subprocess** (`/bin/bash --norc --noprofile`). Only known config variables are extracted via `declare -p` and validated before being applied in the parent. After each untrusted config layer, `_enforce_admin_policy()` compares the resulting values against the admin snapshot, restores admin entries, and merges user additions on top.

This eliminates entire attack classes: function overrides (`source`, `eval`, `builtin`), DEBUG/RETURN traps, `exit`/`return` escapes, IFS manipulation, and background processes — none can escape the subprocess boundary. The merge logic runs in the parent shell, unreachable from user config.

**Enforced arrays** (`BLOCKED_FILES`, `BLOCKED_ENV_VARS`, `BLOCKED_ENV_PATTERNS`, `EXTRA_BLOCKED_PATHS`): admin entries are always present. User additions are preserved, but user removals are undone with a warning:

```
WARNING: User config removed admin-enforced BLOCKED_ENV_VARS entry 'GITHUB_TOKEN' — restored.
```

**HOME_READONLY → HOME_WRITABLE escalation**: if a user config moves an admin read-only entry to writable, the escalation is reverted with a warning:

```
WARNING: User config moved admin HOME_READONLY entry '.gnupg' to HOME_WRITABLE — reverted.
```

**DENIED_WRITABLE_PATHS**: any `EXTRA_WRITABLE_PATHS` entry matching or under a denied path is stripped with a warning:

```
WARNING: User config added EXTRA_WRITABLE_PATHS entry '/etc/cron.d' under denied path '/etc' — removed.
```

## Admin Config Skeleton

The `sandbox-admin.conf` shipped with the install is a minimal starting point. It contains only the enforcement-only knobs (`DENIED_WRITABLE_PATHS`, `BLOCKED_*`, `ALLOWED_PROJECT_PARENTS`, etc.) with commented-out examples. Uncomment and edit what you need.

See [`sandbox-admin.conf`](sandbox-admin.conf) for the full skeleton.

**Environment overrides:** Users can override `SLURM_SCOPE` and `HOME_ACCESS` at launch time without editing any config file: `SLURM_SCOPE=session agent-sandbox claude` or `HOME_ACCESS=tmpwrite agent-sandbox bash`. Environment values take precedence over both admin and user configs.

## Example User Config

Users create `~/.config/agent-sandbox/user.conf` to add project-specific mounts and tools:

```bash
# ~/.config/agent-sandbox/user.conf — User customization
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

Note the `+=` syntax — this appends to the admin's arrays. Using `=()` to replace an enforced array has no effect — the admin values are forcefully re-applied.

## Per-Project Overrides

Per-project configs in `~/.config/agent-sandbox/conf.d/*.conf` are user-controlled and subject to the same post-merge validation as `user.conf` (cannot remove admin-enforced entries).

Example — a project-specific config that conditionally activates based on project path:

```bash
# conf.d/genomics.conf
[[ "$_PROJECT_DIR" == /fh/fast/mylab/genomics/* ]] || return 0

READONLY_MOUNTS+=(
    "/fh/fast/shared/reference_genomes"
)
EXTRA_WRITABLE_PATHS+=(
    "/fh/scratch/delete30/mylab/pipeline-output"
)
```

These configs also run in isolated subprocesses and go through admin enforcement — they cannot remove admin-set entries.

## Chaperon: Slurm Proxy

The chaperon is a zero-trust Slurm proxy that sits between the sandboxed agent and the real Slurm commands. Inside the sandbox, Slurm binaries (`sbatch`, `srun`, `scancel`, `squeue`, etc.) are replaced with stubs that communicate with a chaperon process running outside the sandbox via FIFO IPC. The chaperon validates every request against a flag whitelist, wraps submitted jobs to re-enter the sandbox on compute nodes, and scopes `squeue`/`scancel` to the agent's own jobs.

**Key security properties:**
- Real Slurm binaries are blocked inside the sandbox (bind-mounted to `/dev/null` on bwrap, blacklisted on firejail). Munge socket is blocked on bwrap/firejail. **Landlock: neither Slurm binaries nor munge socket are blocked** — chaperon is fully bypassable (see [Admin Hardening](ADMIN_HARDENING.md) §1)
- Dangerous flags (`--uid`, `--prolog`, `--bcast`, `--container`, `--get-user-env`) are rejected
- Job wrapping: sbatch scripts are inlined via heredoc into a wrapper that calls `sandbox-exec.sh` on the compute node — no temp files on NFS
- Job scoping via `--comment` tags: `squeue`/`scancel` only see jobs submitted by this sandbox session/project (configurable via `SLURM_SCOPE`)
- Scope-widening flags (`squeue --me`, `scancel --all`, `scancel -u <user>`) are silently mapped to "all jobs in your scope" — transparent to the user
- All denials include prompt-injection recovery messages that re-anchor the agent to its instructions

See [CHAPERON.md](CHAPERON.md) for the full protocol, supported commands, and flag whitelists.

## Testing

Two test suites validate the sandbox:

- **`test.sh`** — run on every install to verify backend isolation: filesystem, env blocking, agent overlays, chaperon Slurm proxy (flag validation, job submission, scoped cancel, transparent squeue/scancel, comment tag stripping), security hardening, symlink/hardlink attacks, `/proc` escapes, FD inheritance, signal isolation, TIOCSTI, cgroup/userns restrictions, deterministic isolation, concurrent instances. Tests all available backends (bwrap, firejail, landlock).
- **`test-admin.sh`** — run on admin installs to verify config enforcement: admin entries survive user tampering, `DENIED_WRITABLE_PATHS`, `HOME_READONLY` escalation blocking, scalar protection, `HOME` override resistance, `conf.d` enforcement, subprocess isolation of escape attempts, admin Slurm wrappers. Skips automatically if no admin config is found.

```bash
bash test.sh                          # all backends
bash test.sh --backend bwrap          # single backend
bash test-admin.sh                    # admin enforcement (needs admin config)
bash test-admin.sh --verbose          # show output on failure
```

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

Install bwrap and create an AppArmor profile that allows it to create user namespaces:

```bash
# 1. Install bwrap
sudo apt install bubblewrap

# 2. Create AppArmor profile
BWRAP_PATH=$(command -v bwrap)   # typically /usr/bin/bwrap

cat > /etc/apparmor.d/bwrap-sandbox << EOF
abi <abi/4.0>,
include <tunables/global>

profile bwrap-sandbox $BWRAP_PATH flags=(unconfined) {
  userns,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/bwrap-sandbox
```

This allows bwrap to create user namespaces. Other programs remain restricted. The profile survives reboots. Verify:

```bash
# As a regular user — should work after the profile is loaded
bwrap --ro-bind / / -- id
```

The sandbox auto-detects bwrap from `$PATH`, or admins can set `BWRAP=/path/to/bwrap` in `sandbox.conf` to pin a specific binary. Users can also install bwrap via [Homebrew](https://brew.sh/) (`brew install bubblewrap`) — the AppArmor profile would need to include that path too (`~/.linuxbrew/bin/bwrap`) or a second profile entry.

**Note:** The AppArmor profile grants `userns` to any invocation of bwrap at the profiled path, not just sandbox-initiated ones. This is acceptable — bwrap user namespaces are unprivileged and cannot escalate beyond what the calling user already has access to. The sandbox adds filesystem restrictions on top.

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

**`/tmp` isolation** (`--private-tmp`): Enabled by default for both bwrap and firejail (controlled by `PRIVATE_TMP` in `sandbox.conf`). Breaks MPI shared-memory transport (OpenMPI, MPICH) and NCCL inter-GPU sockets. Set `PRIVATE_TMP=false` in `sandbox.conf` for multi-rank MPI or multi-GPU workloads.

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
| Seccomp | Generated BPF filter (`generate-seccomp.py`) — [see below](#seccomp-for-bwrap) | Built-in (`--seccomp` + `--caps.drop=all`) |
| Internal state exposure | None | `/run/firejail/mnt/seccomp/` readable (reveals BPF filter) |
| Attack surface | Minimal, no setuid | Setuid root binary on every node |
| CVE history | [4 CVEs](https://www.opencve.io/cve?search=bubblewrap), 0 root exploits, none since 2020 | [18 CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html), 12 local root exploits ([details](APPTAINER_COMPARISON.md#firejail-18-cves-12-are-local-root)) |
| Supplementary groups | Display as `nogroup` (user namespace limitation — file perms unaffected) | Correct display (setuid avoids user namespace) |
| AppArmor on Ubuntu 24.04+ | Requires admin AppArmor profile | Works without admin action |

---

## Seccomp Filter — HPC Compatibility

All three backends include seccomp filters that block dangerous syscalls. Firejail and Landlock have built-in filters; bwrap loads a generated BPF filter via `--seccomp FD` (see `generate-seccomp.py`).

### What is blocked

The filters block two groups of syscalls:

1. **Core attack-surface denials** — `io_uring_{setup,enter,register}`, `userfaultfd`, `kexec_load`/`kexec_file_load`. The `io_uring` block provides the main security value; it has a [large kernel attack surface](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html) and [Docker's default seccomp profile](https://github.com/moby/moby/pull/46762) blocks it since version 25.0.

2. **Defense-in-depth set** — `bpf`, `mount`, `umount2`, `pivot_root`, `reboot`, `swapon`/`swapoff`, `personality`, `acct`, `quotactl`, `kcmp`. Each of these is already rejected at the capability layer for an unprivileged sandboxed process; denying them at the seccomp layer too is belt-and-suspenders in case a kernel bug or misconfiguration ever leaks the gating capability. Zero observable effect on HPC/ML workloads — see [SECURITY.md §Seccomp Filter](SECURITY.md#seccomp-filter) for the per-syscall justification.

The Landlock backend additionally denies `ptrace` and `process_vm_readv`/`writev` because it has no PID namespace to prevent sibling-process inspection. bwrap and firejail rely on PID namespacing for that.

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
| No sandbox self-protection | In user-only install, scripts writable under `~/.config/agent-sandbox/`. Admin install avoids this — scripts are root-owned, `~/.config/agent-sandbox/` contains only user data. |
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

- **[Slurm job enforcement](slurm-enforce/README.md)** — ensures agent-submitted Slurm jobs inherit the sandbox. All Slurm enforcement variables (`TOKEN_FILE`, `REAL_SBATCH`, `REAL_SRUN`, `SANDBOX_EXEC`) can be added directly to `/app/lib/agent-sandbox/sandbox.conf` — one config file for both systems. See the [example admin config](#example-admin-config) for the Slurm variables.
