# Security Policy

## Important Disclaimer

This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared HPC systems but cannot prevent all possible bypasses. See the [Threat Model & Protections](#threat-model-protections) and [Known Limitations](#known-limitations) for documented boundaries.

## Scope

A vulnerability is a flaw that allows an agent (or attacker) to bypass a protection that the sandbox claims to enforce. Examples:

- Escaping filesystem isolation to read or write paths that should be hidden
- Recovering environment variables that should have been stripped
- Bypassing seccomp filters to execute blocked syscalls
- Escaping the chaperon proxy to submit unsandboxed Slurm jobs
- Privilege escalation through the sandbox scripts themselves
- User enumeration (e.g. extracting usernames, home paths, or org structure from `/etc/passwd`, LDAP, or `finger`)
- Host process table extraction (reading `/proc` to discover or inspect other users' processes)
- Slurm queue information disclosure (extracting job names, resource usage, or submission details of other users)

The following are **not** in scope (they are documented known limitations):

- Network-based exfiltration (the sandbox does not isolate the network)
- Abstract Unix socket access in bwrap/firejail (shared network namespace)
- Landlock's inability to block `AF_UNIX connect()`, PID namespace, or mount namespace features
- `memfd_create` / fileless execution (intentionally allowed for CUDA/PyTorch/JAX)
- Anything already listed in the [Known Limitations](#known-limitations) table, unless you have found a way to escalate its impact beyond what is described

If you are unsure whether something qualifies, report it anyway. We would rather triage a non-issue than miss a real one.

## Supported Versions

Only the latest commit on `main` is supported. There are no versioned releases; please test against the current `main` branch.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://github.com/katosh/agent_sandbox/security/advisories/new) to submit a report. This keeps the details confidential until a fix is available.

Please include:

- Which backend(s) are affected (bwrap, firejail, landlock, or all)
- Steps to reproduce (a minimal script or command sequence)
- What protection was bypassed and what access was gained
- Your kernel version and distribution (sandbox behavior can vary across kernels)

## Response Timeline

- **Acknowledgment** within 72 hours of receiving the report
- **Triage and initial assessment** within 1 week
- **Fix or documented mitigation** as soon as practical, depending on complexity

We will coordinate disclosure timing with the reporter. If we cannot fix the issue promptly, we will document it as a known limitation with mitigations.

## Security Documentation

This project maintains extensive security documentation:

- [Threat Model & Protections](#threat-model-protections) — threat model with protection strength ratings
- [Known Limitations](#known-limitations) — per-backend limitations sorted by severity, with mitigations
- [Admin Hardening](../admin/hardening.md) — options to close remaining gaps (admin-enforced installation, network restrictions, cgroups)
- [Apptainer Comparison](apptainer-comparison.md) — detailed comparison with HPC container runtimes
- [Pentest Reports](pentest/) — findings from structured security audits of all three backends
- [Chaperon](chaperon.md) — Slurm proxy design and security properties

## Accepted Trade-offs

The sandbox makes deliberate trade-offs for HPC compatibility. These are not bugs:

- **Network remains open.** AI coding agents require network access for API calls. Full network isolation would require a dedicated network namespace with selective forwarding, which is not yet implemented.
- **`memfd_create` is allowed.** Blocking it breaks CUDA, PyTorch, and JAX. Docker's default seccomp profile makes the same trade-off.
- **`LD_PRELOAD` / `LD_LIBRARY_PATH` are not blocked.** Conda, CUDA, Intel MKL, and other HPC tools depend on them. The agent already has code execution, so these do not add attack surface.

## Seccomp Filter

The sandbox applies a seccomp-bpf denylist at the kernel layer. Two sets of syscalls are denied:

### Core attack-surface denials (all backends)

Each has either a large, rapidly-evolving kernel attack surface or a history of exploit primitives. Docker's default seccomp profile denies all of them.

| Syscall(s) | Why denied |
|---|---|
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Exposes a large, rapidly-evolving kernel attack surface (kernel ≥ 5.1). Docker 25.0+ denies by default. No HPC workload needs it — ordinary `read`/`write` suffice. |
| `userfaultfd` | Primitive for exploiting kernel race conditions (CVE-2021-22555, CVE-2024-1086). Only needed by QEMU postcopy and CRIU lazy restore — neither relevant to HPC. Kernel also restricts it via `vm.unprivileged_userfaultfd=0` since 5.11. |
| `kexec_load`, `kexec_file_load` | Loads a replacement kernel. `CAP_SYS_BOOT`-gated, already blocked by `no_new_privs`, but denied here for defense in depth. |

### Defense-in-depth denials (all backends)

These are already rejected at the capability layer for unprivileged sandboxed processes (see the reachability probe summary in `pentest/round2_findings.md` and issue #9). Adding them to the seccomp filter is belt-and-suspenders: if a kernel bug or misconfiguration ever leaked the gating capability, the seccomp filter still rejects the call. Zero observable effect on HPC/ML workloads.

| Syscall | Why it's safe to deny |
|---|---|
| `bpf` | Loads eBPF programs. Requires `CAP_BPF`/`CAP_SYS_ADMIN` for most operations. Only bcc/bpftrace/tracing tools use it; no HPC workload does. |
| `mount`, `umount2`, `pivot_root` | Filesystem-namespace mutation. `CAP_SYS_ADMIN`-gated; not reachable from userns-only sandboxes. |
| `reboot` | Halts the machine. `CAP_SYS_BOOT`-gated. |
| `swapon`, `swapoff` | Swap-space manipulation. `CAP_SYS_ADMIN`-gated. |
| `personality` | Execution-domain quirks (e.g. legacy `READ_IMPLIES_EXEC`). Historically used in exploit-mitigation bypass chains (CVE-2022-1499 class). Docker restricts to "safe" values; we deny outright. |
| `acct` | BSD process accounting. `CAP_SYS_PACCT`-gated. |
| `quotactl` | Filesystem quota control. `CAP_SYS_ADMIN`-gated. |
| `kcmp` | Compares two processes' kernel resources. `CAP_SYS_PTRACE`-gated across UIDs; same-UID inspection can be abused for kernel-pointer leaks. |

### Landlock-only denials

Because the Landlock backend has no PID namespace, two additional syscalls are denied so that a sandboxed agent cannot read or inject into sibling processes:

- `ptrace`
- `process_vm_readv`, `process_vm_writev`

The bwrap and firejail backends do not deny these: PID namespaces already prevent the agent from seeing sibling processes, and `process_vm_readv` is required by MPI CMA transport (OpenMPI, MVAPICH) for high-performance cross-rank data transfer within a compute node.

### Remaining allowed-but-risky syscalls

The following are **not** in the denylist because denying them would break common HPC/ML workflows. An agent with code execution can still reach them (they are gated by capabilities, `yama.ptrace_scope`, `kernel.perf_event_paranoid`, or argument filters at the kernel layer — not by our seccomp profile).

| Syscall | Why it stays allowed | Kernel-level mitigation that still applies |
|---|---|---|
| `perf_event_open` | Profilers (`perf`, `py-spy --native`, Intel VTune) depend on it | `kernel.perf_event_paranoid` ≥ 2 (default on most distros) restricts to self-profiling |
| `ptrace` (bwrap/firejail only) | Debuggers (`gdb`, `strace`, `lldb`) are routinely used in HPC work | PID namespace hides sibling processes; `kernel.yama.ptrace_scope` ≥ 1 restricts cross-process attach |
| `setns` | Nested namespaces used by Apptainer-in-sandbox, `uv`, some subprocess-isolation tooling | Capability-gated for most namespace types |
| `unshare` | Required by Apptainer build, Podman, and various subprocess isolation patterns | Same caps as `setns`; `kernel.unprivileged_userns_clone` can be disabled by admins |
| `process_vm_readv`, `process_vm_writev` (bwrap/firejail) | MPI CMA transport in OpenMPI, MVAPICH | PID namespace + `CAP_SYS_PTRACE` required across UIDs |
| `add_key`, `request_key`, `keyctl` | Required for Kerberos / NFSv4 with `krb5` flavor on sites that use it | Keyring namespacing; subject to normal UNIX permissions |

Sites that do not need profiling, debugging, or nested containers may wish to add an opt-in config knob to also deny these syscalls. That extension is tracked as a future change; see `pentest/round2_findings.md`.

### Out of scope

The following are intentionally not blocked and will not be:

- `memfd_create` — breaks CUDA, PyTorch, JAX (see Accepted Trade-offs above).
- `clone`/`fork`/`execve` — the sandbox is designed to host a normal shell and toolchain.

## Threat Model & Protections

| Threat | Protection | Strength |
|---|---|---|
| Agent reads SSH keys | Hidden (bwrap/firejail: ENOENT) or blocked (Landlock: EACCES) | **Hard** — kernel-enforced |
| Agent reads API tokens from env | `BLOCKED_ENV_VARS` + `BLOCKED_ENV_PATTERNS` removed from environment | **Hard** — all backends |
| Agent reads `~/.aws` credentials | Hidden or blocked (same as SSH keys) | **Hard** |
| Agent writes to other projects | Only project dir is writable | **Hard** |
| Agent reads other users' data | Only explicitly allowed paths are accessible | **Hard** |
| User enumeration & profile extraction | LDAP/AD directories (`/etc/passwd`, `finger`) are hidden or restricted (bwrap/firejail/landlock) | **Hard** — prevents agent from mapping organizational structure or extracting real names and login history |
| Extraction of other users' data | Shared filesystems (NFS, Lustre) are restricted; only the project directory and specified paths are accessible | **Hard** — prevents credential-based access to other lab members' data |
| Agent escapes via Unix sockets | Bwrap/firejail: filesystem-based sockets (e.g. `/run/dbus`) hidden by mount namespace, but abstract sockets (`@/org/...`) remain accessible (shared network namespace). **Landlock: full escape** — `systemd-run --user` executes outside sandbox (reads `~/.ssh`, `~/.aws`, submits Slurm jobs). See [Admin Hardening §0](../admin/hardening.md) | **Partial** (bwrap/firejail) / **None** (Landlock) |
| Agent escapes via PID namespace | Bwrap/firejail: isolated PID namespace. Landlock: host PIDs visible | **Hard** (bwrap/firejail) / **None** (Landlock) |
| Agent uses dangerous syscalls | All backends block `io_uring`, `userfaultfd`, `kexec`, plus a defense-in-depth set (`bpf`, `mount`, `umount2`, `pivot_root`, `reboot`, `swapon`/`swapoff`, `personality`, `acct`, `quotactl`, `kcmp`) via seccomp-bpf. See the [Seccomp Filter](#seccomp-filter) section above. | **Hard** — all backends |
| Slurm job bypasses sandbox | Chaperon proxy: munge socket blocked (bwrap/firejail), Slurm binaries blocked (bwrap/firejail), argument whitelisting, all jobs wrapped in sandbox-exec.sh. **Landlock: chaperon fully bypassable** — munge socket reachable and Slurm binaries callable | **Hard** (bwrap/firejail) / **None** (Landlock — use bwrap or firejail) |
| Agent tampers with sandbox scripts | Read-only mount (bwrap/firejail) / not protected (Landlock) | **Hard** (bwrap/firejail) / **None** (Landlock) — see [Admin Hardening §2](../admin/hardening.md) |
| SSH escape (if `~/.ssh` exposed) | Not protected — sandbox does not restrict network | **None** — agent can SSH to localhost or other nodes to get an unsandboxed shell. **Do not expose `~/.ssh`** unless you understand this risk. |

**Bottom line:** Filesystem isolation is kernel-enforced with all three backends. Bwrap/firejail add mount + PID namespace isolation. Landlock works without admin privileges but provides filesystem-only isolation. Slurm job submission is enforced by the chaperon proxy on bwrap/firejail — munge auth is blocked inside the sandbox, so there is no way to submit jobs without going through the validated, wrapped path. **On Landlock, the chaperon is fully bypassable** — Landlock cannot block `AF_UNIX connect()`, so the munge socket is reachable and `/usr/bin/sbatch` is directly callable. Use bwrap or firejail for any deployment that needs a hard Slurm boundary. For comparison with Apptainer, see [Sandbox vs. Apptainer](apptainer-comparison.md).

**Accepted risks (all backends):** Fileless execution via `memfd_create` (needed by CUDA/PyTorch/JAX). `/proc/net` information disclosure (needed for network stack). Abstract Unix sockets accessible (shared network namespace required for DNS/NSS). See `pentest/` in the repository for detailed pentest findings.

## Backend Comparison

| Tool | Available? | Pros | Cons |
|---|---|---|---|
| **[Bubblewrap](https://github.com/containers/bubblewrap)** | `apt`/`dnf`/`brew` | Mount namespace isolation, paths hidden entirely (ENOENT), file overlays, Slurm binary relocation, sandbox self-protection, seccomp via generated BPF filter (io_uring/userfaultfd/kexec + defense-in-depth set) | Requires unprivileged user namespaces; blocked by AppArmor on Ubuntu 24.04+ without admin help |
| **[Firejail](https://firejail.wordpress.com/)** | yes (`apt install`) | Mount namespace (ENOENT), PID namespace, built-in seccomp + io_uring + userfaultfd + defense-in-depth set blocked, caps dropping, works when AppArmor blocks user namespaces | Requires setuid root binary |
| **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** | yes (kernel ≥ 5.13) | No root or admin needed, works on Ubuntu 24.04 despite AppArmor, pure kernel LSM, no external dependencies (Python 3 only) | No mount namespace — blocked paths return EACCES not ENOENT, no file overlays, no PID isolation, no Slurm binary relocation, no sandbox self-protection, cannot block Unix socket connect (**chaperon fully bypassable** — see [Admin Hardening](../admin/hardening.md)) |
| **[Apptainer/Singularity](https://apptainer.org/)** | yes (lmod) | Full container, HPC-native | Heavy — requires container images, path mapping |
| **Docker** | no | Industry standard | Requires root daemon; not available on shared HPC |

Auto-detection priority: bwrap → firejail → landlock. All three provide kernel-enforced filesystem isolation. Force a backend with `SANDBOX_BACKEND` in `sandbox.conf` or `--backend` on the command line.

## Known Limitations

Sorted by perceived severity (security impact first, then operational issues).

| Backend | Limitation | Mitigation |
|---|---|---|
| **All** | Network not isolated — agent can exfiltrate data via HTTP, reach cloud metadata endpoints (169.254.169.254), access internal services, or SSH to an unsandboxed shell if `~/.ssh` is exposed. Claude Code requires network for its API, so full isolation is not possible without a dedicated network namespace with selective forwarding | Do not expose `~/.ssh`; limit keys to single-service scopes (e.g. GitHub deploy keys only). See [Admin Hardening](../admin/hardening.md) for iptables/nftables templates to block metadata endpoints and restrict outbound connections |
| **Firejail** | Setuid-root binary with a significant [CVE history](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html) (18 CVEs, 12 local root exploits). Installing firejail adds a privileged attack surface to every node | Prefer bwrap where possible. See [Apptainer Comparison](apptainer-comparison.md#security-track-record) for the full CVE breakdown |
| **Landlock** | Cannot block `AF_UNIX connect()` — **full sandbox escape** via `systemd-run --user` if `user@.service` is running (reads `~/.ssh`, `~/.aws`, writes arbitrary files with no Landlock restrictions). Also bypasses chaperon (munge socket reachable) | **Use bwrap or firejail.** If Landlock-only: [Admin Hardening §0](../admin/hardening.md) (mask `user@.service`) is **mandatory** |
| **Landlock** | No sandbox self-protection — agent can modify wrapper scripts. Current session is safe (kernel rules are irrevocable), but future sessions could be compromised | Use bwrap or firejail |
| **Landlock** | No PID namespace — host processes visible via `/proc`. Agent could read `/proc/PID/environ` of same-UID processes | Use bwrap or firejail for PID isolation |
| **bwrap** | Supplementary groups display as `nogroup` (65534) inside the sandbox. Unprivileged bwrap always creates a user namespace (required to obtain mount/PID namespaces without root), and that namespace can only map the caller's own UID/GID. All other GIDs appear unmapped. **File permissions still work correctly** — the kernel uses host credentials for filesystem access, so group-owned directories remain fully accessible. Only display tools (`id`, `ls -l`) are affected | Cosmetic only — no functional impact. A privileged bwrap installation (setuid or `CAP_SYS_ADMIN`) could avoid the user namespace entirely, preserving group display |
| **bwrap** | Seccomp filter generated at runtime (`generate-seccomp.py`) rather than built-in — see [Seccomp for bwrap](../admin/install.md#seccomp-for-bwrap) | Verify the filter loads (no "seccomp" warnings on stderr at startup) |
| **All** | `memfd_create` not blocked by any backend (HPC compatibility). `process_vm_readv/writev` blocked only on Landlock (no PID namespace to mitigate). Docker's default seccomp profile makes similar trade-offs | Accepted trade-off. `memfd_create` needed by CUDA, PyTorch, JAX. `process_vm_readv/writev` needed by MPI (mitigated by PID namespace in bwrap/firejail, blocked by seccomp on Landlock). See [Admin Hardening](../admin/hardening.md) |
| **bwrap** (`DEVICES+=(/dev/pts)`) | `/dev/pts` exposure — required for tmux on kernels < 5.4. On kernels < 6.2, `TIOCSTI` ioctl allows keystroke injection into same-user terminals outside the sandbox. Admin enforces with `DEVICES_BLACKLIST+=(/dev/pts)` to refuse the opt-in cluster-wide | Defaults expose only NVIDIA driver nodes — pty is opt-in. Upgrade to kernel ≥ 5.4 to avoid the need, or ≥ 6.2 to disable TIOCSTI entirely. The legacy `BIND_DEV_PTS=true` knob is rewritten to this form for compatibility — see [Device Passthrough](device-passthrough.md) |
| **Landlock** | Host `/dev/pts/*` always visible (no mount namespace). On kernels < 6.2, `TIOCSTI` ioctl allows keystroke injection into same-user terminals — unlike bwrap, this is not opt-in | Kernel ≥ 6.2 disables TIOCSTI system-wide. Use bwrap or firejail for private `/dev` |
| **All** | Agent config directories (e.g., `~/.claude/`, `~/.codex/`) are writable (required for agents to function). An agent in one project can read session data from other projects | Inherent requirement — agents need write access to their config directories. Cross-project data access could be mitigated by per-project config copies |
| **Landlock** | `/dev/shm` is writable and shared (no IPC namespace) — could be used for covert cross-sandbox communication or to read/corrupt shared memory of same-UID processes | Use bwrap or firejail (both isolate IPC via `PRIVATE_IPC=true`, the default) |
| **Landlock** | User enumeration via LDAP/AD — `getent passwd` reveals all directory users | No mount namespace to overlay files or block sockets; set `FILTER_PASSWD=false` if LDAP lookups are needed |
| **Landlock** | `BLOCKED_FILES` has no effect — file overlays require a mount namespace, which Landlock doesn't have. Files listed in `BLOCKED_FILES` remain readable | Use bwrap or firejail for file-level hiding |
| **Landlock** | `PRIVATE_TMP` has no effect — `/tmp` isolation requires a mount namespace. Sandboxed processes share the host `/tmp` | Use bwrap or firejail if `/tmp` isolation is needed |
| **Landlock** | **Chaperon fully bypassable** — Landlock cannot block `AF_UNIX connect()`, so the munge socket (`/run/munge/munge.socket.2`) is reachable despite not being in the Landlock allowlist. Combined with directly callable Slurm binaries (`/usr/bin/sbatch`), agents can forge munge credentials and submit arbitrary unwrapped jobs, completely bypassing the chaperon | **Use bwrap or firejail** for any deployment that needs a hard Slurm boundary |
| **bwrap/Firejail** | `/tmp` isolated by default (`PRIVATE_TMP=true`) — breaks MPI shared-memory transport and NCCL inter-GPU sockets | Set `PRIVATE_TMP=false` in `sandbox.conf` for HPC multi-process workloads |
| **All** | Environment variable blocking uses explicit names (`BLOCKED_ENV_VARS`) and glob patterns (`BLOCKED_ENV_PATTERNS` — e.g. `*_TOKEN`, `SSH_*`, `CI_*`). Patterns catch most credential conventions automatically, but secrets with unusual names may slip through | Review your environment (`env \| grep -iE 'token\|key\|secret\|auth'`), add names to `BLOCKED_ENV_VARS` or patterns to `BLOCKED_ENV_PATTERNS`, and use `ALLOWED_ENV_VARS` to override. See [Admin Hardening](../admin/hardening.md) for an allowlist approach |
| **All** | No resource exhaustion limits by default — a sandboxed process can consume unlimited CPU, memory, processes, and disk space in the project directory | Set `SANDBOX_NPROC_LIMIT` in `sandbox.conf` for fork bomb defense. See [Admin Hardening](../admin/hardening.md) for cgroup-based limits. Slurm-submitted jobs are limited by the scheduler |
| **All** | Chaperon logs record requests with full arguments and handler denials. Logs are per-session files in `~/.local/state/agent-sandbox/chaperon/`, auto-pruned by age (`CHAPERON_LOG_RETAIN_DAYS`, default 7) and total size (50 MiB cap). Configure `CHAPERON_LOG_LEVEL` in `sandbox.conf` (`debug` for script content, `info` for requests and denials, `warn`/`error` for less). Filenames include hostname for NFS-safe uniqueness across machines | Review logs for denied access patterns. For system-level audit (file access, execve, network), see [Admin Hardening §5](../admin/hardening.md) which requires dedicated agent accounts |
| **All** | `srun --pty` (interactive PTY) is not supported through the chaperon protocol. Some advanced srun flags may be blocked — check the denied list in [Chaperon](chaperon.md) if a launch fails | Use `sbatch` for interactive-like workflows, or `srun` without `--pty` for non-interactive execution |
| **All** | Chaperon temp files (wrapper scripts, original scripts) in `$TMPDIR` persist after SIGKILL since the cleanup trap cannot fire | Stale files are named `chaperon-*` in `$TMPDIR`; periodic cleanup recommended on NFS-backed tmp |
| **Firejail** | `FILTER_PASSWD=true` blocks NSS daemon sockets (nscd, nslcd, sssd) on LDAP/AD clusters where the current user is not in local `/etc/passwd`, breaking user/group resolution and Slurm | Set `FILTER_PASSWD=false` in `sandbox.conf` on LDAP clusters, or prefer bwrap which overlays a pre-generated `/etc/passwd` |
