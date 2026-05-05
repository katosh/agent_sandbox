# Architecture

How agent-sandbox achieves kernel-enforced filesystem isolation, per resource and per backend.

## Isolation by Resource

| Resource | bwrap | firejail | landlock |
|---|---|---|---|
| **Filesystem (read)** | Hidden (ENOENT) | Hidden (ENOENT) | Blocked (EACCES) |
| **Filesystem (write)** | Project dir only | Project dir only | Project dir only |
| **Environment variables** | Blocked | Blocked | Blocked |
| **PID namespace** | Isolated | Isolated | Host PIDs visible |
| **Network** | Not isolated | Not isolated | Not isolated |
| **`/run` (system sockets)** | tmpfs + selective bind (munge, nscd, resolved) | Blacklist (dbus, systemd, containerd) | Full access |
| **Abstract Unix sockets** | Accessible | Accessible | Accessible |
| **IPC / `/dev/shm`** | Isolated | Isolated | Shared |
| **Syscalls (seccomp)** | io_uring + userfaultfd + kexec + defense-in-depth set (bpf, mount, umount2, pivot_root, reboot, swapon/off, personality, acct, quotactl, kcmp) blocked via generated BPF filter | Built-in + io_uring + userfaultfd + kexec + defense-in-depth set blocked | io_uring + userfaultfd + kexec + ptrace + process_vm_readv/writev + defense-in-depth set (kernel ≥ 5.13 only) |
| **User enumeration** | Filtered (`FILTER_PASSWD`) | Filtered (`FILTER_PASSWD`) | Not filtered |
| **Slurm (chaperon)** | Munge + binaries + config blocked; chaperon proxy | Munge + binaries + config blocked; chaperon proxy | Munge not granted; chaperon proxy |
| **Sandbox self-protection** | Read-only mount | Read-only mount | Not protected |
| **tmux** | Outer blocked, nested works | Outer blocked, nested works | Outer blocked, nested works |
| **Notifications** | `sandbox-notify` emits one BEL; tmux's `bell-action any` propagates to both inner and outer status bars (`tmux new-window` IPC fallback when `/dev/tty` is unavailable) | Same | Same |

**Network** is not isolated on any backend — Claude Code requires network access to communicate with the Anthropic API, and many HPC tools (Slurm, LDAP/NSS, NFS) depend on network connectivity. See [Admin Hardening](../admin/hardening.md) for network restriction options.

**Abstract Unix sockets** (`@/org/...`) bypass filesystem isolation because they live in the network namespace, not on the filesystem. Isolating them requires a separate network namespace (`--unshare-net` / `--net=none`), which would break Claude Code's API access and Slurm connectivity. On systems with `systemd --user`, an abstract D-Bus socket could be used for sandbox escape — see [Admin Hardening](../admin/hardening.md).

**IPC / `/dev/shm`** is isolated on bwrap (`--unshare-ipc` + private `/dev/shm` tmpfs) and firejail (`--ipc-namespace`). Each sandbox gets its own `/dev/shm` and SysV IPC namespace, preventing the agent from reading or corrupting shared memory of processes outside the sandbox. This is safe for HPC workloads: `sbatch` jobs run entirely within a single sandbox, so all MPI ranks, NCCL collectives, and CUDA IPC within a job share the same IPC namespace. Landlock cannot isolate IPC (no namespace support). Configurable via `PRIVATE_IPC` in `sandbox.conf` (default: `true`). When set by an admin config, users cannot weaken it to `false`.

**Environment variables:** The sandbox inherits your shell environment, blocks specific names via `BLOCKED_ENV_VARS`, and blocks credential-pattern globs via `BLOCKED_ENV_PATTERNS` (`*_TOKEN`, `SSH_*`, `CI_*`, etc.). To grant access, add the variable to `ALLOWED_ENV_VARS`.


## HPC & Slurm Integration

On shared HPC systems, the risks are amplified: LDAP/AD directories expose every user on the cluster (`getent passwd`, `finger`), other people's lab data is accessible via shared filesystems, and Slurm job submission can escape filesystem restrictions entirely — an agent just submits a job that reads `~/.ssh` on the compute node.

### Chaperon: Secure Slurm Proxy

Inside the sandbox, all Slurm authentication and binaries are **blocked** — munge socket hidden, `/usr/bin/sbatch` etc. blacklisted, `/etc/slurm` removed. Job submission goes through the **chaperon**, a proxy process running outside the sandbox that communicates via named pipes in a per-session temp directory.

**From the agent's perspective, Slurm looks unperturbed.** Running `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, and friends from inside the sandbox behaves as if you were calling them from outside the sandbox — the stubs are invoked on PATH exactly like the real binaries, return the same exit codes, and print stdout/stderr that matches what the real tools would produce. Under the hood every call is funneled through the chaperon and heavily filtered (argument whitelisting, CWD validation, scope-filtered output, denied subcommands), but the surface presented to the agent is the unmodified Slurm CLI. The filtering is intentionally transparent: allowed commands pass through untouched, denied ones fail with an explanatory error, and scoped output is rewritten so chaperon internals never leak.

- **Stub sbatch:** Parses `--wrap` and script arguments, sends them over the `CHAPERON/1` protocol to the chaperon, prints the response. The agent calls `sbatch` as normal.
- **Stub srun:** Proxied through the chaperon like sbatch. Two modes: **allocation mode** (login node) — validates flags, wraps the command in `sandbox-exec.sh` so compute-node processes are sandboxed, then calls real srun. **Step mode** (inside an sbatch job, `SLURM_JOB_ID` set) — validates flags against a step-only whitelist and execs real srun directly for MPI/multi-process step launching. `--pty` is denied (no PTY passthrough). The chaperon runs outside the sandbox and has munge access — munge is never exposed inside the sandbox.
- **Stub scancel:** Sends cancel requests to the chaperon, which filters job IDs by scope (session, project, or user). By default, jobs submitted by any sandbox session with the same project directory can be cancelled. Configurable via `SLURM_SCOPE` in `sandbox.conf`, or as an environment variable override: `SLURM_SCOPE=session agent-sandbox claude`.
- **Stub squeue:** Proxied through the chaperon. Output is filtered to only show jobs within scope. The agent sees only its own sandbox-submitted jobs, not other users' jobs or unrelated jobs.
- **Stub scontrol:** Proxied through the chaperon. Read-only commands (`show node`, `show partition`, `show config`) pass through. Job operations (`show job`, `hold`, `release`, `requeue`, `update job`) are scoped to chaperon-submitted jobs. Dangerous subcommands (`shutdown`, `reconfigure`, etc.) and user-enumerating targets (`show assoc_mgr`) are denied.
- **Stub sacct:** Proxied through the chaperon. Always scoped to the current user (`--user=$(whoami)` injected). `--allusers` and `--accounts` are denied to prevent viewing other users' job history. Self-scoped variants (`--user $USER`, `--user=$USER`, `--me`, `--uid $(id -u)`) are silently accepted as no-ops; cross-user values are denied with an actionable hint pointing at the simple fix.
- **Stub sacctmgr:** Proxied through the chaperon. Only read-only queries for cluster, QOS, TRES, and config are allowed. User/account enumeration (`show user`, `show account`, `show association`) and all write operations are denied.
- **Chaperon proxy:** Validates arguments against a whitelist of ~40 safe sbatch flags (rejects `--uid`, `--get-user-env`, `--prolog`, etc.), validates CWD is under the project directory, wraps the job in `sandbox-exec.sh`, and submits via the real sbatch.
- **Security:** Named pipes with per-session temp directories, the chaperon dies with its parent (PR_SET_PDEATHSIG + liveness polling), and all user data is base64-encoded in the protocol (injection-proof).

For the full architecture, protocol specification, and security analysis, see [Chaperon](chaperon.md).

