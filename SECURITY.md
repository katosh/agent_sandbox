# Security Policy

## Important Disclaimer

This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared HPC systems but cannot prevent all possible bypasses. See the [Security Summary](README.md#security-summary) and [Known Limitations](README.md#known-limitations) for documented boundaries.

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
- Anything already listed in the [Known Limitations](README.md#known-limitations) table, unless you have found a way to escalate its impact beyond what is described

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

- [Security Summary](README.md#security-summary) — threat model with protection strength ratings
- [Known Limitations](README.md#known-limitations) — per-backend limitations sorted by severity, with mitigations
- [Admin Hardening](ADMIN_HARDENING.md) — options to close remaining gaps (admin-enforced installation, network restrictions, cgroups)
- [Apptainer Comparison](APPTAINER_COMPARISON.md) — detailed comparison with HPC container runtimes
- [Pentest Reports](pentest/) — findings from structured security audits of all three backends
- [Chaperon](CHAPERON.md) — Slurm proxy design and security properties

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
