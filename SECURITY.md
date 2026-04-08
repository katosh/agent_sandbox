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
