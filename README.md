# agent-sandbox

**Kernel-enforced filesystem isolation for AI coding agents on Linux.**

> [!WARNING]
> **Disclaimer.** This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared systems, but it cannot prevent all possible bypasses — see the [Security model](https://katosh.github.io/agent_sandbox/reference/security/) for documented limitations. Use at your own risk.

Hides SSH keys, cloud credentials, GPG keys, and environment secrets from AI coding agents while letting them do their job. Backed by bubblewrap (with firejail and Landlock as fallbacks), six built-in agent profiles (Claude Code, Codex, Gemini, Aider, OpenCode, pi-mono) with a one-line recipe for adding more, zero containers.

## Quick start

```bash
brew tap katosh/tools
brew install agent-sandbox

agent-sandbox claude          # Claude Code, sandboxed
agent-sandbox bash            # interactive shell, sandboxed
```

The agent starts in your project directory with read access to the system but write access only there. SSH keys, sensitive tokens, and unrelated credentials are invisible.

## Slurm-aware sandboxing for HPC

**Sandbox status is preserved across Slurm jobs.** Calls to `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, and `sacctmgr` from inside the sandbox are mediated by the chaperon — a proxy running outside the sandbox. The agent uses Slurm normally; under the hood every submission is rewritten to wrap the job in `sandbox-exec.sh` on the compute node, flags are whitelisted, and munge authentication plus the real Slurm binaries are blocked inside the sandbox. There is no path where an agent submits a job that escapes the sandbox.

**Container-class isolation without the container.** Similar isolation goals to Docker or Apptainer, very different ergonomics. No image to build, no registry, no volumes to map. The host filesystem is mapped 1:1 with secrets selectively hidden via mount-namespace overlays, so `lmod`, conda envs, CUDA, MPI, and your installed compiled software all work as if you were running natively. The agent sees the same paths you see — minus the credentials and unrelated projects.

**Hardening followers** (with the default bubblewrap backend):

- **Queue scoping.** `squeue` from inside the sandbox shows only jobs from sandbox sessions in the same project, not the whole cluster; `sacct --allusers` and `sacctmgr` user/account enumeration are denied.
- **Process-table isolation.** PID namespace cuts off the host process table; `/proc` exposes only the sandbox's own processes.
- **User-enumeration filtering.** `/etc/passwd` is overlaid (`FILTER_PASSWD`) so LDAP/AD lookups don't expose real names, login history, or org structure.
- **File scoping.** Writable only to the project directory; `~/.ssh`, `~/.aws`, `~/.gnupg`, and unrelated projects are hidden, not just blocked. Credential env vars (`*_TOKEN`, `SSH_*`, `CI_*`) are stripped at sandbox entry.

**Backends.** Bubblewrap is the primary backend and the recommended dependency. Firejail (setuid root) and Landlock (kernel ≥ 5.13, no mount/PID namespaces) are fallbacks for systems where bwrap is unavailable; they have documented gaps. See the [backend comparison](https://katosh.github.io/agent_sandbox/reference/security/#backend-comparison) for the per-backend protection matrix.

For other install paths (Make, system-wide, no-Homebrew), HPC integration, configuration, troubleshooting, and the full security model, see the **[documentation site](https://katosh.github.io/agent_sandbox/)**.

## Project links

- **Docs:** <https://katosh.github.io/agent_sandbox/>
- **Source:** <https://github.com/katosh/agent_sandbox>
- **Issues / discussion:** <https://github.com/katosh/agent_sandbox/issues>
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **License:** MIT — see [`LICENSE`](LICENSE)
