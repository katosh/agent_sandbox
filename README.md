# agent-sandbox

**Kernel-enforced filesystem isolation for AI coding agents on Linux.**

[![CI](https://github.com/katosh/agent_sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/katosh/agent_sandbox/actions/workflows/ci.yml)
[![Docs](https://github.com/katosh/agent_sandbox/actions/workflows/docs.yml/badge.svg)](https://github.com/katosh/agent_sandbox/actions/workflows/docs.yml)
[![Release](https://img.shields.io/github/v/release/katosh/agent_sandbox)](https://github.com/katosh/agent_sandbox/releases)
[![License](https://img.shields.io/github/license/katosh/agent_sandbox)](LICENSE)

> [!WARNING]
> **Disclaimer.** This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared systems, but it cannot prevent all possible bypasses — see the [Security model](https://katosh.github.io/agent_sandbox/reference/security/) for documented limitations. Use at your own risk.

Hides SSH keys, cloud credentials, GPG keys, and environment secrets from AI coding agents while letting them do their job. Backed by bubblewrap (with firejail and Landlock as fallbacks), six built-in agent profiles (Claude Code, Codex, Gemini, Aider, OpenCode, pi-mono) with a one-line recipe for adding more, zero containers.

## Why agent-sandbox?

The agent-sandboxing field has converged into roughly six isolation layers — kernel-bind wrappers, OCI containers, gVisor, microVMs, WASM, and hosted SaaS. agent-sandbox sits in the small cluster of process-level kernel-bind wrappers (alongside Anthropic's `sandbox-runtime`, OpenAI Codex CLI's Linux sandbox, `nono`, `cco`, and `scode`) and is the **only project surveyed with first-class HPC/Slurm awareness**: the [chaperon proxy](https://katosh.github.io/agent_sandbox/reference/chaperon/) mediates `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, and `sacctmgr` so submissions made from inside the sandbox stay sandboxed on the compute node, with no path for an agent to escape via job submission.

![Securing AI agents: agent-sandbox for HPC — overview of kernel-enforced FS isolation, automatic credential stealth, container-free containment, the Slurm chaperon proxy, and built-in agent profiles.](https://raw.githubusercontent.com/katosh/agent_sandbox/assets/agent-sandbox.png)

Two structural strengths follow from the design:

- **Kernel-enforced bind-mount FS isolation** rather than a path-denylist — denied paths return `ENOENT`, with no canonical name for an agent to reach via `ld-linux` or `/proc/self/root`. Whole evasion classes documented for denylist sandboxes do not apply.
- **Containment without a container** — no image to build, no daemon, no setuid helper on the bwrap backend; `lmod`, conda envs, CUDA, MPI, and your installed compiled software work as on the host.

For the field overview, the comparison matrix against six deeply-compared peers, and an honest accounting of where the project lags the field (egress allowlists, credential proxies), see [agent-sandbox in the agent-sandboxing landscape](https://katosh.github.io/agent_sandbox/reference/landscape-comparison/).

## Quick start

```bash
brew tap katosh/tools
brew install agent-sandbox

agent-sandbox claude          # Claude Code, sandboxed
agent-sandbox bash            # interactive shell, sandboxed
```

The agent starts in your project directory with read access to the system but write access only there. SSH keys, sensitive tokens, and unrelated credentials are invisible.

> [!TIP]
> **Configure the sandbox.** Mounts, devices, environment variables, Slurm scope, and admin enforcement: see the [configuration reference](https://katosh.github.io/agent_sandbox/configure/).

## Project links

- **Docs:** <https://katosh.github.io/agent_sandbox/>
- **Source:** <https://github.com/katosh/agent_sandbox>
- **Issues / discussion:** <https://github.com/katosh/agent_sandbox/issues>
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **License:** MIT — see [`LICENSE`](LICENSE)
