# agent-sandbox

**Kernel-enforced credential and network jail for untrusted Linux processes — AI coding agents are the canonical use case.**

Hides SSH keys, cloud credentials, GPG keys, and environment secrets from any process started inside the jail, while letting that process do its job. Three backends (bubblewrap, firejail, Landlock), six built-in agent profiles (Claude Code, Codex, Gemini, Aider, OpenCode, pi-mono) with a one-line recipe for adding more, zero containers. Network egress is enforced by the Linux kernel at the network-namespace boundary (four [`NETWORK_FILTER_MODE`](reference/network-filter.md#modes) values — `open`/`filtered`/`proxied`/`isolated`), not by the sandboxed process's own permission system: a jailbroken process cannot reach destinations outside the configured policy regardless of what its CLI tooling allows.

The shipped profiles and defaults are tuned for AI coding agents on HPC login nodes; the same jail wraps any other command — untrusted CLI tools, local CI / build steps, notebook kernels, or a collaborator's branch checked out for review. See [What this means for agent-sandbox's design](reference/landscape-comparison.md#what-this-means-for-agent-sandboxs-design) for the wider profile.

```bash
agent-sandbox claude          # Claude Code, the canonical use case
agent-sandbox bash            # interactive shell, sandboxed
agent-sandbox npm install     # any other command, same jail
```

!!! warning "Disclaimer"
    This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared systems, but it cannot prevent all possible bypasses — see the [Security model](reference/security.md) and [Admin hardening](admin/hardening.md) for known limitations. Use at your own risk.

## Quick start

```bash
brew tap katosh/tools
brew install agent-sandbox
agent-sandbox claude
```

For other install paths (Make, system-wide, no-Homebrew), see [Installation](admin/install.md).

## Where to go from here

- **[Reference](reference/chaperon.md)** — chaperon (Slurm proxy), device passthrough, sandbox-vs-Apptainer, security model.
- **[Admin](admin/install.md)** — installation, hardening, the runtime config guide that the in-sandbox agents themselves read.
- **[GitHub](https://github.com/katosh/agent_sandbox)** — source, issues, releases.
