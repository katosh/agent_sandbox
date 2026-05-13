# agent-sandbox

**Kernel-enforced filesystem isolation for AI coding agents on Linux.**

Hides SSH keys, cloud credentials, GPG keys, and environment secrets from AI coding agents while letting them do their job. Three backends (bubblewrap, firejail, Landlock), six built-in agent profiles (Claude Code, Codex, Gemini, Aider, OpenCode, pi-mono) with a one-line recipe for adding more, zero containers.

```bash
agent-sandbox claude          # Claude Code, sandboxed
agent-sandbox bash            # interactive shell, sandboxed
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

- **[Configure](configure.md)** — every knob (`NETWORK_FILTER_MODE`, `HOME_ACCESS`, `BLOCKED_FILES`, …) with defaults, types, and admin-pin behaviour.
- **[Network filter](reference/network-filter.md)** — outbound port-level enforcement. v1.1 enforces by default on bwrap (mail-submission + DoT + r-services ports closed in a pasta-provisioned netns); hostname-level egress is a [known limitation](reference/network-filter.md#known-limitations) with a managed-proxy mitigation.
- **[Reference](reference/chaperon.md)** — chaperon (Slurm proxy), device passthrough, sandbox-vs-Apptainer, security model.
- **[Admin](admin/install.md)** — installation, hardening, the runtime config guide that the in-sandbox agents themselves read.
- **[GitHub](https://github.com/katosh/agent_sandbox)** — source, issues, releases.
