# agent-sandbox

**Kernel-enforced filesystem isolation for AI coding agents on Linux.**

> [!WARNING]
> **Disclaimer.** This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared systems, but it cannot prevent all possible bypasses — see the [Security model](https://katosh.github.io/agent_sandbox/reference/security/) for documented limitations. Use at your own risk.

Hides SSH keys, cloud credentials, GPG keys, and environment secrets from AI coding agents while letting them do their job. Three backends (bubblewrap, firejail, Landlock), six built-in agent profiles (Claude Code, Codex, Gemini, Aider, OpenCode, pi-mono) with a one-line recipe for adding more, zero containers.

## Quick start

```bash
brew tap katosh/tools
brew install agent-sandbox

agent-sandbox claude          # Claude Code, sandboxed
agent-sandbox bash            # interactive shell, sandboxed
```

The agent starts in your project directory with read access to the system but write access only there. SSH keys, sensitive tokens, and unrelated credentials are invisible.

For other install paths (Make, system-wide, no-Homebrew), HPC integration, configuration, troubleshooting, and the full security model, see the **[documentation site](https://katosh.github.io/agent_sandbox/)**.

## Project links

- **Docs:** <https://katosh.github.io/agent_sandbox/>
- **Source:** <https://github.com/katosh/agent_sandbox>
- **Issues / discussion:** <https://github.com/katosh/agent_sandbox/issues>
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **License:** MIT — see [`LICENSE`](LICENSE)
