# Configuration

Your sandbox permissions live in `~/.config/agent-sandbox/sandbox.conf`. Edit it to match your environment:

```bash
$EDITOR ~/.config/agent-sandbox/sandbox.conf
```

Changes take effect the next time you start a sandbox — no reinstall needed.

On admin-installed sites the effective policy is layered: admin baseline (`/app/lib/agent-sandbox/sandbox.conf`, if present) → your user config (`sandbox.conf` or `user.conf`) → per-project overrides (`conf.d/*.conf`). Each layer adds to the previous and users cannot weaken admin-enforced entries. See [Admin Install](admin/install.md) for the full hierarchy.

### Home Access Modes

The `HOME_ACCESS` setting in `sandbox.conf` controls how much of your home directory the agent can see and modify:

| Mode | Real files visible? | Agent can write? | Writes persist? | Use case |
|------|-------------------|-----------------|-----------------|----------|
| **`tmpwrite`** (default) | Only listed paths | Anywhere in `$HOME` | **No** — lost on exit | Recommended: agents can create dotfiles, caches, lock files without errors, but nothing leaks between sessions |
| `restricted` | Only listed paths | Only listed writable paths | Yes | Maximum lockdown — unlisted writes get "Read-only file system" errors |
| `read` | Everything | Only listed writable + project dir | Yes | Agent needs to read arbitrary dotfiles or configs |
| `write` | Everything | Everything | Yes | Full access — use with caution |

The default `tmpwrite` mode blanks `$HOME` with a tmpfs, re-mounts only the paths in `HOME_READONLY` and `HOME_WRITABLE`, but leaves the tmpfs writable. This means the agent can freely create files (lock files, caches, temp directories) anywhere in `$HOME`, but those writes vanish when the sandbox exits. Real home content not in the mount lists remains hidden. Credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`) are always blocked regardless of mode.

Override per-session via environment: `HOME_ACCESS=read agent-sandbox bash`

### Review your config

The default config ships with commented-out example paths that you should **replace with your own**. The principle of least privilege applies — the agent should only see data it actually needs for the task:

- **`READONLY_MOUNTS`** — Every path listed here is readable by the agent. The system paths (`/usr`, `/lib`, `/bin`, `/sbin`, `/etc`) are required for basic functionality. Lab storage paths should be limited to what the agent needs — mounting your PI's entire fast directory is convenient but exposes all data under it. Consider mounting only the specific subdirectory the agent will work with.
- **`EXTRA_BLOCKED_PATHS`** — Use this to carve out sensitive subdirectories from otherwise-visible mounts (e.g. clinical data under a lab storage path).
- **`HOME_READONLY`** — Each entry is visible inside the sandbox. The defaults cover shell config and tools; entries are marked in `sandbox.conf` with why they're needed. Remove any you don't use.
- **`BLOCKED_ENV_VARS`** / **`BLOCKED_ENV_PATTERNS`** — Patterns (`*_TOKEN`, `SSH_*`, `CI_*`, etc.) catch most credentials automatically. Check your environment (`env | grep -iE 'token|key|secret|pat|auth'`) and add any site-specific secrets with unusual names.

### Common Customizations

```bash
# Add a read-only data directory (add inside the READONLY_MOUNTS array)
    "/shared/other_lab/data"

# Add writable output directory (beyond the project dir)
EXTRA_WRITABLE_PATHS=("/shared/scratch/agent-output")

# Block sensitive directories (overlaid with empty tmpfs)
EXTRA_BLOCKED_PATHS=("/shared/lab/clinical_restricted")

# Allow GitHub CLI: add ".config/gh" to HOME_READONLY
# and add "GITHUB_TOKEN" "GH_TOKEN" to ALLOWED_ENV_VARS
```

### Per-Project Overrides

Different projects may need different data access. Create files in `conf.d/*.conf` to add mounts only when the project directory matches:

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

These files are sourced after `sandbox.conf`, so `+=` appends to the global arrays. See `conf.d/example.conf`.

> **SSH keys:** `~/.ssh` is excluded from `HOME_READONLY` by default — the agent cannot see it. **Do not add it.** On HPC clusters with passwordless SSH between nodes, an agent with access to `~/.ssh` can SSH to localhost for an unsandboxed shell. If the agent needs git access, prefer [deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) scoped to a single repo, or HTTPS with a fine-grained token (add the token var to `ALLOWED_ENV_VARS`).

#### Sandbox Permissions (settings.json)

For Claude Code, the sandbox overlays `~/.claude/settings.json` to auto-allow tools (`Bash`, `Read`, `Edit`, `Write`, `Glob`, `Grep`, `NotebookEdit`) that are already restricted by the kernel-enforced filesystem isolation. Your existing rules (including `deny`) are preserved. Customize via `~/.config/agent-sandbox/agents/claude/settings.json`.

