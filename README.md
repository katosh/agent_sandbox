# Sandboxing Claude Code Agents on Gizmo

> **Disclaimer:** This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared HPC systems, but it cannot prevent all possible bypasses — see the [Security Summary](#security-summary) and [Admin Hardening Options](ADMIN_HARDENING.md) for known limitations. Use at your own risk.

## Why Sandbox?

AI coding agents like Claude Code are powerful — they read files, write code, run commands, and submit Slurm jobs on your behalf. But on a shared HPC system, your user account has access to a lot more than any single project needs:

- **SSH keys** (`~/.ssh/`) — access to GitHub, remote servers, other clusters
- **Cloud credentials** (`~/.aws/`, API tokens) — access to S3, cloud services
- **GPG keys** (`~/.gnupg/`) — signing identity
- **All lab data** — including other people's projects, possibly clinical data
- **Environment secrets** — `GITHUB_PAT`, `OPENAI_API_KEY`, etc.

An agent working on one project shouldn't be able to read your SSH keys, exfiltrate API tokens, or accidentally overwrite someone else's data. A **sandbox** restricts the agent to only what it needs.

### Why Not a Full Container?

Containers (Docker, Singularity/Apptainer) solve isolation, but they introduce friction on HPC:

| Problem | Container Impact | Sandbox (bwrap) |
|---|---|---|
| **Filesystem mapping** | Must explicitly map every NFS path, home dir, scratch — get it wrong and paths differ inside vs. outside | Same filesystem, same paths. No mapping needed. |
| **Path consistency** | Scripts that reference `/fh/fast/...` may break inside the container if mounts differ | All paths are identical inside and outside. |
| **Software stack** | Must install tools inside the image, or map `/app` — versions may conflict | Directly uses `/app`, lmod, your Homebrew — everything just works. |
| **Image maintenance** | Must rebuild images when tools change | Nothing to rebuild. |
| **Starting Claude** | Must install and configure Claude Code inside each container image | `bwrap-sandbox.sh -- claude` — that's it. |
| **Slurm integration** | Either Slurm is inaccessible inside the container — making interactive agents on the login node pointless since they can't submit compute jobs — or jobs escape the container and run unsandboxed on compute nodes, defeating the isolation entirely | `sbatch`/`srun` are transparently wrapped so compute-node jobs inherit the same sandbox restrictions |

Bubblewrap gives you **container-grade filesystem isolation** with none of the path-mapping headaches. The agent sees the exact same filesystem as you, minus the secrets.

### The Slurm Problem

Filesystem isolation on the login node is only half the story. The main point of HPC is submitting work to compute nodes via Slurm. If the agent can run `sbatch` or `srun`, and those jobs execute **outside** the sandbox, then all restrictions are trivially bypassed — the agent just submits a job that reads `~/.ssh` on the compute node.

This sandbox solves the Slurm problem with a two-layer approach. First, wrapper scripts at `~/.claude/sandbox/bin/` **shadow** `sbatch`/`srun` on PATH, so every job submitted by the agent automatically runs inside bwrap on the compute node. Second, the real `/usr/bin/sbatch` and `/usr/bin/srun` binaries are **relocated** to an obscure internal path (`/tmp/.sandbox-slurm-real/`) and replaced with redirector scripts — so even calling them by absolute path still goes through the sandbox wrappers. Since bwrap and all scripts live on NFS, they're available on every compute node. The sandbox directory is mounted read-only, so the agent cannot tamper with the wrappers.

#### Limitations of the Slurm Wrappers

The Slurm wrappers provide strong default protection but are not fully kernel-enforced. They work by:

1. **PATH shadowing** — `sbatch`/`srun` resolve to sandbox wrappers via PATH ordering.
2. **Binary relocation** — the real ELF binaries at `/usr/bin/sbatch` and `/usr/bin/srun` are moved to an obscure internal path (`/tmp/.sandbox-slurm-real/`) and replaced with redirector scripts that funnel calls back through the sandbox wrappers.

Under normal operation (including calling `/usr/bin/sbatch` by absolute path), the agent always hits the sandbox wrappers. **This is a soft boundary** — Slurm authentication (munge) is available inside the sandbox, so a determined bypass is possible. See [Admin Hardening Options](ADMIN_HARDENING.md) for approaches that can close this gap. In practice, the wrappers cover the paths an agent would use autonomously.

---

## Installation

### Prerequisites

- Fred Hutch gizmo account (or similar HPC with Linux kernel ≥ 3.8)
- **Bubblewrap backend** (default): requires `kernel.unprivileged_userns_clone = 1` and [Homebrew](https://brew.sh/) for installation. On Ubuntu 24.04+, AppArmor may also need configuration — see [Troubleshooting](#setting-up-uid-map-permission-denied-ubuntu-2404).
- **Landlock backend** (fallback): requires kernel ≥ 5.13 (Ubuntu 22.04+). Works without root, even when AppArmor blocks user namespaces. No Homebrew needed — uses Python 3 only.

### One-Command Setup

```bash
# Clone the repo (if you haven't already)
git clone git@github.com:settylab/agent_container.git ~/agent_container

# Run the installer
bash ~/agent_container/install.sh
```

The installer:
1. Installs `bubblewrap` via Homebrew (if missing)
2. Copies scripts to `~/.claude/sandbox/`
3. Creates `~/.claude/sandbox/sandbox.conf` (your personal config — won't overwrite)
4. Installs agent instructions (only visible inside the sandbox, your CLAUDE.md is not modified)
5. Runs the test suite to verify everything works

### What Gets Installed

```
~/.claude/sandbox/
├── sandbox.conf          # ← Your permissions config — edit this
├── sandbox-lib.sh        # Core library (config loading, backend detection)
├── sandbox-exec.sh       # Main entry point (auto-selects backend)
├── bwrap-sandbox.sh      # Backward-compatible entry point (delegates to sandbox-exec.sh)
├── sbatch-sandbox.sh     # Slurm sbatch wrapper
├── srun-sandbox.sh       # Slurm srun wrapper
├── sandbox-claude.md     # Agent instructions (overlaid into CLAUDE.md inside sandbox)
├── test.sh               # Test suite
├── backends/
│   ├── bwrap.sh          # Bubblewrap backend (mount namespace isolation)
│   ├── landlock.sh       # Landlock backend (LSM filesystem restrictions)
│   └── landlock-sandbox.py  # Landlock syscall helper (Python)
└── bin/
    ├── sbatch            # Shadows /usr/bin/sbatch inside sandbox
    └── srun              # Shadows /usr/bin/srun inside sandbox
```

### Backends

The sandbox supports two backends, auto-detected at startup:

| Backend | How it works | Requirements | Blocked paths show as |
|---|---|---|---|
| **bwrap** (default) | Mount namespace isolation — hides paths entirely | `unprivileged_userns_clone=1`, no AppArmor userns restriction | `ENOENT` (No such file) |
| **landlock** (fallback) | Landlock LSM — restricts filesystem access | Kernel ≥ 5.13, Python 3 | `EACCES` (Permission denied) |

Both provide equivalent security. The auto-detection tries bwrap first (stronger isolation), then falls back to Landlock (works without admin help on Ubuntu 24.04+).

To force a backend: set `SANDBOX_BACKEND="landlock"` in `sandbox.conf` or use `--backend landlock` on the command line.

### Updating

To pick up newer scripts from the repo:

```bash
cd ~/agent_container && git pull
bash ~/agent_container/install.sh
```

Your `sandbox.conf` is never overwritten, so your customizations are preserved.

### Running Tests

The test suite verifies filesystem isolation, environment blocking, Slurm binary isolation, overlay generation, and self-protection:

```bash
bash ~/agent_container/test.sh            # run all tests
bash ~/agent_container/test.sh --verbose   # show details on failure
```

---

## Quick Start

### Set Up an Alias (optional)

Add this to your `.bashrc` or `.zshrc` for quick access:

```bash
alias claude-sandbox='~/.claude/sandbox/bwrap-sandbox.sh -- claude'
```

### Start Claude Code in a Sandbox

```bash
cd /fh/fast/setty_m/user/$USER/my-project

# With the alias:
claude-sandbox

# Or directly:
~/.claude/sandbox/bwrap-sandbox.sh -- claude
```

That's it. Claude starts in your project directory with full read access to the HPC but write access **only** to that directory. Your SSH keys, API tokens, and all credentials are invisible.

### Verify the Sandbox

```bash
# Secrets are hidden
~/.claude/sandbox/bwrap-sandbox.sh -- ls ~/.ssh
# → ls: cannot access '/home/user/.ssh': No such file or directory

# API tokens are gone
~/.claude/sandbox/bwrap-sandbox.sh -- bash -c 'echo "GITHUB_PAT=${GITHUB_PAT:-UNSET}"'
# → GITHUB_PAT=UNSET

# Slurm works
~/.claude/sandbox/bwrap-sandbox.sh -- squeue --me

# lmod works
~/.claude/sandbox/bwrap-sandbox.sh -- bash -c 'module avail 2>&1 | head -5'

# Writing outside project dir fails
~/.claude/sandbox/bwrap-sandbox.sh -- touch /fh/fast/setty_m/user/$USER/other-project/test
# → touch: cannot touch '...': Read-only file system

# Writing inside project dir works
~/.claude/sandbox/bwrap-sandbox.sh --project-dir $PWD -- bash -c 'touch test && rm test && echo OK'
# → OK
```

---

## Configuration

All sandbox permissions are in **one file**: `~/.claude/sandbox/sandbox.conf`. It's a bash file with well-documented arrays. Edit it with your favorite editor:

```bash
$EDITOR ~/.claude/sandbox/sandbox.conf
```

Changes take effect the next time you start a sandbox — no reinstall needed.

### Common Customizations

#### Block additional directories (e.g., clinical data)

If there are directories under your lab's fast storage that contain restricted data:

```bash
# In sandbox.conf:
EXTRA_BLOCKED_PATHS=(
    "/fh/fast/setty_m/clinical_restricted"
    "/fh/fast/setty_m/user/someone_else/private"
)
```

These paths will be overlaid with an empty tmpfs — the agent won't see them at all.

#### Allow AWS access

When the agent needs to interact with S3 or other AWS services:

```bash
# In sandbox.conf:
ALLOWED_CREDENTIALS=(
    "AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY"
    "AWS_DEFAULT_REGION"
    "AWS_SESSION_TOKEN"
)
```

These are un-blocked (overriding `BLOCKED_ENV_VARS`) so the agent can use them inside the sandbox.

#### Allow SSH keys (e.g., for private Git repos)

If the agent needs to clone or push to private repositories over SSH, you can expose your SSH keys inside the sandbox:

```bash
# In sandbox.conf — add to HOME_READONLY:
HOME_READONLY=(
    ".bashrc"
    ".gitconfig"
    ".linuxbrew"
    ".local/bin"
    "micromamba"
    ".condarc"
    ".mambarc"
    # ... existing entries ...
    ".ssh"                 # ← add this
)
```

> **Warning — understand the trade-offs before enabling this.**
>
> Exposing `~/.ssh` gives the agent access to **all** your SSH private keys. This means the agent can, in principle:
>
> - **Authenticate to any host** your keys grant access to — GitHub, remote clusters, production servers, etc.
> - **Push code, delete branches, or modify repositories** you have write access to — not just the project it's working on.
> - **Connect to remote machines** via SSH and execute commands there, entirely outside the sandbox's filesystem restrictions.
>
> The sandbox cannot limit *which* SSH operations the agent performs once the keys are visible — it only controls filesystem access, not network connections or SSH authentication.
>
> **Alternatives to consider:**
> - **Deploy keys:** Create a read-only [GitHub deploy key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) scoped to a single repository, place it in your project directory, and configure `GIT_SSH_COMMAND` to use it — no need to expose `~/.ssh` at all.
> - **HTTPS + token:** Use HTTPS cloning with a fine-grained personal access token (limited to specific repos) via the `ALLOWED_CREDENTIALS` mechanism instead.
> - **Read-only mount:** Note that `HOME_READONLY` mounts the directory read-only, so the agent cannot modify or delete your keys — but it *can* read and use them for authentication.

#### Allow GitHub CLI

```bash
# In sandbox.conf — add to HOME_READONLY:
HOME_READONLY=(
    ".bashrc"
    ".gitconfig"
    ".linuxbrew"
    ".local/bin"
    "micromamba"
    ".condarc"
    ".mambarc"
    # ... existing entries ...
    ".config/gh"           # ← add this
)

# And allow the token:
ALLOWED_CREDENTIALS=(
    "GITHUB_TOKEN"
    "GH_TOKEN"
)
```

#### Add a read-only data directory

If you have shared data outside the lab's fast directory:

```bash
# In sandbox.conf — add to READONLY_MOUNTS:
READONLY_MOUNTS=(
    "/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc"
    "/app"
    "/fh/fast/setty_m"
    "/fh/fast/other_lab/shared_data"    # ← add this
)
```

#### Sandbox Permissions (settings.json)

The sandbox overlays Claude Code's `~/.claude/settings.json` to **auto-allow tools that are already restricted by bwrap**. Since the sandbox enforces filesystem isolation at the kernel level, Claude Code's own permission prompts for file and shell operations are redundant — the agent can't escape the sandbox regardless of what it runs.

By default, the sandbox adds these to the `allow` list:

| Tool | Why safe inside the sandbox |
|---|---|
| `Bash` | Filesystem is read-only except the project dir |
| `Read` | Only mounted paths are visible |
| `Edit` / `Write` | Can only write to the project dir and `~/.claude` |
| `Glob` / `Grep` | Search is read-only |
| `NotebookEdit` | Same write restrictions as `Edit` |

The user's existing `settings.json` rules (including `deny` rules) are preserved — the sandbox only **adds** to the `allow` list.

To customize the sandbox permissions:

```bash
$EDITOR ~/.claude/sandbox/sandbox-settings.json
```

---

## How It Works

### Mount Strategy

The sandbox uses a layered mount approach:

```
Layer 1: System mounts (read-only)
    /usr, /lib, /lib64, /bin, /sbin, /etc, /app

Layer 1.5: Slurm binary isolation
    /usr/bin/sbatch, /usr/bin/srun → replaced with sandbox redirectors
    Real binaries → relocated to /tmp/.sandbox-slurm-real/

Layer 2: Blank home
    tmpfs on $HOME → hides EVERYTHING

Layer 3: Selective re-mount (read-only)
    ~/.bashrc, ~/.gitconfig, ~/.linuxbrew, ~/.local/bin, ...

Layer 4: Writable mounts
    ~/.claude (session data + auth), project directory

Layer 5: Read-only sandbox overlay
    ~/.claude/sandbox/ → read-only (protects wrapper scripts)

Layer 6: CLAUDE.md + settings.json overlays
    Merged with sandbox instructions/permissions

Layer 7: NFS storage (read-only base)
    /fh/fast/setty_m → entire tree read-only

Layer 8: Project directory (writable overlay)
    /fh/fast/setty_m/user/you/project → writable on top of Layer 7
```

The key insight is that bwrap processes mounts in order, and later mounts overlay earlier ones. So the project directory's `--bind` (writable) overlays the NFS tree's `--ro-bind` (read-only).

### Environment Variables

The sandbox inherits your shell environment, then:
1. **Sets** `SANDBOX_ACTIVE=1`, `SANDBOX_PROJECT_DIR`, and passes through HPC variables (lmod, mamba, etc.)
2. **Blocks** everything in `BLOCKED_ENV_VARS` (API tokens, secrets)
3. **Allows** everything in `ALLOWED_CREDENTIALS` back through (overrides the block)

### What's NOT Isolated

| Resource | Why |
|---|---|
| **Network** | Slurm needs network for job submission and munge authentication |
| **PID namespace** | Slurm job tracking requires host PID visibility |
| **`/run`** | Contains the munge socket for Slurm auth |

---

## Slurm Integration

### Transparent Wrapping

Inside the sandbox, `sbatch` and `srun` are **automatically replaced** by wrapper scripts that inject bwrap on the compute node. The sandbox prepends `~/.claude/sandbox/bin/` to `PATH`, so the wrappers shadow `/usr/bin/sbatch` and `/usr/bin/srun`. The agent (and any scripts it runs) just calls `sbatch` and `srun` as normal — the sandboxing happens transparently.

```bash
# Inside the sandbox, these just work — no special paths needed:
sbatch --wrap="python train.py"
sbatch my_job.sh
srun -n 4 python train.py
```

The wrappers pass all flags through unchanged and call the real Slurm binaries internally (relocated to `/tmp/.sandbox-slurm-real/` inside the sandbox).

### How the Wrappers Work

**sbatch:** In `--wrap` mode, the command string is wrapped in a `bwrap-sandbox.sh` call. In script mode, `#SBATCH` directives are extracted from the original script, a wrapper script is generated that calls `bwrap-sandbox.sh` with the original script as payload, and the wrapper is submitted to the real `sbatch`.

**srun:** The wrapper separates srun flags from the user command (with or without a `--` separator), then calls the real `srun` with bwrap wrapping the command on the compute node.

### Protection

The sandbox directory (`~/.claude/sandbox/`) is mounted **read-only** inside the sandbox. The agent cannot modify the wrapper scripts, config, or bin stubs.

The real Slurm binaries at `/usr/bin/sbatch` and `/usr/bin/srun` are **relocated** inside the sandbox to an obscure internal path and replaced with redirector scripts. This means even calling `/usr/bin/sbatch` by absolute path still goes through the sandbox wrappers. The agent would need to discover and call the internal path directly to bypass the wrappers — something it has no reason to do unless specifically instructed.

---

## Agent Awareness (CLAUDE.md)

The sandbox automatically injects instructions into the agent's `CLAUDE.md` — **without modifying your actual CLAUDE.md file**. It works by overlaying a merged copy (your original + sandbox instructions) at startup via bwrap's mount namespace. Outside the sandbox, your CLAUDE.md is completely unchanged.

This means the agent:

- Knows it can only write to `$SANDBOX_PROJECT_DIR`
- Knows to tell you which `sandbox.conf` setting to change if it needs access to something blocked
- Won't waste time trying to access credentials that don't exist

The sandbox-specific instructions live in `~/.claude/sandbox/sandbox-claude.md`. Edit that file to customize what the agent sees:

```bash
$EDITOR ~/.claude/sandbox/sandbox-claude.md
```

---

## Troubleshooting

### "bwrap: No such file or directory"
Install bubblewrap: `brew install bubblewrap`

### "bwrap: Creating new namespace failed: Operation not permitted"
The kernel doesn't allow unprivileged user namespaces. Check: `cat /proc/sys/kernel/unprivileged_userns_clone` — it must be `1`. On gizmo, this is enabled by default.

### "setting up uid map: Permission denied" (Ubuntu 24.04+)
Ubuntu 24.04 sets `kernel.apparmor_restrict_unprivileged_userns = 1` by default, which blocks bwrap even when `unprivileged_userns_clone = 1`. This requires a sysadmin fix:

**Option 1 — AppArmor profile (recommended):** Create `/etc/apparmor.d/bwrap`:
```
abi <abi/4.0>,
include <tunables/global>
profile bwrap /path/to/bwrap flags=(unconfined) {
  userns,
}
```
Replace `/path/to/bwrap` with the output of `which bwrap`. Then run `sudo apparmor_parser -r /etc/apparmor.d/bwrap`.

**Option 2 — Disable globally:** `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (persist with `/etc/sysctl.d/99-userns.conf`).

### Slurm commands fail with "Authentication error"
The munge socket at `/run/munge/` must be accessible. The sandbox binds `/run` by default. If you're on a non-standard setup, check that `/run/munge/munge.socket.2` exists.

### "Read-only file system" when writing
By design. Only `$SANDBOX_PROJECT_DIR` and `~/.claude/` are writable. If the agent needs to write somewhere else, either change `--project-dir` or add the path to `HOME_WRITABLE` in `sandbox.conf`.

### Module commands don't work
The sandbox passes through `BASH_ENV=/app/lmod/lmod/init/bash` which auto-initializes lmod in bash scripts. If using a different shell, source the appropriate lmod init file.

### "No such file or directory" for a tool
The tool's directory isn't mounted. Check if it's under a path in `READONLY_MOUNTS` or `HOME_READONLY`. Add it to the appropriate list in `sandbox.conf`.

### Can't create new conda/mamba environments
Mamba root (`$MAMBA_ROOT_PREFIX`) is read-only. Create environments outside the sandbox, then use them inside it.

---

## Security Summary

| Threat | Protection | Strength |
|---|---|---|
| Agent reads SSH keys | `~/.ssh` hidden by tmpfs blanking | **Hard** — kernel-enforced mount namespace |
| Agent reads API tokens from env | `BLOCKED_ENV_VARS` unset in sandbox | **Hard** — bwrap `--unsetenv` |
| Agent reads `~/.aws` credentials | Hidden by tmpfs blanking | **Hard** |
| Agent writes to other projects | NFS mounted read-only; only project dir writable | **Hard** |
| Agent reads other users' data | Only mounted paths are visible | **Hard** |
| Slurm job bypasses sandbox | `sbatch`/`srun` replaced at PATH and `/usr/bin/` level; real binaries relocated | **Soft** — covers normal usage; munge auth still available (see [Admin Hardening](ADMIN_HARDENING.md)) |

**Bottom line:** Filesystem isolation is kernel-enforced. Slurm wrapping covers normal code paths but is ultimately soft because munge authentication is available inside the sandbox. See [Admin Hardening Options](ADMIN_HARDENING.md) for stronger approaches.

---

## Appendix: Sandbox Backend Comparison

| Tool | Available? | Pros | Cons |
|---|---|---|---|
| **[Bubblewrap](https://github.com/containers/bubblewrap)** | ✅ Yes (Homebrew) | Strongest isolation (mount namespace), paths hidden entirely, supports file overlays | Requires unprivileged user namespaces; blocked by AppArmor on Ubuntu 24.04+ |
| **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** | ✅ Yes (kernel ≥ 5.13) | No root needed, works on Ubuntu 24.04 despite AppArmor, pure kernel LSM | Blocked paths return EACCES not ENOENT; no mount overlays |
| **[Firejail](https://firejail.wordpress.com/)** | ❌ No | Feature-rich, profile-based | Requires setuid root or CAP_SYS_ADMIN |
| **[Apptainer/Singularity](https://apptainer.org/)** | ✅ Yes (lmod) | Full container, HPC-native | Heavy — requires container images, path mapping |
| **Docker** | ❌ No | Industry standard | Requires root daemon; not available on shared HPC |

The sandbox auto-detects the best available backend. Bubblewrap is preferred for its stronger isolation (mount namespace hides paths entirely). Landlock is the fallback for systems where AppArmor blocks unprivileged user namespaces — it provides equivalent security through a different mechanism (LSM-based access control).
