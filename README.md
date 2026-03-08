# Sandboxing Claude Code Agents on Gizmo

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
| **Starting Claude** | Need to map in Claude's data dir, node binary, socket files... | `bwrap-sandbox.sh -- claude` — that's it. |
| **Slurm integration** | Either Slurm is inaccessible inside the container (making the HPC login node pointless for an interactive agent), or jobs escape the container and run unsandboxed on compute nodes — defeating the isolation entirely | `sbatch`/`srun` are transparently wrapped so compute-node jobs inherit the same sandbox restrictions |

Bubblewrap gives you **container-grade filesystem isolation** with none of the path-mapping headaches. The agent sees the exact same filesystem as you, minus the secrets.

### The Slurm Problem

Filesystem isolation on the login node is only half the story. The main point of HPC is submitting work to compute nodes via Slurm. If the agent can run `sbatch` or `srun`, and those jobs execute **outside** the sandbox, then all restrictions are trivially bypassed — the agent just submits a job that reads `~/.ssh` on the compute node.

This sandbox solves the Slurm problem by **replacing `sbatch` and `srun` on PATH** inside the sandbox. Wrapper scripts at `~/.claude/sandbox/bin/` shadow the real commands, so every job submitted by the agent automatically runs inside bwrap on the compute node. Since bwrap and all scripts live on NFS, they're available on every compute node. The sandbox directory is mounted read-only, so the agent cannot tamper with the wrappers.

#### Limitations of the Slurm Wrappers

The Slurm wrappers are **default-on but not kernel-enforced**. They work by shadowing `sbatch`/`srun` on PATH and wrapping job scripts in bwrap. This means:

- Under normal operation, the agent uses the wrappers transparently — it just calls `sbatch` and gets the sandboxed version.
- A user who **deliberately instructs** the agent to bypass the sandbox (e.g., "call `/usr/bin/sbatch` directly") can circumvent the protection.
- There is no kernel-level enforcement preventing calls to the real binaries by absolute path.

**This is a soft boundary, not a hard one.** For hard separation, you would need a dedicated `${USER}_ai` system account with its own home directory and Slurm association, so that OS-level file permissions prevent access regardless of what the agent does. Bubblewrap cannot replace OS user separation — it operates within a single user's privilege level. What it **does** provide is strong protection against accidental exposure and against the agent autonomously accessing resources it shouldn't, which covers the vast majority of real-world risk.

---

## Installation

### Prerequisites

- Fred Hutch gizmo account (or similar HPC with Linux kernel ≥ 3.8 and `kernel.unprivileged_userns_clone = 1`)
- [Homebrew (Linuxbrew)](https://brew.sh/) — for installing bubblewrap in user space

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
5. Runs a smoke test to verify everything works

### What Gets Installed

```
~/.claude/sandbox/
├── sandbox.conf          # ← Your permissions config — edit this
├── sandbox-lib.sh        # Core library (builds bwrap arguments)
├── bwrap-sandbox.sh      # Main entry point
├── sbatch-sandbox.sh     # Slurm sbatch wrapper
├── srun-sandbox.sh       # Slurm srun wrapper
├── sandbox-claude.md     # Agent instructions (overlaid into CLAUDE.md inside sandbox)
└── bin/
    ├── sbatch            # Shadows /usr/bin/sbatch inside sandbox
    └── srun              # Shadows /usr/bin/srun inside sandbox
```

### Updating

To pick up newer scripts from the repo:

```bash
cd ~/agent_container && git pull
bash ~/agent_container/install.sh
```

Your `sandbox.conf` is never overwritten, so your customizations are preserved.

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

#### Allow GitHub CLI

```bash
# In sandbox.conf — add to HOME_READONLY:
HOME_READONLY=(
    ".dotfiles"
    ".linuxbrew"
    ".local/bin"
    ".condarc"
    ".mambarc"
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

#### Use a different dotfiles directory

If your dotfiles aren't in `~/.dotfiles`:

```bash
# In sandbox.conf:
DOTFILES_DIR="$HOME/.config/dotfiles"
# or set to "" if you don't use a dotfiles repo
DOTFILES_DIR=""
```

---

## How It Works

### Mount Strategy

The sandbox uses a layered mount approach:

```
Layer 1: System mounts (read-only)
    /usr, /lib, /lib64, /bin, /sbin, /etc, /app

Layer 2: Blank home
    tmpfs on $HOME → hides EVERYTHING

Layer 3: Selective re-mount (read-only)
    ~/.dotfiles, ~/.linuxbrew, ~/.local/bin, ...

Layer 4: Writable mounts
    ~/.claude (session data + auth), project directory

Layer 5: Read-only sandbox overlay
    ~/.claude/sandbox/ → read-only (protects wrapper scripts)

Layer 6: NFS storage (read-only base)
    /fh/fast/setty_m → entire tree read-only

Layer 7: Project directory (writable overlay)
    /fh/fast/setty_m/user/you/project → writable on top of Layer 6
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

The wrappers pass all flags through unchanged and call the real `/usr/bin/sbatch` or `/usr/bin/srun` internally.

### How the Wrappers Work

**sbatch:** In `--wrap` mode, the command string is wrapped in a `bwrap-sandbox.sh` call. In script mode, `#SBATCH` directives are extracted from the original script, a wrapper script is generated that calls `bwrap-sandbox.sh` with the original script as payload, and the wrapper is submitted to the real `sbatch`.

**srun:** The wrapper separates srun flags from the user command (with or without a `--` separator), then calls the real `srun` with bwrap wrapping the command on the compute node.

### Protection

The sandbox directory (`~/.claude/sandbox/`) is mounted **read-only** inside the sandbox. The agent cannot modify the wrapper scripts, config, or bin stubs. To bypass the wrappers, the agent would need to explicitly call `/usr/bin/sbatch` by absolute path — something it would only do if specifically instructed.

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
| Slurm job bypasses sandbox | `sbatch`/`srun` on PATH replaced with wrappers; sandbox dir read-only | **Medium** — default-on, requires calling `/usr/bin/sbatch` by absolute path to bypass |
| Agent deliberately circumvents | Not fully prevented — same UID | **Soft** — requires explicit user instruction to bypass |

**Bottom line:** The sandbox provides strong, kernel-enforced protection against accidental credential exposure, data leakage, and unintended writes. It does not protect against a user who deliberately instructs the agent to bypass it. For that level of isolation, a dedicated `${USER}_ai` system account with separate OS permissions is required.

---

## Appendix: Why Bubblewrap?

We evaluated several sandboxing approaches for this environment (Linux 4.15, shared HPC, no root access):

| Tool | Available? | Pros | Cons |
|---|---|---|---|
| **[Bubblewrap](https://github.com/containers/bubblewrap)** | ✅ Yes (Homebrew) | Lightweight, user-space, per-mount control, no root needed | Not a full container; no image caching |
| **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** | ❌ No | Elegant LSM-based filesystem restrictions | Requires kernel ≥ 5.13 (we have 4.15) |
| **[Firejail](https://firejail.wordpress.com/)** | ❌ No | Feature-rich, profile-based | Requires setuid root or CAP_SYS_ADMIN |
| **[Apptainer/Singularity](https://apptainer.org/)** | ✅ Yes (lmod) | Full container, HPC-native | Heavy — requires container images, path mapping |
| **Docker** | ❌ No | Industry standard | Requires root daemon; not available on shared HPC |

Bubblewrap is the clear winner for this use case: it runs as an unprivileged user, gives fine-grained mount control, adds negligible overhead, and keeps paths identical inside and outside the sandbox. It works because the gizmo kernel has `CONFIG_USER_NS=y` and `kernel.unprivileged_userns_clone = 1`, allowing unprivileged user namespace creation.

Bubblewrap is the same tool that Flatpak uses to sandbox desktop applications on Linux. It's mature, widely deployed, and maintained as part of the [containers](https://github.com/containers) project.
