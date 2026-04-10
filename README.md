# Sandboxing AI Coding Agents on HPC

> **Disclaimer:** This sandbox is a best-effort, user-space isolation layer. It is **not** a security product and comes with **no guarantees**. It reduces the attack surface of AI coding agents on shared HPC systems, but it cannot prevent all possible bypasses — see the [Security Summary](#security-summary) and [Admin Hardening Options](ADMIN_HARDENING.md) for known limitations. Use at your own risk.

## Why Sandbox?

AI coding agents (Claude Code, Codex, Gemini, Aider, OpenCode, and others) are powerful — they read files, write code, run commands, and submit Slurm jobs on your behalf. But on a shared HPC system, your user account has access to a lot more than any single project needs:

- **SSH keys** (`~/.ssh/`) — access to GitHub, remote servers, other clusters
- **Cloud credentials** (`~/.aws/`, API tokens) — access to S3, cloud services
- **GPG keys** (`~/.gnupg/`) — signing identity
- **All lab data** — including other people's projects, possibly clinical data
- **Environment secrets** — `GITHUB_PAT`, `OPENAI_API_KEY`, etc.
- **User enumeration & profile extraction** — LDAP/AD directories expose every user on the cluster (`getent passwd`, `finger`); an agent can extract real names, home directory paths, login history, and organizational structure for thousands of users

An agent working on one project shouldn't be able to read your SSH keys, exfiltrate API tokens, enumerate users on the cluster, or accidentally overwrite someone else's data. A **sandbox** restricts the agent to only what it needs.

### Why Not a Full Container?

Docker provides strong isolation but requires root and is unavailable on shared HPC. Apptainer (the HPC container runtime) was designed for reproducibility, not containment. Its default configuration shares PID space, network, home directory, `/tmp`, and environment variables with the host, and applies no seccomp filter. The isolation is not actually stronger out of the box. See the [detailed comparison](APPTAINER_COMPARISON.md). On top of that, containers introduce significant friction on HPC:

| Problem | Container Impact | Sandbox |
|---|---|---|
| **Filesystem mapping** | Must explicitly map every NFS path, home dir, scratch — get it wrong and paths differ inside vs. outside | Same filesystem, same paths. No mapping needed. |
| **Path consistency** | Scripts that reference NFS paths may break inside the container if mounts differ | All paths are identical inside and outside. |
| **Software stack** | Must install tools inside the image, or map `/app` — versions may conflict | Directly uses `/app`, lmod, your Homebrew — everything just works. |
| **Image maintenance** | Must rebuild images when tools change | Nothing to rebuild. |
| **Starting agents** | Must install and configure each agent inside each container image | `sandbox-exec.sh -- claude` — that's it. Works with any agent. |
| **Slurm integration** | Either Slurm is inaccessible inside the container — making interactive agents on the login node pointless since they can't submit compute jobs — or jobs escape the container and run unsandboxed on compute nodes, defeating the isolation entirely | `sbatch`/`srun` are transparently wrapped so compute-node jobs inherit the same sandbox restrictions |

The sandbox gives you **kernel-enforced filesystem isolation** with none of the path-mapping headaches. The agent sees the exact same filesystem as you, minus the secrets.

### The Slurm Problem

Filesystem isolation on the login node is only half the story. The main point of HPC is submitting work to compute nodes via Slurm. If the agent can run `sbatch` or `srun`, and those jobs execute **outside** the sandbox, then all restrictions are trivially bypassed — the agent just submits a job that reads `~/.ssh` on the compute node.

This sandbox solves the Slurm problem with the **chaperon** — a zero-trust Slurm proxy that runs *outside* the sandbox and handles all job submission on behalf of the sandboxed process. Inside the sandbox, the munge authentication socket is blocked, all Slurm binaries are hidden or blacklisted, and Slurm configuration files are removed. The only way to submit jobs is through stub scripts that communicate with the chaperon via named pipes in a per-session temp directory (chmod 700, unpredictable response FIFO names). The chaperon validates arguments against a whitelist of safe sbatch flags, wraps every job in `sandbox-exec.sh` so compute-node jobs inherit the same sandbox, and rejects dangerous flags like `--uid`, `--get-user-env`, `--container`, and `--export`.

Despite the heavy filtering, **the user-facing experience is indistinguishable from calling Slurm directly**: the sandboxed agent runs `sbatch`/`srun`/`squeue`/etc. exactly as it would outside the sandbox, sees the same exit codes, and reads stdout/stderr identical to what the real tools would print. All of the validation, scoping, and wrapping happens transparently in the chaperon.

For the full architecture and security analysis, see [Chaperon: Secure Slurm Proxy](CHAPERON.md).

---

## Installation

### Prerequisites

- Linux HPC with Slurm (kernel ≥ 3.8)
- **Bubblewrap backend** (recommended): `sudo apt install bubblewrap` or `sudo dnf install bubblewrap`. Requires unprivileged user namespaces. On Ubuntu 24.04+, AppArmor may need an admin profile — see [Troubleshooting](#setting-up-uid-map-permission-denied-ubuntu-2404).
- **Firejail backend**: `sudo apt install firejail` (setuid root binary). Works when AppArmor blocks unprivileged user namespaces.
- **Landlock backend**: kernel ≥ 5.13 (Ubuntu 22.04+), Python 3. No install needed but weakest isolation.

**No root access?** Install bubblewrap via [Homebrew](https://brew.sh/) — no sudo needed:
```bash
mkdir -p ~/.linuxbrew
curl -fsSL https://github.com/Homebrew/brew/tarball/master \
  | tar xz --strip-components=1 -C ~/.linuxbrew
eval "$(~/.linuxbrew/bin/brew shellenv)"  # add to .bashrc to persist
brew install bubblewrap
```

### One-Command Setup

```bash
# Clone the repo (if you haven't already)
git clone git@github.com:settylab/agent_sandbox.git

# Run the installer
bash agent_sandbox/install.sh
```

The installer:
1. Detects available backends (bwrap, firejail, landlock) and shows install guidance if none found
2. Copies scripts to `~/.config/agent-sandbox/`
3. Installs agent profiles (Claude, Codex, Gemini, Aider, OpenCode)
4. Creates `~/.config/agent-sandbox/sandbox.conf` (your personal config — won't overwrite)
5. Runs the test suite to verify everything works

### What Gets Installed

```
~/.config/agent-sandbox/
├── sandbox.conf          # ← Your permissions config — edit this
├── sandbox-lib.sh        # Core library (config loading, backend detection)
├── sandbox-exec.sh       # Main entry point (auto-selects backend)
├── test.sh               # Test suite
├── agents/               # Agent profiles (auto-detected at sandbox start)
│   ├── claude/           # Claude Code — merges CLAUDE.md + settings.json
│   ├── codex/            # OpenAI Codex CLI — merges AGENTS.md, unblocks OPENAI_API_KEY, CODEX_API_KEY
│   ├── gemini/           # Google Gemini CLI — merges GEMINI.md, unblocks GOOGLE_API_KEY
│   ├── aider/            # Aider — unblocks OPENAI_API_KEY, ANTHROPIC_API_KEY
│   └── opencode/         # OpenCode — unblocks OPENAI_API_KEY, ANTHROPIC_API_KEY
├── backends/
│   ├── bwrap.sh          # Bubblewrap backend (mount namespace isolation)
│   ├── firejail.sh       # Firejail backend (setuid sandbox, namespaces + seccomp)
│   ├── landlock.sh       # Landlock backend (LSM filesystem restrictions)
│   ├── landlock-sandbox.py  # Landlock syscall helper (Python)
│   └── generate-seccomp.py  # Seccomp BPF filter generator (for bwrap)
├── chaperon/             # Secure Slurm proxy (see CHAPERON.md)
│   ├── chaperon.sh       # Main loop (runs OUTSIDE sandbox)
│   ├── protocol.sh       # CHAPERON/1 wire protocol primitives
│   ├── handlers/         # Request handlers (sbatch, srun, scancel, etc.)
│   └── stubs/            # PATH-shadowing stubs (all talk to chaperon)
├── bin/                  # Fallback PATH shadows (delegate to stubs)
```

### Backends

The sandbox supports three backends, auto-detected at startup (in priority order):

| Backend | How it works | Requirements | Blocked paths show as |
|---|---|---|---|
| **bwrap** | Mount namespace isolation — hides paths entirely | `unprivileged_userns_clone=1`, no AppArmor userns restriction | `ENOENT` (No such file) |
| **firejail** | Setuid sandbox — namespaces + seccomp-bpf | `firejail` installed with setuid root | `ENOENT` (No such file) |
| **landlock** | Landlock LSM — kernel-enforced filesystem ACLs | Kernel ≥ 5.13, Python 3 | `EACCES` (Permission denied) |

All three provide kernel-enforced filesystem isolation. The auto-detection tries bwrap first, then firejail, then landlock — picking whichever works on your system. Each has trade-offs — see [Backend Comparison](#appendix-sandbox-backend-comparison) for details.

To force a backend: set `SANDBOX_BACKEND="firejail"` in `sandbox.conf` or use `--backend firejail` on the command line.

### Updating

To pick up newer scripts from the repo:

```bash
cd /path/to/agent_sandbox && git pull
bash install.sh
```

Your `sandbox.conf` is never overwritten, so your customizations are preserved.

### Running Tests

The test suite verifies filesystem isolation, environment blocking, Slurm binary isolation, and overlay generation:

```bash
bash test.sh            # run all tests (from the repo directory)
bash test.sh --verbose   # show details on failure
```

---

## Quick Start

### Start an Agent in the Sandbox

```bash
cd /path/to/my-project

# Claude Code
~/.config/agent-sandbox/sandbox-exec.sh -- claude

# OpenAI Codex
~/.config/agent-sandbox/sandbox-exec.sh -- codex

# Google Gemini
~/.config/agent-sandbox/sandbox-exec.sh -- gemini

# Or add an alias to .bashrc:
# alias agent-sandbox='~/.config/agent-sandbox/sandbox-exec.sh --'
# Then: agent-sandbox claude
```

The agent starts in your project directory with full read access to the HPC but write access **only** to that directory (plus ephemeral writes anywhere in `$HOME` — see [Home Access Modes](#home-access-modes)). SSH keys, API tokens, and credentials are invisible. Agent profiles are auto-detected — if both Claude and Codex are installed, both profiles activate simultaneously (each gets its own writable paths and credential access).

### Verify the Sandbox

```bash
~/.config/agent-sandbox/sandbox-exec.sh -- ls ~/.ssh        # → No such file / Permission denied
~/.config/agent-sandbox/sandbox-exec.sh -- bash -c 'echo $GITHUB_PAT'  # → (empty)
~/.config/agent-sandbox/sandbox-exec.sh -- squeue --me       # → works (Slurm accessible)
```

---

## Configuration

All sandbox permissions are in **one file**: `~/.config/agent-sandbox/sandbox.conf`. Edit it to match your environment:

```bash
$EDITOR ~/.config/agent-sandbox/sandbox.conf
```

Changes take effect the next time you start a sandbox — no reinstall needed.

### Home Access Modes

The `HOME_ACCESS` setting in `sandbox.conf` controls how much of your home directory the agent can see and modify:

| Mode | Real files visible? | Agent can write? | Writes persist? | Use case |
|------|-------------------|-----------------|-----------------|----------|
| **`tmpwrite`** (default) | Only listed paths | Anywhere in `$HOME` | **No** — lost on exit | Recommended: agents can create dotfiles, caches, lock files without errors, but nothing leaks between sessions |
| `restricted` | Only listed paths | Only listed writable paths | Yes | Maximum lockdown — unlisted writes get "Read-only file system" errors |
| `read` | Everything | Only listed writable + project dir | Yes | Agent needs to read arbitrary dotfiles or configs |
| `write` | Everything | Everything | Yes | Full access — use with caution |

The default `tmpwrite` mode blanks `$HOME` with a tmpfs, re-mounts only the paths in `HOME_READONLY` and `HOME_WRITABLE`, but leaves the tmpfs writable. This means the agent can freely create files (lock files, caches, temp directories) anywhere in `$HOME`, but those writes vanish when the sandbox exits. Real home content not in the mount lists remains hidden. Credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`) are always blocked regardless of mode.

Override per-session via environment: `HOME_ACCESS=read sandbox-exec.sh -- bash`

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

---

## How It Works

### Isolation by Resource

| Resource | bwrap | firejail | landlock |
|---|---|---|---|
| **Filesystem (read)** | Hidden (ENOENT) | Hidden (ENOENT) | Blocked (EACCES) |
| **Filesystem (write)** | Project dir only | Project dir only | Project dir only |
| **Environment variables** | Blocked | Blocked | Blocked |
| **PID namespace** | Isolated | Isolated | Host PIDs visible |
| **Network** | Not isolated | Not isolated | Not isolated |
| **`/run` (system sockets)** | tmpfs + selective bind (munge, nscd, resolved) | Blacklist (dbus, systemd, containerd) | Full access |
| **Abstract Unix sockets** | Accessible | Accessible | Accessible |
| **IPC / `/dev/shm`** | Isolated | Isolated | Shared |
| **Syscalls (seccomp)** | io_uring + userfaultfd + kexec blocked (generated BPF filter) | Built-in + io_uring + userfaultfd + kexec blocked | io_uring + userfaultfd + kexec + ptrace + process_vm_readv/writev (kernel ≥ 5.13 only) |
| **User enumeration** | Filtered (`FILTER_PASSWD`) | Filtered (`FILTER_PASSWD`) | Not filtered |
| **Slurm (chaperon)** | Munge + binaries + config blocked; chaperon proxy | Munge + binaries + config blocked; chaperon proxy | Munge not granted; chaperon proxy |
| **Sandbox self-protection** | Read-only mount | Read-only mount | Not protected |
| **tmux** | Outer blocked, nested works | Outer blocked, nested works | Outer blocked, nested works |

**Network** is not isolated on any backend — Claude Code requires network access to communicate with the Anthropic API, and many HPC tools (Slurm, LDAP/NSS, NFS) depend on network connectivity. See [Admin Hardening](ADMIN_HARDENING.md) for network restriction options.

**Abstract Unix sockets** (`@/org/...`) bypass filesystem isolation because they live in the network namespace, not on the filesystem. Isolating them requires a separate network namespace (`--unshare-net` / `--net=none`), which would break Claude Code's API access and Slurm connectivity. On systems with `systemd --user`, an abstract D-Bus socket could be used for sandbox escape — see [Admin Hardening](ADMIN_HARDENING.md).

**IPC / `/dev/shm`** is isolated on bwrap (`--unshare-ipc` + private `/dev/shm` tmpfs) and firejail (`--ipc-namespace`). Each sandbox gets its own `/dev/shm` and SysV IPC namespace, preventing the agent from reading or corrupting shared memory of processes outside the sandbox. This is safe for HPC workloads: `sbatch` jobs run entirely within a single sandbox, so all MPI ranks, NCCL collectives, and CUDA IPC within a job share the same IPC namespace. Landlock cannot isolate IPC (no namespace support). Configurable via `PRIVATE_IPC` in `sandbox.conf` (default: `true`). When set by an admin config, users cannot weaken it to `false`.

**Environment variables:** The sandbox inherits your shell environment, blocks specific names via `BLOCKED_ENV_VARS`, and blocks credential-pattern globs via `BLOCKED_ENV_PATTERNS` (`*_TOKEN`, `SSH_*`, `CI_*`, etc.). To grant access, add the variable to `ALLOWED_ENV_VARS`.

---

## Slurm Integration (Chaperon)

Inside the sandbox, all Slurm authentication and binaries are **blocked** — munge socket hidden, `/usr/bin/sbatch` etc. blacklisted, `/etc/slurm` removed. Job submission goes through the **chaperon**, a proxy process running outside the sandbox that communicates via named pipes in a per-session temp directory.

**From the agent's perspective, Slurm looks unperturbed.** Running `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, and friends from inside the sandbox behaves as if you were calling them from outside the sandbox — the stubs are invoked on PATH exactly like the real binaries, return the same exit codes, and print stdout/stderr that matches what the real tools would produce. Under the hood every call is funneled through the chaperon and heavily filtered (argument whitelisting, CWD validation, scope-filtered output, denied subcommands), but the surface presented to the agent is the unmodified Slurm CLI. The filtering is intentionally transparent: allowed commands pass through untouched, denied ones fail with an explanatory error, and scoped output is rewritten so chaperon internals never leak.

- **Stub sbatch:** Parses `--wrap` and script arguments, sends them over the `CHAPERON/1` protocol to the chaperon, prints the response. The agent calls `sbatch` as normal.
- **Stub srun:** Proxied through the chaperon like sbatch. Two modes: **allocation mode** (login node) — validates flags, wraps the command in `sandbox-exec.sh` so compute-node processes are sandboxed, then calls real srun. **Step mode** (inside an sbatch job, `SLURM_JOB_ID` set) — validates flags against a step-only whitelist and execs real srun directly for MPI/multi-process step launching. `--pty` is denied (no PTY passthrough). The chaperon runs outside the sandbox and has munge access — munge is never exposed inside the sandbox.
- **Stub scancel:** Sends cancel requests to the chaperon, which filters job IDs by scope (session, project, or user). By default, jobs submitted by any sandbox session with the same project directory can be cancelled. Configurable via `SLURM_SCOPE` in `sandbox.conf`, or as an environment variable override: `SLURM_SCOPE=session sandbox-exec.sh -- claude`.
- **Stub squeue:** Proxied through the chaperon. Output is filtered to only show jobs within scope. The agent sees only its own sandbox-submitted jobs, not other users' jobs or unrelated jobs.
- **Stub scontrol:** Proxied through the chaperon. Read-only commands (`show node`, `show partition`, `show config`) pass through. Job operations (`show job`, `hold`, `release`, `requeue`, `update job`) are scoped to chaperon-submitted jobs. Dangerous subcommands (`shutdown`, `reconfigure`, etc.) and user-enumerating targets (`show assoc_mgr`) are denied.
- **Stub sacct:** Proxied through the chaperon. Always scoped to the current user (`--user=$(whoami)` injected). `--allusers`, `--user`, and `--accounts` are denied to prevent viewing other users' job history.
- **Stub sacctmgr:** Proxied through the chaperon. Only read-only queries for cluster, QOS, TRES, and config are allowed. User/account enumeration (`show user`, `show account`, `show association`) and all write operations are denied.
- **Chaperon proxy:** Validates arguments against a whitelist of ~40 safe sbatch flags (rejects `--uid`, `--export`, `--get-user-env`, etc.), validates CWD is under the project directory, wraps the job in `sandbox-exec.sh`, and submits via the real sbatch.
- **Security:** Named pipes with per-session temp directories, the chaperon dies with its parent (PR_SET_PDEATHSIG + liveness polling), and all user data is base64-encoded in the protocol (injection-proof).

For the full architecture, protocol specification, and security analysis, see [CHAPERON.md](CHAPERON.md).

---

## Agent Profiles

The sandbox uses an auto-detection system to find installed agents and apply per-agent configurations. Each agent profile lives in `agents/<name>/` and contains:

| File | Purpose |
|------|---------|
| `detect.sh` | Returns 0 if the agent is installed/configured |
| `overlay.sh` | Config merging (e.g., CLAUDE.md + sandbox instructions) |
| `agent.md` | Sandbox instructions injected into the agent's instruction file |
| `config.conf` | Home paths, hidden files, env var unblocking (all in one) |

**How it works:** At sandbox start, all `agents/*/detect.sh` are scanned. Every matching profile's `config.conf` is merged into the global sandbox config (home paths, hidden files, env var unblocks). Then each matching agent's `overlay.sh` runs to handle config file merging.

**Credentials are isolated per-agent:** The base config blocks all API keys. Each agent's `config.conf` unblocks only what it needs — Claude uses OAuth (no env vars), Codex unblocks `OPENAI_API_KEY` and `CODEX_API_KEY`, Gemini unblocks `GOOGLE_API_KEY`.

Customize agent instructions via `~/.config/agent-sandbox/agents/<name>/agent.md`.

---

## Agent Teams / tmux

The outer tmux socket is blocked (escape risk), but a **nested tmux** running inside the sandbox works well: `sandbox-exec.sh -- tmux new-session claude` (prefix is `Ctrl-a`). On kernels < 5.4, set `BIND_DEV_PTS=true` in `sandbox.conf` for pty allocation (see Known Limitations). Customize via `~/.config/agent-sandbox/sandbox-tmux.conf`.

**Tip — long-lived Jupyter kernels for stateful experimentation:** The sandbox ships a `lab` utility (in `bin/`) that runs a project-local JupyterLab and provides CLI access to running kernels so the agent can execute code, inspect live variables, and edit notebook cells without clicking through the web UI. Two run modes:

```bash
# Mode 1: user starts lab in a tmux pane inside the sandbox
sandbox-exec.sh -- tmux new-session    # nested tmux
lab kernel add && lab                   # foreground JupyterLab
# agent (in another pane) attaches to the running kernel:
lab kernel exec -n analysis.ipynb "df.describe()"

# Mode 2: agent starts lab in the background
lab kernel add && lab start             # daemonize (agent does this)
lab notebook attach analysis.ipynb      # spawn kernel
lab kernel exec -n analysis.ipynb "df = pd.read_csv('data.csv')"
```

On multi-user machines, pick a unique port to avoid collisions: `PORT=9012 lab start`. Variables, loaded dataframes, and model state persist between turns — load once, iterate cheaply. Both the kernel and the agent share the same sandboxed filesystem view, so the isolation guarantees hold. Run `lab help` for the full command list.

---

## Troubleshooting

### "bwrap: No such file or directory"

Install bubblewrap via your system package manager (needs root):
```bash
sudo apt install bubblewrap    # Debian/Ubuntu
sudo dnf install bubblewrap    # RHEL/Fedora/Rocky
```

**No root access?** Install via [Homebrew](https://brew.sh/) (a package manager that installs into your home directory — no root needed, widely used on HPC clusters for user-local tools):
```bash
# Install Homebrew to ~/.linuxbrew (one-time, ~2 min)
# The default installer tries /home/linuxbrew/.linuxbrew which needs sudo.
# Setting the prefix explicitly installs under your home directory instead.
mkdir -p ~/.linuxbrew
curl -fsSL https://github.com/Homebrew/brew/tarball/master | tar xz --strip-components=1 -C ~/.linuxbrew

# Add to PATH (add this to your .bashrc/.zshrc to persist across sessions)
eval "$(~/.linuxbrew/bin/brew shellenv)"

# Install bubblewrap
brew install bubblewrap
```
Homebrew installs to `~/.linuxbrew/` and doesn't touch system directories. The sandbox auto-detects bwrap from `$PATH` including `~/.linuxbrew/bin/`.

### "bwrap: Creating new namespace failed: Operation not permitted"
The kernel doesn't allow unprivileged user namespaces. Check: `cat /proc/sys/kernel/unprivileged_userns_clone` — it must be `1`.

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

### Slurm commands fail inside the sandbox
By design, `sbatch` inside the sandbox goes through the chaperon proxy. If it fails, check that the chaperon started successfully (look for "chaperon:" prefixed errors in stderr). The munge socket is intentionally blocked inside the sandbox — Slurm authentication happens in the chaperon, which runs outside. If `sbatch` fails with authentication errors, ensure `/run/munge/munge.socket.2` exists on the host.

### "Read-only file system" when writing
By design. Only `$SANDBOX_PROJECT_DIR` and agent-specific directories are writable. To grant write access elsewhere, add the path to `HOME_WRITABLE` (for entries under `$HOME`) or `EXTRA_WRITABLE_PATHS` (for paths outside `$HOME`, e.g. scratch directories) in `sandbox.conf`. Alternatively, run with a different `--project-dir`.

### Module commands don't work
The sandbox passes through `BASH_ENV` (typically pointing to the lmod init script, e.g. `/app/lmod/lmod/init/bash`) which auto-initializes lmod in bash scripts. If `module` isn't available, check that `BASH_ENV` is set correctly for your site's lmod installation. For non-bash shells, source the appropriate lmod init file.

### "No such file or directory" for a tool
The tool's directory isn't mounted. Check if it's under a path in `READONLY_MOUNTS` or `HOME_READONLY`. Add it to the appropriate list in `sandbox.conf`.

### Can't create new conda/mamba environments
Mamba root (`$MAMBA_ROOT_PREFIX`) is read-only by default. Rather than opening it up, prefer **project-specific environments** that live inside `$SANDBOX_PROJECT_DIR` — they're isolated, reproducible, and writable without any config changes. [`uv`](https://docs.astral.sh/uv/) is a good fit: `uv venv .venv && uv pip install ...` creates a per-project Python environment in seconds, and `uv`'s cache (`~/.cache/uv`) is already writable in the default `HOME_WRITABLE`. The agent itself can set this up for you — just ask it to "create a uv environment for this project and install <packages>". If you really need shared mamba envs, either create them outside the sandbox and use them inside (read-only is fine for activation), or add `$MAMBA_ROOT_PREFIX` to `HOME_WRITABLE` in `sandbox.conf`.

---

## Security Summary

| Threat | Protection | Strength |
|---|---|---|
| Agent reads SSH keys | Hidden (bwrap/firejail: ENOENT) or blocked (Landlock: EACCES) | **Hard** — kernel-enforced |
| Agent reads API tokens from env | `BLOCKED_ENV_VARS` + `BLOCKED_ENV_PATTERNS` removed from environment | **Hard** — all backends |
| Agent reads `~/.aws` credentials | Hidden or blocked (same as SSH keys) | **Hard** |
| Agent writes to other projects | Only project dir is writable | **Hard** |
| Agent reads other users' data | Only explicitly allowed paths are accessible | **Hard** |
| User enumeration & profile extraction | LDAP/AD directories (`/etc/passwd`, `finger`) are hidden or restricted (bwrap/firejail/landlock) | **Hard** — prevents agent from mapping organizational structure or extracting real names and login history |
| Extraction of other users' data | Shared filesystems (NFS, Lustre) are restricted; only the project directory and specified paths are accessible | **Hard** — prevents credential-based access to other lab members' data |
| Agent escapes via Unix sockets | Bwrap/firejail: filesystem-based sockets (e.g. `/run/dbus`) hidden by mount namespace, but abstract sockets (`@/org/...`) remain accessible (shared network namespace). **Landlock: full escape** — `systemd-run --user` executes outside sandbox (reads `~/.ssh`, `~/.aws`, submits Slurm jobs). See [Admin Hardening §0](ADMIN_HARDENING.md) | **Partial** (bwrap/firejail) / **None** (Landlock) |
| Agent escapes via PID namespace | Bwrap/firejail: isolated PID namespace. Landlock: host PIDs visible | **Hard** (bwrap/firejail) / **None** (Landlock) |
| Agent uses dangerous syscalls | All backends block `io_uring`, `userfaultfd`, `kexec` via seccomp-bpf. Firejail: built-in. Landlock: custom filter in `landlock-sandbox.py` (requires kernel ≥ 5.13). Bwrap: generated filter via `generate-seccomp.py` | **Hard** — all backends |
| Slurm job bypasses sandbox | Chaperon proxy: munge socket blocked (bwrap/firejail), Slurm binaries blocked (bwrap/firejail), argument whitelisting, all jobs wrapped in sandbox-exec.sh. **Landlock: chaperon fully bypassable** — munge socket reachable and Slurm binaries callable | **Hard** (bwrap/firejail) / **None** (Landlock — see [Admin Hardening](ADMIN_HARDENING.md) §1 for SPANK plugin enforcement) |
| Agent tampers with sandbox scripts | Read-only mount (bwrap/firejail) / not protected (Landlock) | **Hard** (bwrap/firejail) / **None** (Landlock) — see [Admin Hardening](ADMIN_HARDENING.md) §2 |
| SSH escape (if `~/.ssh` exposed) | Not protected — sandbox does not restrict network | **None** — agent can SSH to localhost or other nodes to get an unsandboxed shell. **Do not expose `~/.ssh`** unless you understand this risk. |

**Bottom line:** Filesystem isolation is kernel-enforced with all three backends. Bwrap/firejail add mount + PID namespace isolation. Landlock works without admin privileges but provides filesystem-only isolation. Slurm job submission is enforced by the chaperon proxy on bwrap/firejail — munge auth is blocked inside the sandbox, so there is no way to submit jobs without going through the validated, wrapped path. **On Landlock, the chaperon is fully bypassable** — Landlock cannot block `AF_UNIX connect()`, so the munge socket is reachable and `/usr/bin/sbatch` is directly callable. Landlock deployments with Slurm require [Admin Hardening](ADMIN_HARDENING.md) §1 (SPANK plugin) for server-side enforcement. For comparison with Apptainer, see [Sandbox vs. Apptainer](APPTAINER_COMPARISON.md).

**Accepted risks (all backends):** Fileless execution via `memfd_create` (needed by CUDA/PyTorch/JAX). `/proc/net` information disclosure (needed for network stack). Abstract Unix sockets accessible (shared network namespace required for DNS/NSS). See the [pentest reports](pentest/) for detailed findings and analysis per backend.

---

## Appendix: Sandbox Backend Comparison

| Tool | Available? | Pros | Cons |
|---|---|---|---|
| **[Bubblewrap](https://github.com/containers/bubblewrap)** | `apt`/`dnf`/`brew` | Mount namespace isolation, paths hidden entirely (ENOENT), file overlays, Slurm binary relocation, sandbox self-protection, seccomp via generated BPF filter (io_uring/userfaultfd/kexec) | Requires unprivileged user namespaces; blocked by AppArmor on Ubuntu 24.04+ without admin help |
| **[Firejail](https://firejail.wordpress.com/)** | ✅ Yes (`apt install`) | Mount namespace (ENOENT), PID namespace, built-in seccomp + io_uring + userfaultfd blocked, caps dropping, works when AppArmor blocks user namespaces | Requires setuid root binary |
| **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** | ✅ Yes (kernel ≥ 5.13) | No root or admin needed, works on Ubuntu 24.04 despite AppArmor, pure kernel LSM, no external dependencies (Python 3 only) | No mount namespace — blocked paths return EACCES not ENOENT, no file overlays, no PID isolation, no Slurm binary relocation, no sandbox self-protection, cannot block Unix socket connect (**chaperon fully bypassable** — see [Admin Hardening](ADMIN_HARDENING.md)) |
| **[Apptainer/Singularity](https://apptainer.org/)** | ✅ Yes (lmod) | Full container, HPC-native | Heavy — requires container images, path mapping |
| **Docker** | ❌ No | Industry standard | Requires root daemon; not available on shared HPC |

Auto-detection priority: bwrap → firejail → landlock. All three provide kernel-enforced filesystem isolation. Force a backend with `SANDBOX_BACKEND` in `sandbox.conf` or `--backend` on the command line.

### Known Limitations

Sorted by perceived severity (security impact first, then operational issues).

| Backend | Limitation | Mitigation |
|---|---|---|
| **All** | Network not isolated — agent can exfiltrate data via HTTP, reach cloud metadata endpoints (169.254.169.254), access internal services, or SSH to an unsandboxed shell if `~/.ssh` is exposed. Claude Code requires network for its API, so full isolation is not possible without a dedicated network namespace with selective forwarding | Do not expose `~/.ssh`; limit keys to single-service scopes (e.g. GitHub deploy keys only). See [Admin Hardening](ADMIN_HARDENING.md) for iptables/nftables templates to block metadata endpoints and restrict outbound connections |
| **Firejail** | Setuid-root binary with a significant [CVE history](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html) (18 CVEs, 12 local root exploits). Installing firejail adds a privileged attack surface to every node | Prefer bwrap where possible. See [Apptainer Comparison](APPTAINER_COMPARISON.md#security-track-record) for the full CVE breakdown |
| **Landlock** | Cannot block `AF_UNIX connect()` — **full sandbox escape** via `systemd-run --user` if `user@.service` is running (reads `~/.ssh`, `~/.aws`, writes arbitrary files with no Landlock restrictions). Also bypasses chaperon (munge socket reachable) | **Use bwrap or firejail.** If Landlock-only: [Admin Hardening §0](ADMIN_HARDENING.md) (mask `user@.service`) is **mandatory** |
| **Landlock** | No sandbox self-protection — agent can modify wrapper scripts. Current session is safe (kernel rules are irrevocable), but future sessions could be compromised | Use bwrap or firejail |
| **Landlock** | No PID namespace — host processes visible via `/proc`. Agent could read `/proc/PID/environ` of same-UID processes (e.g. sbatch wrapper injecting bypass token) | Use bwrap or firejail for PID isolation; token exposure window is microseconds. A SPANK plugin would eliminate it entirely |
| **bwrap** | Supplementary groups display as `nogroup` (65534) inside the sandbox. Unprivileged bwrap always creates a user namespace (required to obtain mount/PID namespaces without root), and that namespace can only map the caller's own UID/GID. All other GIDs appear unmapped. **File permissions still work correctly** — the kernel uses host credentials for filesystem access, so group-owned directories remain fully accessible. Only display tools (`id`, `ls -l`) are affected | Cosmetic only — no functional impact. A privileged bwrap installation (setuid or `CAP_SYS_ADMIN`) could avoid the user namespace entirely, preserving group display |
| **bwrap** | Seccomp filter generated at runtime (`generate-seccomp.py`) rather than built-in — see [Seccomp for bwrap](ADMIN_INSTALL.md#seccomp-for-bwrap) | Verify the filter loads (no "seccomp" warnings on stderr at startup) |
| **All** | `memfd_create` not blocked by any backend (HPC compatibility). `process_vm_readv/writev` blocked only on Landlock (no PID namespace to mitigate). Docker's default seccomp profile makes similar trade-offs | Accepted trade-off. `memfd_create` needed by CUDA, PyTorch, JAX. `process_vm_readv/writev` needed by MPI (mitigated by PID namespace in bwrap/firejail, blocked by seccomp on Landlock). See [Admin Hardening](ADMIN_HARDENING.md) |
| **bwrap** (`BIND_DEV_PTS=true`) | Host `/dev` exposure — required for tmux on kernels < 5.4. On kernels < 6.2, `TIOCSTI` ioctl allows keystroke injection into same-user terminals outside the sandbox | Default `false` (safe). Upgrade to kernel ≥ 5.4 to avoid the need, or ≥ 6.2 to disable TIOCSTI entirely |
| **Landlock** | Host `/dev/pts/*` always visible (no mount namespace). On kernels < 6.2, `TIOCSTI` ioctl allows keystroke injection into same-user terminals — unlike bwrap, this is not opt-in | Kernel ≥ 6.2 disables TIOCSTI system-wide. Use bwrap or firejail for private `/dev` |
| **All** | Agent config directories (e.g., `~/.claude/`, `~/.codex/`) are writable (required for agents to function). An agent in one project can read session data from other projects | Inherent requirement — agents need write access to their config directories. Cross-project data access could be mitigated by per-project config copies |
| **Landlock** | `/dev/shm` is writable and shared (no IPC namespace) — could be used for covert cross-sandbox communication or to read/corrupt shared memory of same-UID processes | Use bwrap or firejail (both isolate IPC via `PRIVATE_IPC=true`, the default) |
| **Landlock** | User enumeration via LDAP/AD — `getent passwd` reveals all directory users | No mount namespace to overlay files or block sockets; set `FILTER_PASSWD=false` if LDAP lookups are needed |
| **Landlock** | `BLOCKED_FILES` has no effect — file overlays require a mount namespace, which Landlock doesn't have. Files listed in `BLOCKED_FILES` remain readable | Use bwrap or firejail for file-level hiding |
| **Landlock** | `PRIVATE_TMP` has no effect — `/tmp` isolation requires a mount namespace. Sandboxed processes share the host `/tmp` | Use bwrap or firejail if `/tmp` isolation is needed |
| **Landlock** | **Chaperon fully bypassable** — Landlock cannot block `AF_UNIX connect()`, so the munge socket (`/run/munge/munge.socket.2`) is reachable despite not being in the Landlock allowlist. Combined with directly callable Slurm binaries (`/usr/bin/sbatch`), agents can forge munge credentials and submit arbitrary unwrapped jobs, completely bypassing the chaperon | **Use bwrap or firejail.** If Landlock is the only option, [Admin Hardening](ADMIN_HARDENING.md) §1 (SPANK plugin) is **mandatory** for Slurm environments |
| **bwrap/Firejail** | `/tmp` isolated by default (`PRIVATE_TMP=true`) — breaks MPI shared-memory transport and NCCL inter-GPU sockets | Set `PRIVATE_TMP=false` in `sandbox.conf` for HPC multi-process workloads |
| **All** | Environment variable blocking uses explicit names (`BLOCKED_ENV_VARS`) and glob patterns (`BLOCKED_ENV_PATTERNS` — e.g. `*_TOKEN`, `SSH_*`, `CI_*`). Patterns catch most credential conventions automatically, but secrets with unusual names may slip through | Review your environment (`env \| grep -iE 'token\|key\|secret\|auth'`), add names to `BLOCKED_ENV_VARS` or patterns to `BLOCKED_ENV_PATTERNS`, and use `ALLOWED_ENV_VARS` to override. See [Admin Hardening](ADMIN_HARDENING.md) for an allowlist approach |
| **All** | No resource exhaustion limits by default — a sandboxed process can consume unlimited CPU, memory, processes, and disk space in the project directory | Set `SANDBOX_NPROC_LIMIT` in `sandbox.conf` for fork bomb defense. See [Admin Hardening](ADMIN_HARDENING.md) for cgroup-based limits. Slurm-submitted jobs are limited by the scheduler |
| **All** | No audit/logging trail — there is no persistent log of sandbox sessions, chaperon requests, or denied access attempts | The chaperon prints errors to stderr per-request but does not persist them. Consider redirecting to a log file or using `logger` for syslog integration |
| **All** | `srun --pty` (interactive PTY) is not supported through the chaperon protocol. Some advanced srun flags may be blocked — check the denied list in [CHAPERON.md](CHAPERON.md) if a launch fails | Use `sbatch` for interactive-like workflows, or `srun` without `--pty` for non-interactive execution |
| **All** | Chaperon temp files (wrapper scripts, original scripts) in `$TMPDIR` persist after SIGKILL since the cleanup trap cannot fire | Stale files are named `chaperon-*` in `$TMPDIR`; periodic cleanup recommended on NFS-backed tmp |
| **Firejail** | `FILTER_PASSWD=true` blocks NSS daemon sockets (nscd, nslcd, sssd) on LDAP/AD clusters where the current user is not in local `/etc/passwd`, breaking user/group resolution and Slurm | Set `FILTER_PASSWD=false` in `sandbox.conf` on LDAP clusters, or prefer bwrap which overlays a pre-generated `/etc/passwd` |
