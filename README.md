# Sandboxing Claude Code Agents on HPC

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

Docker provides strong isolation but requires root and is unavailable on shared HPC. Apptainer (the HPC container runtime) was designed for reproducibility, not containment. Its default configuration shares PID space, network, home directory, `/tmp`, and environment variables with the host, and applies no seccomp filter. The isolation is not actually stronger out of the box. See the [detailed comparison](APPTAINER_COMPARISON.md). On top of that, containers introduce significant friction on HPC:

| Problem | Container Impact | Sandbox |
|---|---|---|
| **Filesystem mapping** | Must explicitly map every NFS path, home dir, scratch — get it wrong and paths differ inside vs. outside | Same filesystem, same paths. No mapping needed. |
| **Path consistency** | Scripts that reference NFS paths may break inside the container if mounts differ | All paths are identical inside and outside. |
| **Software stack** | Must install tools inside the image, or map `/app` — versions may conflict | Directly uses `/app`, lmod, your Homebrew — everything just works. |
| **Image maintenance** | Must rebuild images when tools change | Nothing to rebuild. |
| **Starting Claude** | Must install and configure Claude Code inside each container image | `sandbox-exec.sh -- claude` — that's it. |
| **Slurm integration** | Either Slurm is inaccessible inside the container — making interactive agents on the login node pointless since they can't submit compute jobs — or jobs escape the container and run unsandboxed on compute nodes, defeating the isolation entirely | `sbatch`/`srun` are transparently wrapped so compute-node jobs inherit the same sandbox restrictions |

The sandbox gives you **container-grade filesystem isolation** with none of the path-mapping headaches. The agent sees the exact same filesystem as you, minus the secrets.

### The Slurm Problem

Filesystem isolation on the login node is only half the story. The main point of HPC is submitting work to compute nodes via Slurm. If the agent can run `sbatch` or `srun`, and those jobs execute **outside** the sandbox, then all restrictions are trivially bypassed — the agent just submits a job that reads `~/.ssh` on the compute node.

This sandbox solves the Slurm problem with a two-layer approach. First, wrapper scripts at `~/.claude/sandbox/bin/` **shadow** `sbatch`/`srun` on PATH, so every job submitted by the agent automatically runs inside the sandbox on the compute node. Second, with mount-namespace backends (bwrap and firejail), the real `/usr/bin/sbatch` and `/usr/bin/srun` binaries are **relocated** to an obscure internal path (`/tmp/.sandbox-slurm-real/`) and replaced with redirector scripts — so even calling them by absolute path still goes through the sandbox wrappers. Since all scripts live on NFS, they're available on every compute node. The sandbox directory is mounted read-only, so the agent cannot tamper with the wrappers.

#### Limitations of the Slurm Wrappers

The Slurm wrappers provide strong default protection but are not fully kernel-enforced. They work by:

1. **PATH shadowing** (all backends) — `sbatch`/`srun` resolve to sandbox wrappers via PATH ordering.
2. **Binary relocation** (bwrap only) — the real ELF binaries at `/usr/bin/sbatch` and `/usr/bin/srun` are moved to an obscure internal path (`/tmp/.sandbox-slurm-real/`) and replaced with redirector scripts that funnel calls back through the sandbox wrappers. Firejail and Landlock cannot do this (firejail could in theory but uses the same PATH shadowing approach for consistency), so the real binaries remain at `/usr/bin/` and are directly callable.

With **bwrap**, even calling `/usr/bin/sbatch` by absolute path hits the sandbox wrappers. With **firejail** and **Landlock**, only PATH shadowing is available — an agent that calls `/usr/bin/sbatch` directly bypasses the wrappers. **This is a soft boundary** in all cases — Slurm authentication (munge) is available inside the sandbox. See [Admin Hardening Options](ADMIN_HARDENING.md) for approaches that can close this gap. In practice, the PATH-based wrappers cover the paths an agent would use autonomously.

---

## Installation

### Prerequisites

- Linux HPC with Slurm (kernel ≥ 3.8)
- **Bubblewrap backend**: requires `kernel.unprivileged_userns_clone = 1` and [Homebrew](https://brew.sh/) for installation. On Ubuntu 24.04+, AppArmor may also need configuration — see [Troubleshooting](#setting-up-uid-map-permission-denied-ubuntu-2404).
- **Firejail backend**: requires `firejail` installed with setuid root (`sudo apt install firejail`). Works when AppArmor blocks unprivileged user namespaces (which breaks bwrap).
- **Landlock backend**: requires kernel ≥ 5.13 (Ubuntu 22.04+). Works without root, even when AppArmor blocks user namespaces. No Homebrew needed — uses Python 3 only.

### One-Command Setup

```bash
# Clone the repo (if you haven't already)
git clone git@github.com:settylab/agent_sandbox.git

# Run the installer
bash agent_sandbox/install.sh
```

The installer:
1. Installs `bubblewrap` via Homebrew (if not already available) and copies all three backend files (bwrap, firejail, landlock)
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
├── sbatch-sandbox.sh     # Slurm sbatch wrapper
├── srun-sandbox.sh       # Slurm srun wrapper
├── sandbox-claude.md     # Agent instructions (overlaid into CLAUDE.md inside sandbox)
├── test.sh               # Test suite
├── backends/
│   ├── bwrap.sh          # Bubblewrap backend (mount namespace isolation)
│   ├── firejail.sh       # Firejail backend (setuid sandbox, namespaces + seccomp)
│   ├── landlock.sh       # Landlock backend (LSM filesystem restrictions)
│   └── landlock-sandbox.py  # Landlock syscall helper (Python)
└── bin/
    ├── sbatch            # Shadows /usr/bin/sbatch inside sandbox
    └── srun              # Shadows /usr/bin/srun inside sandbox
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

### Set Up an Alias (optional)

Add this to your `.bashrc` or `.zshrc` for quick access:

```bash
alias claude-sandbox='~/.claude/sandbox/sandbox-exec.sh -- claude'
```


### Start Claude Code in a Sandbox

```bash
cd /path/to/my-project

# With the alias:
claude-sandbox

# Or directly:
~/.claude/sandbox/sandbox-exec.sh -- claude

# Force a specific backend:
~/.claude/sandbox/sandbox-exec.sh --backend firejail -- claude
```

That's it. Claude starts in your project directory with full read access to the HPC but write access **only** to that directory. Your SSH keys, API tokens, and all credentials are invisible.

### Verify the Sandbox

```bash
# Secrets are hidden
~/.claude/sandbox/sandbox-exec.sh -- ls ~/.ssh
# → ls: cannot access '/home/user/.ssh': No such file or directory  (bwrap/firejail)
# → ls: cannot open directory '/home/user/.ssh': Permission denied   (landlock)

# API tokens are gone
~/.claude/sandbox/sandbox-exec.sh -- bash -c 'echo "GITHUB_PAT=${GITHUB_PAT:-UNSET}"'
# → GITHUB_PAT=UNSET

# Slurm works
~/.claude/sandbox/sandbox-exec.sh -- squeue --me

# lmod works
~/.claude/sandbox/sandbox-exec.sh -- bash -c 'module avail 2>&1 | head -5'

# Writing outside project dir fails
~/.claude/sandbox/sandbox-exec.sh -- touch /path/to/other-project/test
# → touch: cannot touch '...': Read-only file system  (bwrap)
# → touch: cannot touch '...': Permission denied      (firejail/landlock)

# Writing inside project dir works
~/.claude/sandbox/sandbox-exec.sh --project-dir $PWD -- bash -c 'touch test && rm test && echo OK'
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
    "/shared/lab/clinical_restricted"
    "/shared/lab/user/someone_else/private"
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

If the agent needs to clone or push to private repositories over SSH, you *can* expose your SSH keys — but consider the alternatives first:

- **Deploy keys** (recommended): Create a read-only [GitHub deploy key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) scoped to a single repository, place it in your project directory, and configure `GIT_SSH_COMMAND` to use it.
- **HTTPS + token**: Use HTTPS cloning with a fine-grained personal access token (limited to specific repos) via the `ALLOWED_CREDENTIALS` mechanism.

If you still need full SSH access:

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
    ".ssh"                 # ← NOT RECOMMENDED — see warning below
)
```

> **Sandbox escape risk:** Exposing `~/.ssh` gives the agent access to all your SSH private keys. On HPC clusters where passwordless SSH between nodes is configured, the agent can SSH to `localhost` or another node, getting an **unsandboxed shell** with full access to your account. The sandbox controls filesystem access only — not network connections or SSH authentication.

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
    "/shared/lab"
    "/shared/other_lab/data"    # ← add this
)
```

#### Sandbox Permissions (settings.json)

The sandbox overlays Claude Code's `~/.claude/settings.json` to **auto-allow tools that are already restricted by the sandbox**. Since the sandbox enforces filesystem isolation at the kernel level, Claude Code's own permission prompts for file and shell operations are redundant — the agent can't escape the sandbox regardless of what it runs.

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

### Isolation Strategy

Each backend achieves isolation differently, but the end result is the same: the agent can only see and write what you explicitly allow.

**bwrap (mount namespace):**
```
Layer 1: System mounts (read-only)      /usr, /lib, /bin, /sbin, /etc, /app
Layer 2: Blank tmpfs home               hides EVERYTHING under $HOME
Layer 3: Selective re-mount (read-only) ~/.bashrc, ~/.gitconfig, ...
Layer 4: Writable mounts                ~/.claude, project directory
Layer 5: Slurm binary relocation        /usr/bin/sbatch → sandbox redirector
Layer 6: NFS storage (read-only)        /shared/lab_data → entire tree
Layer 7: Project dir (writable overlay) writable on top of Layer 6
```

**firejail (setuid sandbox):**
```
--whitelist   selective paths from real $HOME into private tmpfs home
--read-only   system paths + home (defense in depth)
--read-write  explicit writable paths (project dir, ~/.claude)
--blacklist   dangerous paths (/run/dbus, /run/user, credentials)
--seccomp     built-in syscall filter (blocks kexec, reboot, swapon, ...)
--caps.drop   drops all capabilities
PID namespace enabled by default (no flag needed)
```

**landlock (LSM):**
```
Kernel-enforced filesystem ACLs — read-only/read-write/no-access per path.
No mount namespace — blocked paths return EACCES, not ENOENT.
Custom seccomp filter blocks kexec_load + io_uring syscalls.
```

### Environment Variables

The sandbox inherits your shell environment, then:
1. **Sets** `SANDBOX_ACTIVE=1`, `SANDBOX_BACKEND`, `SANDBOX_PROJECT_DIR`, and passes through HPC variables (lmod, mamba, etc.)
2. **Blocks** everything in `BLOCKED_ENV_VARS` (API tokens, secrets)
3. **Allows** everything in `ALLOWED_CREDENTIALS` back through (overrides the block)

### What's NOT Isolated

| Resource | Backend behavior |
|---|---|
| **Network** | Not isolated (any backend) — Slurm needs network for job submission and munge authentication |
| **PID namespace** | Isolated by bwrap (`--unshare-pid`) and firejail (default). Not isolated by Landlock. |
| **`/run`** | Partially isolated. Firejail blacklists `/run/dbus`, `/run/user`, `/run/systemd/private`, `/run/containerd` but allows munge socket. Bwrap exposes only `/run/munge`. Landlock allows all of `/run`. |
| **User enumeration** | bwrap/firejail: filtered (`FILTER_PASSWD=true` — bwrap overlays `/etc/passwd` + nsswitch; firejail blocks NSS daemon sockets). Landlock: not filtered. |
| **tmux** | Outer tmux socket blocked by `/tmp` isolation (exposing it would allow sandbox escape). Experimental: a `bin/tmux` wrapper enables nested tmux with `Ctrl-a` prefix. Requires `BIND_DEV_PTS=true` on kernels < 5.4 (see Known Limitations). |

---

## Slurm Integration

### Transparent Wrapping

Inside the sandbox, `sbatch` and `srun` are **automatically replaced** by wrapper scripts that inject the sandbox on the compute node. The sandbox prepends `~/.claude/sandbox/bin/` to `PATH`, so the wrappers shadow `/usr/bin/sbatch` and `/usr/bin/srun`. The agent (and any scripts it runs) just calls `sbatch` and `srun` as normal — the sandboxing happens transparently.

```bash
# Inside the sandbox, these just work — no special paths needed:
sbatch --wrap="python train.py"
sbatch my_job.sh
srun -n 4 python train.py
```

The wrappers pass all flags through unchanged and call the real Slurm binaries internally.

### How the Wrappers Work

**sbatch:** In `--wrap` mode, the command string is wrapped in a sandbox call. In script mode, `#SBATCH` directives are extracted from the original script, a wrapper script is generated that calls the sandbox with the original script as payload, and the wrapper is submitted to the real `sbatch`.

**srun:** The wrapper separates srun flags from the user command (with or without a `--` separator), then calls the real `srun` with the sandbox wrapping the command on the compute node.

### Protection

**Bwrap backend:** The sandbox directory (`~/.claude/sandbox/`) is mounted **read-only** — the agent cannot modify wrapper scripts, config, or bin stubs. The real Slurm binaries at `/usr/bin/sbatch` and `/usr/bin/srun` are **relocated** to an obscure internal path and replaced with redirector scripts, so even calling `/usr/bin/sbatch` by absolute path goes through the sandbox wrappers.

**Firejail backend:** The sandbox directory is whitelisted read-only inside firejail's mount namespace. Slurm wrappers work via PATH shadowing (same as landlock). The real `/usr/bin/sbatch` remains directly callable but is covered by the PATH wrappers in normal agent usage.

**Landlock backend:** Neither self-protection nor binary relocation is possible — Landlock has no mount namespace to overlay files or make subdirectories read-only. The Slurm wrappers work via PATH shadowing only, and the real `/usr/bin/sbatch` remains directly callable. See [Admin Hardening](ADMIN_HARDENING.md) for mitigations.

---

## Agent Awareness (CLAUDE.md)

The sandbox automatically injects instructions into the agent's `CLAUDE.md` — **without modifying your actual CLAUDE.md file**. On each sandbox start, `~/.claude/sandbox-config/` is populated with a merged `CLAUDE.md` and `settings.json`, and `CLAUDE_CONFIG_DIR` is set so Claude Code reads from there instead of `~/.claude/` directly. Everything else in `~/.claude/` is symlinked through, so sessions, projects, and other state work normally. Files that were updated inside the sandbox (e.g. refreshed OAuth tokens) are preserved across restarts — they are only replaced with a symlink when the outside version is newer.

This means the agent:

- Knows it can only write to `$SANDBOX_PROJECT_DIR`
- Knows to tell you which `sandbox.conf` setting to change if it needs access to something blocked
- Won't waste time trying to access credentials that don't exist

The sandbox-specific instructions live in `~/.claude/sandbox/sandbox-claude.md`. Edit that file to customize what the agent sees:

```bash
$EDITOR ~/.claude/sandbox/sandbox-claude.md
```

---

## Agent Teams / tmux (experimental)

Claude Code agent teams require tmux. The outer tmux socket is blocked inside the sandbox (exposing it would allow escape via `tmux new-window 'unsandboxed command'`). Instead, a nested tmux runs inside the sandbox with a separate prefix key.

**Requirements:** tmux inside the sandbox needs working pty allocation. On kernels >= 5.4, bwrap's minimal `/dev` provides this automatically. On older kernels (e.g. 4.15 on current gizmo nodes), you must enable `BIND_DEV_PTS=true` in `sandbox.conf`. This binds the host's `/dev` into the sandbox, which on kernels < 6.2 exposes a TIOCSTI escape risk (see Known Limitations and [Admin Hardening](ADMIN_HARDENING.md)).

```bash
# Start sandbox with nested tmux:
~/.claude/sandbox/sandbox-exec.sh -- tmux new-session claude
```

The nested tmux uses **`Ctrl-a`** as prefix (instead of `Ctrl-b`) to avoid conflicts with the outer session. A minimal `sandbox-tmux.conf` is used instead of your `~/.tmux.conf` — custom configs with `run-shell` plugins may reference paths hidden by the sandbox. Edit `~/.claude/sandbox/sandbox-tmux.conf` to customize.

---

## Troubleshooting

### "bwrap: No such file or directory"
Install bubblewrap: `brew install bubblewrap`

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

### Firejail: Slurm "sbatch: error: ... Invalid user id"
This was caused by firejail's `/etc/passwd` filtering, which removes UIDs >= `UID_MIN`. The sandbox now uses `--allusers` to disable this filtering, so this issue should no longer occur. If you still see it, ensure you're running the latest version of the sandbox scripts.

### Slurm commands fail with "Authentication error"
The munge socket at `/run/munge/` must be accessible. Bwrap binds `/run` by default. Firejail allows `/run/munge` but blacklists `/run/dbus` and `/run/user`. If you're on a non-standard setup, check that `/run/munge/munge.socket.2` exists.

### "Read-only file system" when writing
By design. Only `$SANDBOX_PROJECT_DIR` and `~/.claude/` are writable. If the agent needs to write somewhere else, either change `--project-dir` or add the path to `HOME_WRITABLE` in `sandbox.conf`.

### Module commands don't work
The sandbox passes through `BASH_ENV` (typically pointing to the lmod init script, e.g. `/app/lmod/lmod/init/bash`) which auto-initializes lmod in bash scripts. If `module` isn't available, check that `BASH_ENV` is set correctly for your site's lmod installation. For non-bash shells, source the appropriate lmod init file.

### "No such file or directory" for a tool
The tool's directory isn't mounted. Check if it's under a path in `READONLY_MOUNTS` or `HOME_READONLY`. Add it to the appropriate list in `sandbox.conf`.

### Can't create new conda/mamba environments
Mamba root (`$MAMBA_ROOT_PREFIX`) is read-only by default. Either create environments outside the sandbox and use them inside, or add the mamba root to `HOME_WRITABLE` in `sandbox.conf` to make it writable.

### eBPF token protection not blocking reads
If verification step 2 (simulated sandboxed read) prints "FAIL: readable":
1. Check the program is loaded: `sudo bpftool prog show | grep deny_token_read`
2. Check the map has values: `sudo bpftool map dump id $(sudo bpftool map show | grep protected_file | head -1 | awk '{print $1}' | tr -d ':')`
3. If `dev` is 0 or doesn't match the kernel encoding, re-run `load-token-protect.sh`. Note: `stat -c %d` returns old-format `dev_t`; the kernel uses `new_encode_dev` (`major << 20 | minor`). The loader script handles this.
4. If reloading after an update, remove old pins first: `sudo rm -rf /sys/fs/bpf/token_protect`

### eBPF: "bpf" not in active LSM list
Add `bpf` to the kernel boot parameters: `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`. Check current list: `cat /sys/kernel/security/lsm`.

---

## Security Summary

| Threat | Protection | Strength |
|---|---|---|
| Agent reads SSH keys | Hidden (bwrap/firejail: ENOENT) or blocked (Landlock: EACCES) | **Hard** — kernel-enforced |
| Agent reads API tokens from env | `BLOCKED_ENV_VARS` removed from environment | **Hard** — all backends |
| Agent reads `~/.aws` credentials | Hidden or blocked (same as SSH keys) | **Hard** |
| Agent writes to other projects | Only project dir is writable | **Hard** |
| Agent reads other users' data | Only explicitly allowed paths are accessible | **Hard** |
| Agent escapes via Unix sockets | Bwrap/firejail: filesystem-based sockets (e.g. `/run/dbus`) hidden by mount namespace, but abstract sockets (`@/org/...`) remain accessible (shared network namespace). Landlock: cannot block `AF_UNIX connect` | **Partial** (bwrap/firejail) / **None** (Landlock) |
| Agent escapes via PID namespace | Bwrap/firejail: isolated PID namespace. Landlock: host PIDs visible | **Hard** (bwrap/firejail) / **None** (Landlock) |
| Agent uses dangerous syscalls | Firejail: built-in seccomp + io_uring blocked via `--seccomp.drop`. Landlock: custom seccomp (kexec + io_uring). Bwrap: seccomp optional | **Hard** (firejail/landlock) / **None** (bwrap) |
| Slurm job bypasses sandbox | PATH shadowing (all backends) + binary relocation (bwrap only) | **Soft** — firejail/Landlock have PATH shadowing only; munge auth available (see [Admin Hardening](ADMIN_HARDENING.md)) |
| Agent tampers with sandbox scripts | Read-only mount (bwrap/firejail) / not protected (Landlock) | **Hard** (bwrap/firejail) / **None** (Landlock) — see [Admin Hardening](ADMIN_HARDENING.md) §2 |
| SSH escape (if `~/.ssh` exposed) | Not protected — sandbox does not restrict network | **None** — agent can SSH to localhost or other nodes to get an unsandboxed shell. **Do not expose `~/.ssh`** unless you understand this risk. |

**Bottom line:** Filesystem isolation is kernel-enforced with all three backends. Bwrap and firejail provide the strongest isolation (mount namespace hides paths, PID namespace isolates processes, filesystem-based Unix sockets are hidden — though abstract sockets remain accessible via shared network namespace). Firejail additionally includes built-in seccomp syscall filtering (including io_uring). Landlock provides filesystem-only isolation without mount or PID namespaces, but works without any admin privileges. Slurm wrapping covers normal code paths but is a soft boundary in all backends. See [Admin Hardening Options](ADMIN_HARDENING.md) for stronger approaches.

**How does this compare to Apptainer?** Apptainer's defaults are weaker than they appear — it shares PID space, network, `$HOME`, `/tmp`, and environment variables with the host, applies no seccomp filter, and its admin restrictions are [unenforceable in rootless mode](https://apptainer.org/docs/admin/main/configfiles.html). The sandbox provides stronger default containment for agent use cases, though neither tool isolates the network or blocks all dangerous syscalls. See [Sandbox vs. Apptainer Comparison](APPTAINER_COMPARISON.md) for a detailed analysis including CVE history and shared weaknesses.

---

## Appendix: Sandbox Backend Comparison

| Tool | Available? | Pros | Cons |
|---|---|---|---|
| **[Bubblewrap](https://github.com/containers/bubblewrap)** | ✅ Yes (Homebrew) | Mount namespace isolation, paths hidden entirely (ENOENT), file overlays, Slurm binary relocation, sandbox self-protection | Requires unprivileged user namespaces; blocked by AppArmor on Ubuntu 24.04+ without admin help |
| **[Firejail](https://firejail.wordpress.com/)** | ✅ Yes (`apt install`) | Mount namespace (ENOENT), PID namespace, built-in seccomp + io_uring blocked, caps dropping, works when AppArmor blocks user namespaces | Requires setuid root binary |
| **[Landlock](https://docs.kernel.org/userspace-api/landlock.html)** | ✅ Yes (kernel ≥ 5.13) | No root or admin needed, works on Ubuntu 24.04 despite AppArmor, pure kernel LSM, no external dependencies (Python 3 only) | No mount namespace — blocked paths return EACCES not ENOENT, no file overlays, no PID isolation, no Slurm binary relocation, no sandbox self-protection, cannot block Unix socket connect (see [Admin Hardening](ADMIN_HARDENING.md)) |
| **[Apptainer/Singularity](https://apptainer.org/)** | ✅ Yes (lmod) | Full container, HPC-native | Heavy — requires container images, path mapping |
| **Docker** | ❌ No | Industry standard | Requires root daemon; not available on shared HPC |

The sandbox auto-detects the best available backend (bwrap → firejail → landlock). All three provide kernel-enforced filesystem isolation through different mechanisms:

- **Bwrap**: mount namespaces — strongest isolation with file overlays, Slurm binary relocation, and sandbox self-protection. Requires unprivileged user namespaces.
- **Firejail**: setuid sandbox with mount namespaces, PID namespace, seccomp (including io_uring), and capability dropping. Works on Ubuntu 24.04+ where AppArmor blocks bwrap. Slurm wrapping via PATH shadowing only.
- **Landlock**: kernel LSM — weakest isolation but works everywhere with kernel ≥ 5.13 and no admin privileges. No mount/PID namespace, no seccomp (except custom filter for kexec/io_uring), PATH shadowing only for Slurm.

### Known Limitations

| Backend | Limitation | Mitigation |
|---|---|---|
| **bwrap/Firejail** | `/tmp` isolated by default (`PRIVATE_TMP=true`) — breaks MPI shared-memory transport and NCCL inter-GPU sockets | Set `PRIVATE_TMP=false` in `sandbox.conf` for HPC multi-process workloads |
| **bwrap** | Host `/dev` exposure when `BIND_DEV_PTS=true` — required for tmux on kernels < 5.4 (bwrap's devpts gets `ptmxmode=000`). Exposes host `/dev/pts`; on kernels < 6.2, `TIOCSTI` ioctl allows keystroke injection into same-user terminals outside the sandbox | Default `false` (safe). Set `BIND_DEV_PTS=true` in `sandbox.conf` only if you need tmux inside the sandbox. Upgrade to kernel >= 5.4 to avoid the need, or >= 6.2 to disable TIOCSTI entirely |
| **bwrap** | No seccomp filter by default — bwrap supports `--seccomp` but does not enable it out of the box. Without seccomp, dangerous syscalls like `ptrace`, `process_vm_writev`, `kexec_load`, and `io_uring_setup` remain available. Adding a seccomp policy is harder than with firejail (requires a BPF binary, not a simple drop list) | Use firejail or Landlock for syscall filtering. PID namespace (`--unshare-pid`) mitigates `ptrace`/`process_vm_*` attacks. See [Admin Hardening](ADMIN_HARDENING.md) for io_uring/kexec |
| **All** | `memfd_create`, `userfaultfd`, `process_vm_readv/writev` not blocked by any backend (HPC compatibility). Docker's default seccomp profile makes the same trade-offs: allows `memfd_create` and `process_vm_readv`, blocks `io_uring` (since 25.0), and has always blocked `userfaultfd`. | Accepted trade-off. `memfd_create` needed by CUDA, PyTorch, JAX. `process_vm_readv/writev` needed by MPI (mitigated by PID namespace in bwrap/firejail). `userfaultfd` could likely be blocked (Java ZGC no longer needs it) but kept for QEMU/CRIU. See [Admin Hardening](ADMIN_HARDENING.md). |
| **Landlock** | Cannot block `AF_UNIX connect()` — agent can reach D-Bus, systemd sockets | Use bwrap or firejail; or see [Admin Hardening](ADMIN_HARDENING.md) |
| **Landlock** | No PID namespace — host processes visible via `/proc`. Agent could read `/proc/PID/environ` of same-UID processes (e.g. sbatch wrapper injecting bypass token) | Use bwrap or firejail for PID isolation; token exposure window is microseconds. A SPANK plugin would eliminate it entirely |
| **Landlock** | No sandbox self-protection — agent can modify wrapper scripts | Current session is safe (kernel rules are irrevocable), but future sessions could be affected |
| **All** | `/dev/shm` is writable and shared (IPC namespace not isolated by default) — could be used for covert cross-sandbox communication | `firejail --ipc-namespace`, `bwrap --unshare-ipc` |
| **Firejail** | Setuid-root binary with a significant [CVE history](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html) (18 CVEs, 12 local root exploits). Installing firejail adds a privileged attack surface to every node. | Prefer bwrap where possible. See [Apptainer Comparison](APPTAINER_COMPARISON.md#security-track-record) for the full CVE breakdown. |
| **Firejail** | `FILTER_PASSWD=true` blocks NSS daemon sockets (nscd, nslcd, sssd) to prevent user enumeration. On LDAP/AD clusters where the current user is not in local `/etc/passwd`, this breaks user/group resolution, which can cause Slurm failures and shell issues. bwrap avoids this by overlaying a pre-generated `/etc/passwd` that includes the current user. | Set `FILTER_PASSWD=false` in `sandbox.conf` on LDAP clusters when using the firejail backend, or prefer bwrap which handles this correctly. |
| **Landlock** | User enumeration via LDAP/AD — `getent passwd` reveals all directory users | No mount namespace to overlay files or block sockets; set `FILTER_PASSWD=false` if LDAP lookups are needed |
| **All** | Network not isolated — agent can make HTTP requests, SSH connections | Do not expose `~/.ssh`; consider network policy at admin level |
