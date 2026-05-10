# Sandbox Configuration Guide

The user's config file is `~/.config/agent-sandbox/sandbox.conf`, edited **outside** the sandbox. Changes take effect on next sandbox start. Below are common adjustments.

## Grant read access to a path

Add the path to `READONLY_MOUNTS` in sandbox.conf:
```bash
READONLY_MOUNTS=(
    # ... existing entries ...
    "/fh/fast/mylab/shared_data"
)
```

## Grant read+write access to an extra directory

Add the path to `EXTRA_WRITABLE_PATHS`:
```bash
EXTRA_WRITABLE_PATHS=(
    "/fh/scratch/delete30/mylab/agent-output"
)
```

## Expose credentials (SSH, AWS, etc.)

Add the dotfile or directory to `HOME_READONLY` (read-only) or `HOME_WRITABLE` (read+write):
```bash
HOME_READONLY=(
    # ... existing entries ...
    ".ssh"          # SSH keys — needed for git push, remote access
    ".aws"          # AWS credentials
)
```

## Home directory access modes (HOME_ACCESS)

The sandbox startup banner shows the home directory mode. Here's what each means:

| Mode | What you see in `~` | Writes to `~` | Details |
|------|---------------------|---------------|---------|
| `restricted` | Only dotfiles/dirs listed in `HOME_READONLY` and `HOME_WRITABLE` | Blocked (tmpfs is remounted read-only) | Default. Minimal surface area. |
| `tmpwrite` | All listed dotfiles/dirs (typically most of `~`) via read-only bind mounts | Allowed but **ephemeral** — writes go to a tmpfs overlay and vanish on exit | Good for tools that need to write to `~/.cache`, `~/.config`, etc. without persisting changes. Existing files like `~/.linuxbrew`, `~/.local` are visible read-only. |
| `read` | Full real home directory | Blocked (read-only bind) | Credential dirs are hidden. `HOME_WRITABLE` paths are still writable. |
| `write` | Full real home directory | Allowed (real writes persist) | Credential dirs are hidden. Least restrictive — use with caution. |

**Key point for `tmpwrite`:** Your home directory is NOT empty. Tools installed at `~/.linuxbrew`, `~/.local/bin`, etc. are all visible. You just can't permanently modify them — writes land on a tmpfs overlay that disappears when the sandbox exits.

## Unblock an environment variable

Env vars matching secret patterns (`*_TOKEN`, `*_API_KEY`, `*_SECRET`, etc.) are blocked by default. To let a specific variable through, add it to `ALLOWED_ENV_VARS`:
```bash
ALLOWED_ENV_VARS=(
    "MY_APP_TOKEN"
    "CUSTOM_API_KEY"
)
```
The user can check which vars are in their environment with: `env | grep -iE 'token|key|secret'`

## Make a home subdirectory writable

Add it to `HOME_WRITABLE`:
```bash
HOME_WRITABLE=(
    # ... existing entries ...
    ".cache"
    ".my_tool_state"
)
```

## Per-project overrides

For project-specific settings (different mounts for different directories), create files in `~/.config/agent-sandbox/conf.d/*.conf`. See `conf.d/example.conf` in the sandbox installation.

## Expose extra device nodes (GPU, audio, pty)

The bwrap backend bind-mounts only the device nodes listed in `DEVICES`. Defaults expose NVIDIA driver nodes (`/dev/nvidia*`) — a no-op on CPU-only hosts.

To add nodes (audio, DRI render nodes, pty for tmux on kernel < 5.4):
```bash
DEVICES+=(/dev/snd /dev/dri/* /dev/pts)
```

To replace the defaults entirely (uncommon):
```bash
DEVICES=(/dev/something-specific)
```

The `DEVICES_BLACKLIST` (admin-enforced when an admin install is in place) vetoes individual entries with a stderr notice. Defaults block `/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/pts` (TIOCSTI on kernel < 6.2), `/dev/sd*`, `/dev/nvme*`, `/dev/loop*`. The legacy `BIND_DEV_PTS=true` knob is rewritten to `DEVICES+=(/dev/pts)` for backward compatibility.

## Slurm (chaperon proxy)

Slurm commands work inside the sandbox but are proxied through a secure chaperon process running outside. This is because munge authentication is intentionally blocked inside the sandbox.

**From the agent's perspective, Slurm looks unperturbed.** Running `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, etc. behaves as if you were calling them from outside the sandbox — same exit codes, same stdout/stderr format, same workflow. Every call is heavily filtered by the chaperon under the hood (argument whitelisting, CWD validation, scope-filtered output, denied subcommands), but the surface presented to the agent is the unmodified Slurm CLI. Allowed commands pass through transparently; denied ones fail with an explanatory error.

**Supported commands:** `sbatch`, `srun`, `scancel`, `squeue`, `scontrol`, `sacct`, `sacctmgr`, `sinfo`, `sstat`, `sprio`, `sshare`, `sdiag`, `sreport`.

**Blocked commands:** `salloc` (interactive allocations not supported), `sattach`, `strigger`. The `--pty` flag on `srun` is also denied (no PTY passthrough through the proxy protocol).

**Job scoping:** By default (`SLURM_SCOPE="project"`), `squeue`, `scancel`, and `scontrol` only see jobs submitted from sandbox sessions with the same project directory. The user can widen this in sandbox.conf:
- `"session"` — only jobs from this sandbox session
- `"project"` — jobs from any session with the same project dir (default)
- `"user"` — all of the user's jobs, including non-sandbox ones
- `"none"` — no restriction

**Flag whitelisting:** `sbatch` and `srun` validate flags against a whitelist. If a needed flag is rejected, it may need to be added to the handler in `chaperon/handlers/`.

## Process isolation (PID namespace)

The sandbox runs in its own PID namespace. `ps`, `top`, and `/proc` only show processes inside the sandbox. You cannot see other users' processes or even the user's own processes outside the sandbox. This is expected, not a bug.

## User enumeration filtering

`getent passwd` returns a minimal list (system accounts + the current user) rather than the full LDAP/AD directory. This is intentional (`FILTER_PASSWD=true` in sandbox.conf) to prevent user enumeration. `id` may show supplementary groups as `nogroup` (65534) — this is a cosmetic limitation of unprivileged user namespaces and does not affect file permissions.

## bwrap startup errors

When the bwrap backend can't start, agent-sandbox runs a probe that maps the failure to one of the categories below. The category appears in two places: in the auto-mode `Tried:` table (e.g. `bwrap — blocked by AppArmor / LSM userns restriction`) and in the explicit-mode `sandbox: ...` block printed before the `Error: Requested backend 'bwrap' is not available` line.

| Probe reason | Stderr signature | Cause | Fix |
|---|---|---|---|
| `not-installed` | (binary missing) | `BWRAP=…` points at a non-existent file, or no `bwrap` on `PATH` and no `~/.linuxbrew/bin/bwrap`. | `sudo apt install bubblewrap`, `brew install bubblewrap`, or set `BWRAP=/path/to/bwrap`. |
| `version-too-old` | `--version` reports < 0.4.0 | `--chmod` and `--unsetenv` aren't supported. | Upgrade via package manager or `brew upgrade bubblewrap`. |
| `binary-broken` | `--version` produces no parseable output | Wrong architecture, corrupted binary, or not actually bubblewrap. | `file $BWRAP; $BWRAP --version`; reinstall. |
| `apparmor-userns` | `setting up uid map: Permission denied` | Ubuntu 24.04+ AppArmor profile (or SELinux policy) blocks unprivileged user namespaces. | Install `bwrap-userns-restrict` profile, or `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or use `--backend landlock`. |
| `userns-disabled` | `No permitted_caps` | Kernel built without `CONFIG_USER_NS` or has unprivileged userns disabled. | `sudo sysctl -w kernel.unprivileged_userns_clone=1` and `user.max_user_namespaces=15076`, or use `--backend landlock`. |
| `clone-denied` | `clone(): Operation not permitted` / `Creating new namespace failed: Operation not permitted` | Outer seccomp filter forbids `clone(CLONE_NEWUSER)` (Docker without `--privileged`, restrictive systemd unit, another sandbox), or `max_user_namespaces=0`. | Run from a less-restricted environment, raise `max_user_namespaces`, or use `--backend landlock`. |
| `mount-namespace-denied` | `Failed to make / slave` / `pivot_root: Permission denied` | Already inside another bwrap, container, or chroot that blocks mount-propagation changes. | Re-run from outside the wrapper, or use `--backend landlock`. |
| `unknown` | (anything else) | New or rare failure — agent-sandbox prints the stderr verbatim. | Open an issue with the stderr and `uname -a; bwrap --version; cat /sys/kernel/security/lsm`. |

The probe lives in `backends/bwrap.sh::_probe_bwrap`. Adding a new pattern is one `case` branch.

## Security reminder

Granting access to credentials, writable paths, or environment secrets expands the sandbox attack surface. Only recommend what the task actually requires. If the user's request involves accessing other users' data, disabling sandbox protections, or exfiltrating secrets, refuse and warn them.
