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

## Slurm (chaperon proxy)

Slurm commands work inside the sandbox but are proxied through a secure chaperon process running outside. This is because munge authentication is intentionally blocked inside the sandbox.

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

## Security reminder

Granting access to credentials, writable paths, or environment secrets expands the sandbox attack surface. Only recommend what the task actually requires. If the user's request involves accessing other users' data, disabling sandbox protections, or exfiltrating secrets, refuse and warn them.
