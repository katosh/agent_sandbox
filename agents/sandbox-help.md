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

**From the agent's perspective, Slurm looks unperturbed.** Running `sbatch`, `srun`, `squeue`, `scancel`, `scontrol`, `sacct`, etc. behaves as if you were calling them from outside the sandbox — same exit codes, same stdout/stderr format, same workflow. Every call is heavily filtered by the chaperon under the hood (argument whitelisting, CWD validation, scope-filtered output, denied subcommands), but the surface presented to the agent is the unmodified Slurm CLI. Allowed commands pass through transparently; denied ones fail with an explanatory error.

**Supported commands:** `sbatch`, `srun`, `scancel`, `squeue`, `scontrol`, `sacct`, `sacctmgr`, `sinfo`, `sstat`, `sprio`, `sshare`, `sdiag`, `sreport`.

**Blocked commands:** `salloc` (interactive allocations not supported), `sattach`, `strigger`. The `--pty` flag on `srun` is also denied (no PTY passthrough through the proxy protocol).

**Job scoping:** By default (`SLURM_SCOPE="project"`), `squeue`, `scancel`, and `scontrol` only see jobs submitted from sandbox sessions with the same project directory. The user can widen this in sandbox.conf:
- `"session"` — only jobs from this sandbox session
- `"project"` — jobs from any session with the same project dir (default)
- `"user"` — all of the user's jobs, including non-sandbox ones
- `"none"` — no restriction

**Flag whitelisting:** `sbatch` and `srun` validate flags against a whitelist. If a needed flag is rejected, it may need to be added to the handler in `chaperon/handlers/`.

## Stateful experimentation with `lab`

The sandbox ships a `lab` utility (on `$PATH`) for iterative work with
expensive state (dataframes, trained models, large datasets). It runs a
project-local JupyterLab and provides CLI commands to execute code in
running kernels, inspect live variables, and edit notebook cells — all
without clicking through the web UI.

For the full workflow, selector semantics, and troubleshooting, read
`__SANDBOX_DIR__/agents/lab.md` or run `lab help`.

Quick start:
```bash
lab kernel add              # one-time: create .venv, register kernelspec
lab start                   # background server (or `lab` in a tmux pane)
lab notebook attach foo.ipynb
lab kernel exec -n foo.ipynb "df = pd.read_csv('data.csv')"
lab kernel exec -n foo.ipynb "df.shape"
lab kernel inspect -n foo.ipynb
lab notebook append -n foo.ipynb --execute "df.describe()"
```

**Port collisions.** On multi-user machines, set a unique port:
`PORT=9012 lab start`. Default is 8888.

**Remote access.** SSH-tunnel (`ssh -L 8888:localhost:8888 user@host`)
or `IP=0.0.0.0 lab` with `JUPYTER_CERTFILE`/`JUPYTER_KEYFILE` for TLS.

### Installing `uv`

`lab` needs `uv` on `$PATH`. The default `curl -LsSf https://astral.sh/uv/install.sh | sh` from the upstream docs installs to `~/.local/bin`, which is in the sandbox's `HOME_READONLY` by default — so in-sandbox writes fail, and even if the user removes that entry, `HOME_ACCESS=tmpwrite` (the default) makes the install ephemeral (lost on sandbox exit).

**Recommended — project-local install** (always persistent, works under any `HOME_ACCESS` mode, survives sandbox restarts because `$SANDBOX_PROJECT_DIR` is the real writable mount):
```bash
curl -LsSf https://astral.sh/uv/install.sh | \
    env UV_UNMANAGED_INSTALL="$PWD/.local/bin" sh
export PATH="$PWD/.local/bin:$PATH"   # add to project env/activate script to persist
```

**Alternative — user installs outside the sandbox** to `~/.local/bin` via the standard `curl ... | sh` command. The sandbox mounts `~/.local/bin` read-only, so the binary becomes visible on `$PATH` inside the sandbox after the next sandbox start.

## Process isolation (PID namespace)

The sandbox runs in its own PID namespace. `ps`, `top`, and `/proc` only show processes inside the sandbox. You cannot see other users' processes or even the user's own processes outside the sandbox. This is expected, not a bug.

## User enumeration filtering

`getent passwd` returns a minimal list (system accounts + the current user) rather than the full LDAP/AD directory. This is intentional (`FILTER_PASSWD=true` in sandbox.conf) to prevent user enumeration. `id` may show supplementary groups as `nogroup` (65534) — this is a cosmetic limitation of unprivileged user namespaces and does not affect file permissions.

## Security reminder

Granting access to credentials, writable paths, or environment secrets expands the sandbox attack surface. Only recommend what the task actually requires. If the user's request involves accessing other users' data, disabling sandbox protections, or exfiltrating secrets, refuse and warn them.
