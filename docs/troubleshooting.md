# Troubleshooting


### "bwrap: No such file or directory"

Bubblewrap is not installed. See [Admin Install](admin/install.md) for install options (system package or Homebrew without root).

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

