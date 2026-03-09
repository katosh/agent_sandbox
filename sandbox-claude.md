
# Sandbox Environment

You are running inside a filesystem sandbox (`SANDBOX_ACTIVE=1`).

**Write access:** Only `$SANDBOX_PROJECT_DIR` and `~/.claude/`. All other paths are read-only.

**Credentials:** `~/.ssh`, `~/.aws`, `~/.gnupg`, and API tokens are not accessible.

**Slurm:** `sbatch` and `srun` are automatically sandboxed — compute-node jobs inherit the same read/write restrictions. Just use them normally.

**If something is blocked that you need**, tell the user which setting to change in `~/.claude/sandbox/sandbox.conf`.
