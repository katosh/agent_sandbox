# `.sandbox-state/` — Hidden Chaperon-Owned State Subdir

> **Disclaimer:** Like the rest of the chaperon, the protections described here are best-effort. Read the [threat-model framing](#threat-model-framing) before relying on this dir for security purposes.

## What it is

`.sandbox-state/` is a hidden directory the chaperon creates inside each project tree (`$project_dir/.sandbox-state/`) to hold chaperon-managed state that the sandboxed agent needs to read but must not be able to tamper with.

Layout:

```
$project_dir/.sandbox-state/
├── README.md                     # marker file explaining the convention
├── slurm-logs/<transformed>      # slurmstepd writes job logs here;
│                                 # the in-sandbox wrapper creates
│                                 # relative symlinks from the user's
│                                 # intended --output/--error paths
│                                 # to files here
└── chaperon/<session-id>.log     # chaperon's diagnostic log
                                  # (bwrap/firejail only; XDG fallback
                                  # on landlock)
```

## Writability matrix

| Principal                         | Permission | Why |
|-----------------------------------|------------|-----|
| host (chaperon, slurmstepd)       | read+write | chaperon `mkdir -p`s; slurmstepd writes job logs |
| sandbox (bwrap / firejail)        | read-only  | bind-mount overlay; prevents symlink-plant against slurmstepd |
| sandbox (landlock)                | writable   | landlock can't make a subdir RO under a writable parent; feature degrades |

The bwrap and firejail backends emit a `--ro-bind` / `--read-only=` after the writable project-dir bind. Mount overlays are path-keyed and later-wins, so the RO subtree sits on top of the writable parent in the sandbox's mount namespace.

Landlock cannot do this — its rules are additive at the kernel level, so once `$project_dir` is in the writable allowlist, every descendant is writable too. The chaperon-side feature detects `$SANDBOX_BACKEND=landlock` and disables the parts that depend on the RO overlay (the `--output`/`--error` transformation in `chaperon/handlers/_handler_lib.sh`).

## Threat-model framing

> "Yes, it should be considered hostile, even the now non-directly-writable `.sandbox-state`. After all the submitted job determines what is written, and we just prevent symlink injection."
>
> — operator, 2026-05-20 design discussion

Content under `.sandbox-state/` is hostile. The submitted job — i.e., whatever bash/python/whatever the agent dispatched via `sbatch` — decides what slurmstepd writes there. The bwrap/firejail RO overlay's only job is preventing **symlink injection** at the slurmstepd `open(--output)` layer:

- Without the overlay, an agent inside the sandbox could plant a symlink at a known staging path between the chaperon's `mkdir -p` and slurmstepd's `open()`: `ln -sf /etc/passwd $project_dir/.sandbox-state/slurm-logs/<expected-path>`. slurmstepd runs as the user, has no `O_NOFOLLOW`, and follows the symlink — writing job output to `/etc/passwd`. That's a real escape.
- With the overlay, the `ln -sf` fails inside the sandbox (`EROFS` on bwrap, `EACCES` on firejail), the symlink is never planted, slurmstepd opens the intended staging path, and job output stays inside `.sandbox-state/`.

The chaperon **never trusts** content read back from `.sandbox-state/` for any security decision. Don't read job output and dispatch on it; don't parse the chaperon log and trust its values for access checks. The dir is a write destination for trusted writers and a read source for the agent's convenience, nothing more.

### Distinction from reverted PR #50 (`WRITABLE_TREE_RO_PATHS`)

PR #50 introduced a general operator-configurable mechanism for RO-overlaying arbitrary user-owned paths (`.git/`, `.config/agent-sandbox/`, `.claude/projects/`). It was reverted on the grounds that:

> "the project directory is supposed to be entirely writable and entirely hostile under the threat model. Anything in the tree … can be tampered with by the agent, and running any of it outside the sandbox is an escape regardless of whether the tampering was in `.git/` or in a top-level file."

That argument is correct **for user-owned content**: protecting it doesn't add security (the project is hostile anyway), and it removes legitimate agent capabilities (in-sandbox `git commit`, sandbox config edits, etc.).

`.sandbox-state/` is **chaperon-owned content**:

- The agent never wrote it. The chaperon `mkdir`s it; slurmstepd writes inside; the chaperon writes its diagnostic log inside.
- The agent never *needed* to write it. Removing write access removes nothing the agent legitimately did.
- Protecting it adds a real security property: closes the slurmstepd symlink-plant vector that would otherwise be an escape.

So the narrow RO overlay for this one chaperon-owned path is consistent with the "project dir is hostile" framing — that framing applies to everything else under `$project_dir` (which remains entirely writable).

## Lifecycle

**Keep forever.** `.sandbox-state/` is a sandbox artifact. Logs accumulate (job count × log size). To reclaim:

```sh
rm -rf $project_dir/.sandbox-state/
```

No automatic sweeper. If accumulation becomes a problem, the operator decides the right policy for their project (e.g., a cron job, a `find -mtime` line in a Makefile target).

## Discoverability

The directory is hidden (leading dot) so it doesn't clutter `ls`. `find` and most editors will still surface it. The first-touch `mkdir` writes a `README.md` marker into the dir so operators encountering it via `find` / `tree` / `ls -la` have an immediate explanation without needing to read the source.

## Implementation entry points

- Helper functions: `chaperon/handlers/_handler_lib.sh::_sandbox_state_dir`, `::_ensure_sandbox_state_dir`, `::_slurm_output_feature_enabled`.
- Bind-mount overlay: `backends/bwrap.sh`, `backends/firejail.sh` (search for `.sandbox-state`).
- Landlock warning: `backends/landlock.sh` (search for `.sandbox-state`).
- First mkdir trigger: `chaperon/handlers/sbatch.sh::handle_sbatch`.
- Backend identity propagation to chaperon: `sandbox-exec.sh` after `detect_backend` (`export SANDBOX_BACKEND`).

For the slurm-output-specific use, see `docs/reference/chaperon-output-staging.md`.
