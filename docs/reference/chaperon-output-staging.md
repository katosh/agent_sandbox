# Chaperon Slurm `--output` / `--error` Staging

> **Disclaimer:** Best-effort defense against a specific class of slurmstepd-side escape. Read the [Threat-model framing](sandbox-state-dir.md#threat-model-framing) for `.sandbox-state/` and the [Limitations](#limitations) section below before relying on this.

## The problem

`sbatch --output=<path>` and `sbatch --error=<path>` instruct slurmstepd to redirect the job's stdout/stderr to `<path>` on the compute node. Slurm opens the file as the submitting user with `O_WRONLY|O_CREAT|O_TRUNC` (no `O_NOFOLLOW`), *before* the wrapped job (and therefore the compute-node sandbox) starts. Without intervention, the chaperon's other defenses don't apply:

- `sbatch --output=/etc/cron.d/evil` — slurmstepd writes job output to `/etc/cron.d/evil` (escape).
- `sbatch --output=../../etc/passwd` — relative path resolves against the chaperon's submit cwd (which is under `$project_dir` thanks to #65), but `..`-traversal escapes the project tree (escape).
- `sbatch --output=symlink_pointing_outside` — slurmstepd follows the symlink, writes outside `$project_dir` (escape).

PR #66 closed the cwd-preservation half of a related class. This PR (#67) closes the `--output`/`--error` half.

## How it works

The chaperon transforms the user's `--output` / `--error` value (both command-line and `#SBATCH` directive forms) into an absolute path under `$project_dir/.sandbox-state/slurm-logs/`. Slurm writes job output to the transformed path; the sandbox bind-mount layer (RO overlay on bwrap/firejail; see [`.sandbox-state/`](sandbox-state-dir.md)) prevents an in-sandbox agent from symlink-planting between the chaperon's `mkdir -p` and slurmstepd's `open()`. The in-sandbox wrapper then creates a **relative symlink** from the user's intended path to the staging file — gated by the bind-mount envelope, so a non-sandbox-writable intended path (e.g., `/etc/cron.d/evil`) results in `ln -s` failing gracefully and the log existing only at the staging location.

### Path transformation

Done in `chaperon/handlers/_handler_lib.sh::_transform_slurm_output_path` (pure function, table-tested in `test.sh` §6.5a). Rules:

| Input pattern              | Transformation                            | Why                                  |
|----------------------------|-------------------------------------------|--------------------------------------|
| Leading `/` (absolute)     | Encoded as `__abs__/` prefix              | Reverses to absolute on the way out  |
| `..` path component        | Rewritten to `__updir__` (literal dir)    | Can't traverse out of staging        |
| `.` path component         | Dropped                                   | Path normalisation                   |
| Empty component (from `//`)| Dropped                                   | Path normalisation                   |
| `%`-pattern (`%j` etc.)    | Left intact                               | slurmstepd substitutes at open time  |
| `..foo` (literal filename) | Left alone                                | Component-aware; only exact `..` triggers |

Examples (with `$project_dir = /p`):

| User input              | Chaperon-transformed staging path                        |
|-------------------------|----------------------------------------------------------|
| `out.log`               | `/p/.sandbox-state/slurm-logs/out.log`                   |
| `logs/job-%j.log`       | `/p/.sandbox-state/slurm-logs/logs/job-%j.log`           |
| `/etc/passwd`           | `/p/.sandbox-state/slurm-logs/__abs__/etc/passwd`        |
| `../../etc/foo`         | `/p/.sandbox-state/slurm-logs/__updir__/__updir__/etc/foo` |
| `..foo/bar`             | `/p/.sandbox-state/slurm-logs/..foo/bar`                 |

### In-sandbox symlink

`chaperon/handlers/_handler_lib.sh::create_wrapped_script` emits a small bash prelude that runs **inside the sandbox** as the first action of the wrapped job (after the cwd-restore from #66, before the user's script body). The prelude:

1. Reads the user's intended template (`$_USER_SLURM_OUTPUT` / `_ERROR`) and staging template (`$_STAGING_SLURM_*`) — embedded as literal `printf %q` strings in the wrapper.
2. Resolves Slurm `%`-patterns against `$SLURM_JOB_ID` / `$SLURM_ARRAY_*` / `$SLURMD_NODENAME` / `$SLURM_NODEID` / `$SLURM_PROCID` / `$USER` / `$SLURM_JOB_NAME` to get the final on-disk paths.
3. `mkdir -p`s the intended path's parent (inside the sandbox — fails gracefully if not writable).
4. Computes a relative path from intended-parent to staging via `realpath --relative-to`, so the symlink survives `$project_dir` rename/relocation.
5. Removes anything pre-existing at the intended path (matches Slurm's default `O_TRUNC` overwrite semantics).
6. Creates the symlink via `ln -s <relative-target> <intended>`.

**Failures are non-fatal.** If `mkdir -p` or `ln -s` fails (intended path not sandbox-writable), the prelude emits a one-line warning to stderr (which flows into the job log itself) and returns 0. The job continues; the log lives only at the staging path. This is the "user picked an unwritable target" graceful-degrade path.

### When the prelude runs

Always inside a bash context (the prelude uses bash-specific `${var//pat/replacement}` substitution):

- **Shell-interpreter scripts (bash/sh/dash/zsh/...):** Wrapped as `bash -c '<prelude>; exec <user-interp> -s -- "$@"'`. The outer bash runs the prelude, then `exec`s the user's chosen shell with the script piped via stdin.
- **Non-shell scripts (python, R, perl, ...):** Wrapped as `bash -c '<prelude>; <existing runner script>'`. The runner materialises the script to a tmpfile and exec's it.
- **`sbatch --wrap`:** Stub converts to a `#!/bin/bash --` script before submission, so it always lands in the shell-interpreter path.

## Backend feature matrix

| Backend  | RO overlay | Path transform | Wrapper symlink | Chaperon log dir                    |
|----------|------------|----------------|-----------------|-------------------------------------|
| bwrap    | yes (`--ro-bind`)    | yes  | yes  | `.sandbox-state/chaperon/<id>.log`  |
| firejail | yes (`--read-only=`) | yes  | yes  | `.sandbox-state/chaperon/<id>.log`  |
| landlock | no (additive rules) | **no** | **no** | `~/.local/state/agent-sandbox/chaperon/<id>.log` (XDG fallback) |

The landlock backend skips the entire feature because without the RO overlay, the symlink-plant attack is still exploitable. Operators on landlock get exactly the pre-#67 behavior: `--output` flows verbatim to slurmstepd, the escape vector remains. One-line `NOTE` at backend init (when `.sandbox-state/` exists) tells operators the feature is off.

## Env-var contract

When the feature is active, `validate_sbatch_args` and the `#SBATCH` directive filter populate four chaperon-local variables (cleared at start of each `validate_sbatch_args` call):

| Variable                  | Set when                          | Meaning                                |
|---------------------------|-----------------------------------|----------------------------------------|
| `_USER_SLURM_OUTPUT`      | `--output` present, feature on    | User's verbatim `--output` value       |
| `_STAGING_SLURM_OUTPUT`   | Same                              | Chaperon-transformed staging path      |
| `_USER_SLURM_ERROR`       | `--error` present, feature on     | User's verbatim `--error` value        |
| `_STAGING_SLURM_ERROR`    | Same                              | Chaperon-transformed staging path      |

These values are baked into the generated wrapper via `printf %q`, not passed as job env vars. This means they survive `sbatch --export=NONE` and similar env-filter directives.

## Limitations

- **Landlock:** Feature is fully disabled (documented in the backend matrix above). `--output=/etc/foo` still escapes.
- **`%`-patterns in directory components:** `--output=job-%j/out` — the chaperon `mkdir -p`s the literal-component parent of the staging template (`job-%j/`, with literal `%j`), but slurmstepd substitutes `%j` at open time and tries to write to `job-12345/out` (which doesn't exist). slurmstepd's `open()` fails; the job runs but `--output` redirection is broken. **Workaround:** the user should `mkdir -p` the substituted dir before submitting, or use `%j` only in filenames.
- **TOCTOU on the intended path:** Between the wrapper's `mkdir -p` of the intended parent and `ln -s`, an attacker with concurrent sandbox access could move/replace the parent. The bind-mount envelope still caps the damage (writes only land where the agent could have written anyway), but the symlink may end up pointing to a different file than intended. Single-sandbox-per-project is the assumed deployment.
- **Non-shell, non-bash-runner languages:** The wrapper-side prelude is bash. Non-shell scripts (python etc.) are launched via a bash runner that hosts the prelude, so this is transparent.

## Implementation entry points

- Path transformation: `chaperon/handlers/_handler_lib.sh::_transform_slurm_output_path`.
- Feature gate: `chaperon/handlers/_handler_lib.sh::_slurm_output_feature_enabled`.
- Wire into argument validation: `validate_sbatch_args` in the same file.
- Wire into `#SBATCH` directive filter: `create_wrapped_script` in the same file.
- Wrapper-side symlink prelude: composed in `create_wrapped_script`, embedded into the bash `-c` arg of the in-sandbox invocation.
- Submit-side `mkdir -p` of staging parent: `chaperon/handlers/sbatch.sh::handle_sbatch`.

For the broader `.sandbox-state/` convention and threat-model framing, see [sandbox-state-dir.md](sandbox-state-dir.md).
