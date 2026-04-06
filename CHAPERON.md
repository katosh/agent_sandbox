# Chaperon: Secure Slurm Proxy for Sandboxed Sessions

> **Disclaimer:** The chaperon is a best-effort security mechanism. It has not been formally audited and comes with **no guarantees**. While it aims to prevent sandbox bypass via Slurm, there may be edge cases, Slurm version-specific behaviors, or site-specific configurations that weaken its protections. Review the [Security Properties](#security-properties) and [Known Limitations](#blocked-commands) sections, and test against your environment before relying on it. Use at your own risk.

## Problem

The previous Slurm isolation model exposed the munge authentication socket (`/run/munge`) read-only inside the sandbox, allowing the PATH-shadowing wrappers to authenticate with slurmctld. This meant anything inside the sandbox that could talk to munge — a crafted binary, Python ctypes, a direct `socat` call — could submit jobs without going through the sandbox wrappers. PATH shadowing was a speed bump, not a wall.

The chaperon replaces this with a **zero-trust architecture**: all Slurm authentication assets are blocked inside the sandbox, and a proxy process running *outside* the sandbox validates, wraps, and submits jobs on behalf of the sandboxed process.

## Architecture

```
sandbox-exec.sh
  │
  ├── mktemp -d → _CHAPERON_FIFO_DIR (chmod 700)
  ├── mkfifo req (chmod 600)
  ├── backend_prepare (bind-mounts FIFO dir into sandbox)
  ├── fork chaperon (reads req pipe, outside sandbox)
  ├── close FDs 3+ (no exceptions needed — FIFOs are filesystem-based)
  ├── export _CHAPERON_FIFO_DIR
  └── backend_exec → enters sandbox
        │
        └── Inside sandbox:
              - /run/munge BLOCKED (no munge auth)
              - /usr/bin/{sbatch,srun,...} BLOCKED
              - /etc/slurm/ BLOCKED
              - stub sbatch → writes to req FIFO (flock for atomicity)
                → chaperon validates, closes FD 3 for handler children
                (3>&-), wraps in sandbox-exec.sh, calls real sbatch
                → writes response to per-request FIFO → stub reads result
              - stub srun → writes to req FIFO → chaperon validates flags:
                  alloc mode (login node): wraps command in sandbox-exec.sh,
                    calls real srun → compute node runs sandboxed
                  step mode (compute node, SLURM_JOB_ID set): execs real
                    srun directly for job-step launching (MPI)
              - stub scancel → writes to req FIFO → chaperon validates
                job scope, calls real scancel
```

### Component Roles

**Trusted side** (runs outside the sandbox, has Slurm credentials):

| Component | Role |
|---|---|
| **chaperon.sh** | Main loop: reads requests from FIFO, dispatches to handlers, writes responses |
| **handlers/_handler_lib.sh** | Shared utilities: argument whitelisting, CWD validation, job wrapping, comment tag encoding/stripping |
| **handlers/sbatch.sh** | Validates args, wraps job in `sandbox-exec.sh`, submits to real sbatch |
| **handlers/srun.sh** | Validates flags; allocation mode wraps in `sandbox-exec.sh`, step mode execs real srun |
| **handlers/scancel.sh** | Validates job scope, forwards to real scancel |
| **handlers/squeue.sh** | Scopes output to session/project, strips chaperon tags |
| **handlers/scontrol.sh** | Scoped `show job`, `hold`, `release`, `requeue`, `update`; strips chaperon tags |
| **handlers/sacct.sh** | User-scoped accounting; strips chaperon tags |
| **handlers/sacctmgr.sh** | Read-only cluster/QOS/TRES queries; blocks user enumeration |
| **handlers/sinfo.sh, sstat.sh, sprio.sh, sshare.sh, sdiag.sh** | Read-only or user-scoped passthrough |
| **handlers/sreport.sh, blocked.sh** | Blocked (user enumeration risk / unsupported commands) |

**Untrusted side** (runs inside the sandbox, no Slurm credentials):

| Component | Role |
|---|---|
| **stubs/{sbatch,srun,scancel,...}** | PATH-shadow the real Slurm binaries; serialize the user's command into a FIFO request and relay the response |
| **stubs/_stub_lib.sh** | Shared stub helpers: FIFO communication, request framing, response parsing |

**Shared:**

| Component | Role |
|---|---|
| **protocol.sh** | `CHAPERON/1` wire protocol: base64 encode/decode, message framing |

## File Structure

```
chaperon/
├── chaperon.sh              # Main loop (runs OUTSIDE sandbox)
├── protocol.sh              # Read/write protocol messages (shared)
├── handlers/
│   ├── _handler_lib.sh      # Arg whitelisting, CWD validation, job wrapping
│   ├── sbatch.sh            # Validates, wraps, submits via real sbatch
│   ├── srun.sh              # Validates srun flags, wraps or execs real srun
│   ├── scancel.sh           # Validates job scope, cancels via real scancel
│   ├── squeue.sh            # Filters squeue output to scoped jobs
│   ├── scontrol.sh          # Scoped scontrol: show, hold, release, update
│   ├── sacct.sh             # User-scoped sacct (--allusers denied)
│   ├── sacctmgr.sh          # Read-only cluster/QOS/TRES queries
│   ├── sinfo.sh             # Read-only partition/node info
│   ├── sstat.sh             # User-scoped job step statistics
│   ├── sprio.sh             # User-scoped job priority factors
│   ├── sshare.sh            # User-scoped fairshare data
│   ├── sdiag.sh             # Read-only scheduler diagnostics
│   ├── sreport.sh           # Blocked (user enumeration risk)
│   └── blocked.sh           # Generic "command blocked" response
└── stubs/                   # PATH-shadowing stubs (all talk to chaperon)
    ├── _stub_lib.sh          # Stub→chaperon communication library
    ├── sbatch, srun, scancel, squeue, scontrol
    ├── sacct, sacctmgr, sinfo, sstat, sprio, sshare, sdiag, sreport
    └── salloc, sattach, sbcast, scrontab, scrun, strigger  # blocked
```

## Protocol: `CHAPERON/1`

Line-based, all user data base64-encoded (injection-proof in bash).

### Request (stub → chaperon)

```
CHAPERON/1 sbatch
ARG <base64>          # one per sbatch flag/value
ARG <base64>
CWD <base64>          # working directory (validated by handler)
SCRIPT <base64>       # job script content (--wrap converted to script)
RESP_FIFO <path>      # raw filesystem path (not base64) — validated by chaperon
END
```

Note: `protocol.sh` provides `chaperon_send_request()` as a helper, but `_stub_lib.sh` builds the request message directly (to include the `RESP_FIFO` field and support atomic writes via `flock`). The chaperon main loop also parses requests inline rather than using `chaperon_read_request()`, in order to support read timeouts and parent liveness checks.

### Response (chaperon → stub)

```
CHAPERON/1 RESULT
EXIT <number>         # exit code from real sbatch
STDOUT <base64>       # stdout (e.g., "Submitted batch job 12345")
STDERR <base64>       # stderr (e.g., validation errors)
END
```

### Safety Properties

- **`base64 -w 0`**: single-line encoding prevents newline injection
- **`IFS= read -r`**: prevents word splitting on read
- **Unknown lines silently ignored**: forward compatibility — new fields can be added without breaking old readers
- **No shell interpretation**: the chaperon never passes user data to `sh -c`, `eval`, or any form of shell expansion

## FIFO Design

The communication channel uses named pipes (FIFOs) in a per-session temporary directory created before the sandbox is entered:

1. **Per-session directory**: `mktemp -d` creates a directory with `chmod 700` — only the owning user can access it. The directory is bind-mounted into the sandbox so both sides can reach it.
2. **Persistent request pipe**: A single `req` FIFO handles all requests. The chaperon opens it O_RDWR to prevent blocking and avoid EOF between requests.
3. **Per-request response pipes**: Each stub creates an atomically-named directory (`mktemp -d`) containing a response FIFO (`fifo`), sends the path in the request, and reads the response from it. This eliminates the TOCTOU window that `mktemp -u` + `mkfifo` would have. The FIFO is created with `mkfifo -m 600` (permissions set atomically).
4. **No FD inheritance needed**: Unlike socketpairs, FIFOs are filesystem-backed and survive bwrap's FD closing (which closes all FDs > 2). No exemptions needed.
5. **Timeouts**: The stub reads responses with a 30-second timeout (`chaperon_read_response` in `_stub_lib.sh`) to prevent infinite hangs if the chaperon dies. The chaperon uses a 30-second body read timeout and a 10-second response write timeout to prevent stalls from malicious or dead stubs. All internal squeue calls (for scope resolution) use `timeout 10`.
6. **Cleanup on exit**: The chaperon's EXIT trap removes the entire FIFO directory.

## Chaperon Lifecycle

1. **Creation**: `sandbox-exec.sh` creates a FIFO directory via `mktemp -d` and a request pipe via `mkfifo`, launches `chaperon.sh` as a background process, and exports `_CHAPERON_FIFO_DIR` for the sandbox.
2. **Orphan prevention**: The chaperon sets `PR_SET_PDEATHSIG` via Python/ctypes so it receives SIGTERM if its parent (sandbox-exec.sh) dies. This prevents orphaned chaperon processes.
3. **Signal handling**: SIGTERM and SIGINT are trapped for clean shutdown (FD cleanup).
4. **Main loop**: Reads requests inline with timeouts (30-second body timeout to prevent stalls from malformed requests), dispatches to the appropriate handler with FD 3 closed (`3>&-`) to prevent child processes from inheriting the request FIFO, captures stdout/stderr, and writes the response via the held response FD with a 10-second write timeout.
5. **Exit**: On read error, parent death (liveness polling), or signal, the chaperon removes the FIFO directory and exits 0.

Note: `protocol.sh` provides a `chaperon_read_request()` helper, but the main loop in `chaperon.sh` performs its own inline parsing to support read timeouts and liveness checks that the helper does not provide.

## Handler Dispatch

Filesystem-based: when a request for command `X` arrives, the chaperon looks for `handlers/X.sh` and calls `handle_X()`. If no handler exists, `handlers/blocked.sh` is used.

This design makes it trivial to add support for new commands (drop a handler file) or block them (they're blocked by default).

### sbatch Handler

The sbatch handler (`handlers/sbatch.sh`) performs three validation steps before submission:

1. **CWD validation**: The requested working directory must be a physical path under the project directory (resolves symlinks to prevent escape). Both sbatch and srun (allocation mode) validate CWD.
2. **Argument whitelisting**: Every flag is checked against `_SBATCH_ALLOWED_FLAGS` (~40 safe flags). Denied flags cause immediate rejection with a clear error message.
3. **Job wrapping**: The user's script is written to a temp file, and a wrapper script is generated that runs it inside `sandbox-exec.sh --project-dir $PROJECT_DIR`. The wrapper is submitted to the real sbatch.

### Job Tagging and Scoping via `--comment`

The chaperon needs to track which jobs belong to which sandbox session/project so that `squeue`, `scancel`, and other scoped handlers can filter appropriately. This is done by injecting a structured tag into Slurm's `--comment` field on every submitted job.

**Why `--comment` and not `--job-name`?** The `--job-name` (`-J`) field is user-visible, commonly set by workflows and scripts, and used for human identification (e.g., `alignment-step1`, `train-model`). Overwriting or prefixing it would break existing workflows that parse job names. The `--comment` field, by contrast, is rarely used in practice — it's a free-text metadata field that most users never set, and it doesn't appear in default `squeue` output. This makes it ideal for machine-readable tagging without interfering with user workflows.

**What happens to user-supplied comments?** If the user passes `--comment "my note"` to sbatch, the chaperon preserves it by appending it (percent-encoded) to the tag as `user=my%20note`. The encoding prevents crafted comments from injecting fake `chaperon:`, `sid=`, or `proj=` patterns that would confuse scope filtering. When the sandbox user queries jobs (via `squeue`, `scontrol show job`, or `sacct`), the chaperon tag is automatically stripped and the original comment is restored — the user sees `my note`, not the internal tag.

#### Tag format

```
chaperon:sid=<session_id>,proj=<project_hash>[,user=<original_comment>]:END
```

| Field | Content | Purpose |
|---|---|---|
| `sid` | `<PID>.<epoch>` | Unique per chaperon instance (session scope). Set once at startup and guarded against re-initialization when `_handler_lib.sh` is re-sourced per handler dispatch. |
| `proj` | First 12 hex of `md5(project_dir)` | Groups jobs by project (project scope) |
| `user` | User's original `--comment` value (percent-encoded) | Preserves user metadata |
| `:END` | Literal end marker | Unambiguous tag boundary for stripping (colons are percent-encoded in user values, so `:END` cannot appear inside the encoded comment) |

This tag is set once at submission and is **inherited by array tasks**, **survives preemption** (job ID may change, comment does not), and is **queryable via squeue/sacct**:

```bash
squeue --me -h -o "%i %k" | grep "chaperon:sid=$SID"     # session
squeue --me -h -o "%i %k" | grep "chaperon:.*proj=$HASH"  # project
squeue --me -h -o "%i %k" | grep "chaperon:"              # all sandbox jobs
```

### scancel Handler

The scancel handler (`handlers/scancel.sh`) queries `squeue --comment` to resolve which jobs are in scope, then passes only matching IDs to the real scancel. No file-based tracking — the tag in Slurm is the source of truth.

1. **Argument whitelisting**: Only safe scancel flags are forwarded. Flags like `--user`, `--me`, `--account`, `--wckey` are denied — scope is controlled by the chaperon.
2. **Job ID validation**: Positional arguments must be numeric job IDs.
3. **Scope filtering**: Requested job IDs are checked against `squeue` output filtered by the chaperon tag.
4. **`scancel all`**: Cancels everything within scope (no specific IDs needed).

#### Scope Levels

Configured via `SLURM_SCOPE` in `sandbox.conf`. Applies to scancel, squeue, scontrol, and sstat:

| Scope | Behavior | Filter |
|---|---|---|
| `session` | Only jobs from THIS sandbox session | `chaperon:sid=<this_session>` |
| `project` (default) | Jobs from any sandbox with same project dir | `chaperon:.*proj=<hash>` |
| `user` | All jobs of the current user (including non-sandbox jobs) | `squeue --me` |
| `none` | No scope restriction (full access to your own jobs) | `squeue --me` |

### Denied sbatch Flags

These flags are explicitly rejected because they could bypass sandboxing:

| Flag | Reason |
|---|---|
| `--wrap` | Reconstructed by the handler (user data from protocol, not shell) |
| `--chdir` / `-D` | CWD comes from protocol and is validated against project dir |
| `--uid` / `--gid` | Must not impersonate other users |
| `--get-user-env` | Can leak host environment variables |
| `--propagate` | Can propagate unsafe resource limits |
| `--export` | Could inject env vars to bypass sandbox detection |
| `--prolog` / `--epilog` | Run arbitrary scripts outside sandbox control |
| `--task-prolog` / `--task-epilog` | Same as above |
| `--burst-buffer-file` / `--bbf` | Arbitrary file access |
| `--bcast` | Copy binary to compute nodes (bypass wrapping) |
| `--container` | OCI container execution could bypass sandbox wrapping |

Unknown flags (not in the whitelist) are also rejected.

### srun Handler

The srun handler (`handlers/srun.sh`) operates in two modes:

**Allocation mode** (no `SLURM_JOB_ID` — login node):
1. Validates CWD is under the project directory (same check as sbatch)
2. Validates flags against a whitelist that includes scheduling flags (`-p`, `-A`, `-t`, etc.)
3. Wraps the command in `sandbox-exec.sh --project-dir $DIR` so the compute-node process inherits sandbox restrictions
4. Calls real srun with the validated flags and wrapped command

**Step mode** (`SLURM_JOB_ID` set — inside a compute-node allocation):
1. Validates flags against a step-only whitelist (no scheduling flags — steps inherit the job's resources)
2. Execs real srun directly — the command runs within the existing sandboxed allocation

**Denied srun flags** (both modes):

| Flag | Reason |
|---|---|
| `--pty` | No PTY passthrough via the chaperon protocol |
| `--jobid` / `-j` | Cannot attach to arbitrary allocations |
| `--uid` / `--gid` | Must not impersonate other users |
| `--export` | Could inject env vars to bypass sandbox detection |
| `--chdir` / `-D` | CWD comes from protocol and is validated |
| `--get-user-env` | Can leak host environment variables |
| `--propagate` | Can propagate unsafe resource limits |
| `--prolog` / `--epilog` / `--task-prolog` / `--task-epilog` | Arbitrary script execution |
| `--bcast` | Binary broadcast (bypass wrapping) |
| `--container` | OCI container execution bypasses sandbox |
| `--network` | Network namespace manipulation |

In step mode, allocation flags (`-p`, `-A`, `-t`, `-q`, `--reservation`, etc.) are also denied.

### squeue Handler

The squeue handler (`handlers/squeue.sh`) filters queue output to only show jobs within scope. Uses the `SLURM_SCOPE` setting from `sandbox.conf`.

- Flags like `--user`, `--me`, `--account` are denied (scope controlled by chaperon)
- If specific job IDs are requested via `-j`, they're validated against scope
- Otherwise, all jobs in scope are shown
- All internal squeue calls use `timeout 10` to prevent hangs if slurmctld is unresponsive

### scontrol Handler

The scontrol handler (`handlers/scontrol.sh`) allows a subset of scontrol subcommands with scope enforcement:

| Subcommand | Scoped? | Notes |
|---|---|---|
| `show job [ID]` | Yes | Shows only chaperon-submitted jobs |
| `show node/partition/config/step` | No | Read-only system info |
| `hold JOBID` | Yes | Must be in scope |
| `release JOBID` | Yes | Must be in scope |
| `requeue JOBID` | Yes | Must be in scope |
| `update job JOBID Key=Val` | Yes | Must be in scope; only safe update keys allowed |

Denied subcommands: `shutdown`, `reconfigure`, `create`, `delete`, and all others.

Denied update keys: `UserId`, `GroupId`, `WorkDir`, `AdminComment`, and all keys not in the whitelist. See `handlers/scontrol.sh` for the full list.

### sacct Handler

The sacct handler (`handlers/sacct.sh`) enforces user-level scoping:

- Always injects `--user=$(whoami)` — only the current user's jobs are shown
- `--allusers`, `--user`, `--uid`, `--accounts` are denied
- Job-level scoping (by chaperon comment) is intentionally not applied — sacct is retrospective and the full job history is useful for debugging

### sacctmgr Handler

The sacctmgr handler (`handlers/sacctmgr.sh`) is heavily restricted to prevent user/group enumeration:

| Subcommand | Allowed targets |
|---|---|
| `show` / `list` | `cluster`, `qos`, `tres`, `configuration` |

**Denied show targets**: `user`, `account`, `association`, `coordinator`, `event`, `reservation`, `transaction`, `wckey` — all expose user/group data.

**Denied subcommands**: `add`, `modify`, `delete`, `archive`, `dump`, `load`, `reconfigure` — all write operations.

### sinfo Handler

Read-only passthrough for partition/node status. No scoping needed — this is system information. Unknown flags are rejected.

### sstat Handler

Shows statistics for running job steps. Job step IDs (format `jobid.stepid`) are validated — the base job ID must be in the current scope. Uses `_validate_job_in_scope` from `_handler_lib.sh`.

### sprio Handler

Shows priority factors for pending jobs. Always injects `--user=$(whoami)` to scope output to the current user. `--allusers` and `--user` are denied.

### sshare Handler

Shows fairshare data. Always injects `--user=$(whoami)`. Denies `--all`, `--user`, and `--accounts` to prevent enumerating other users' fairshare allocations.

### sdiag Handler

Read-only scheduler diagnostics passthrough. Denies `--reset` (clears scheduler statistics — a write operation).

### sreport Handler

Blocked entirely. `sreport` generates accounting reports across many sub-report types, many of which enumerate users and accounts. Use `sacct` with formatting options for similar data scoped to your user.

### Comment Stripping

The chaperon injects structured tags into Slurm's `--comment` field for scoping, but the sandbox user should never see these internals. The `_strip_chaperon_tags()` function in `_handler_lib.sh` is piped over the output of all user-facing handlers that may display comments: **squeue**, **scontrol** (`show job`), and **sacct**.

The stripping pipeline:
1. **Extracts the user value**: regex matches the full tag `chaperon:sid=...,proj=...[,user=VALUE]:END` and replaces it with just `VALUE` (or empty string if no user comment was set)
2. **Decodes percent-encoding**: restores `%2C` → `,`, `%3A` → `:`, `%3D` → `=`

The `:END` marker makes extraction reliable across all Slurm output formats (tabular, parsable/pipe-delimited, JSON, YAML, `scontrol` key=value). Because colons are percent-encoded (`%3A`) in user values, `:END` cannot appear inside the encoded comment, providing an unambiguous boundary.

**Result**: sandbox users see their original `--comment` value (or an empty field) — the Slurm interface behaves as expected with no chaperon artifacts visible.

Comments on jobs **not** submitted through the chaperon (e.g., in `user`/`none` scope modes) pass through unchanged.

### Blocked Commands

The following commands are routed to `blocked.sh` (no handler):

| Command | Reason |
|---|---|
| `salloc` | Interactive allocations can't be safely proxied (requires PTY) |
| `sattach` | Attaching to step I/O could interfere with other jobs |
| `sbcast` | File broadcast bypasses sandbox restrictions |
| `scrontab` | Recurring jobs would bypass sandbox wrapping |
| `scrun` | OCI container launcher bypasses sandbox |
| `strigger` | Event triggers can execute arbitrary commands |

## What Gets Blocked Inside the Sandbox

| Resource | bwrap | firejail | landlock |
|---|---|---|---|
| `/run/munge/` (auth socket) | Hidden (tmpfs /run, not re-mounted) | `--blacklist=/run/munge` | Not granted (EACCES) |
| `/usr/bin/{sbatch,srun,...}` | `--ro-bind /dev/null` | `--blacklist=` | Not blocked (known limitation) |
| `/etc/slurm/`, `/etc/slurm-llnl/` | `--tmpfs` | `--blacklist=` | Not blocked |
| Munge auth capability | **None** — can't auth without socket | **None** | **None** — EACCES on socket |

**Defense in depth**: Without the munge socket, even finding a Slurm binary (on Landlock where `/usr/bin` can't be blocked) is useless — authentication will fail. The chaperon is the only path to Slurm interaction (job submission and step launching).

## Comparison with Previous Architecture

| Aspect | Previous (PATH wrappers) | Chaperon |
|---|---|---|
| Munge socket | **Exposed** (read-only inside sandbox) | **Blocked** (not mounted/blacklisted) |
| Slurm binaries | **Relocated** (bwrap) or **available** (others) | **Blocked** (all backends) |
| Bypass via crafted binary | **Possible** (munge auth available) | **Impossible** (no munge, no binaries) |
| Bypass via `/usr/bin/sbatch` | **Possible** (firejail/landlock) | **Impossible** (blocked/blacklisted) |
| Argument injection | **Possible** (wrappers pass-through) | **Blocked** (whitelist rejects unknown flags) |
| Communication channel | PATH ordering (soft) | Named pipes (per-session temp dir, 700 permissions) |
| Compute-node wrapping | Via wrapper scripts | Via wrapper scripts (same) |

## Security Properties

1. **No shell interpretation**: The chaperon never passes user data to `sh -c`, `eval`, or any form of shell expansion. Script content is written to files via `printf '%s\n'`, and arguments are passed as array elements.
2. **Base64 encoding**: All user data in the protocol is base64-encoded, preventing newline injection, null byte issues, and protocol framing attacks.
3. **Argument whitelisting**: Only explicitly allowed sbatch flags are forwarded. The whitelist is conservative — new Slurm flags must be manually added.
4. **CWD validation**: The working directory is resolved to a physical path (following symlinks) and validated as being under the project directory. Both sbatch and srun (allocation mode) perform this check.
5. **Always wrapped**: Every job submitted through the chaperon is wrapped in `sandbox-exec.sh`, ensuring compute-node execution inherits sandbox restrictions.
6. **FIFO security**: Communication uses named pipes in a per-session temp directory with 700 permissions. Response FIFOs are created inside atomically-named subdirectories (`mktemp -d`), validated against path traversal (`..`) and symlinks (`-L` check), and must match the expected `FIFO_DIR/resp-XXXXXX/fifo` structure.
7. **Die-with-parent**: The chaperon sets `PR_SET_PDEATHSIG` and polls parent liveness every 5 seconds as a fallback.
8. **Handler dispatch validation**: Command names are validated against `^[a-z_][a-z0-9_]*$` to prevent path traversal in handler lookup.
9. **TOCTOU prevention**: Response FIFOs are opened to a held FD immediately after validation, and writes go through the FD (not the path). Symlinks are rejected before the `-p` (FIFO) check to prevent symlink-following attacks.
10. **#SBATCH directive filtering**: `#SBATCH` directives are filtered against the flag whitelist — safe directives pass through, dangerous ones are stripped.
11. **Atomic request writes**: Request messages are built into a buffer and written with `flock` on the request FIFO lock file to prevent interleaving from concurrent stubs.
12. **scancel scoping**: Job cancellation is restricted to jobs submitted by this session/project/user, preventing cancellation of other users' jobs.

## Testing

The test suite (`test.sh` sections 5–6) verifies:

- PATH shadowing resolves to chaperon stubs
- Munge socket is hidden/blocked inside sandbox
- Slurm binaries are blocked inside sandbox (bwrap/firejail)
- Slurm config is hidden inside sandbox (bwrap/firejail)
- `srun --pty` and `srun --jobid` are denied by chaperon
- `_CHAPERON_FIFO_DIR` is set inside sandbox
- Chaperon request FIFO exists inside sandbox
- Comment stripping (`_strip_chaperon_tags`):
  - User comment restored from chaperon tag
  - Empty result when no user comment was set
  - Percent-encoded special characters decoded correctly
  - Non-chaperon comments pass through unchanged
  - Correct across output formats: tabular, JSON, pipe-delimited (parsable)
- `sbatch --wrap` via chaperon submits jobs successfully
- No infinite recursion in chaperon sbatch path
- Denied flags (`--uid`, `--get-user-env`) are rejected
- scancel can cancel jobs submitted by the same session
- scancel rejects jobs not submitted by the current session

## Extending

### Adding a new Slurm command

1. Create `chaperon/handlers/newcmd.sh` with a `handle_newcmd()` function
2. Create `chaperon/stubs/newcmd` that uses `_stub_lib.sh` to send the request (see `stubs/scancel` for a minimal example)
3. Make the stub executable: `chmod +x chaperon/stubs/newcmd`
4. The chaperon's filesystem-based dispatch will automatically route requests
5. Binary blocking is automatic: backends scan `chaperon/stubs/` at startup to build the block list (any executable file not starting with `_` is blocked)
6. `install.sh` uses globs to copy handlers and stubs — no edits needed

To block a command without proxying it, create a standalone stub that prints an error without sourcing `_stub_lib.sh`.

### Adding a new allowed sbatch flag

Add the flag to `_SBATCH_ALLOWED_FLAGS` in `handlers/_handler_lib.sh`. If it takes a value argument, also add it to `_SBATCH_VALUE_FLAGS`.

### Configuring Slurm scope

Set `SLURM_SCOPE` in `sandbox.conf`:

```bash
# Jobs from any sandbox session with the same project dir (default)
SLURM_SCOPE="project"

# Only jobs submitted by THIS sandbox session
SLURM_SCOPE="session"

# All jobs of the current user (including non-sandbox jobs)
SLURM_SCOPE="user"

# No restriction (full access to your own jobs)
SLURM_SCOPE="none"
```

### Querying sandbox jobs

The `--comment` tag makes it easy to filter squeue from outside:

```bash
# All sandbox jobs for this user
squeue --me -o "%.18i %.9P %.8j %.2t %.10M %k" | grep chaperon:

# Jobs from a specific project
squeue --me -h -o "%i %k" | grep "proj=<hash>"
```
