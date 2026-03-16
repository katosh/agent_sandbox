# Chaperon: Secure Slurm Proxy for Sandboxed Sessions

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
              - stub sbatch → writes to req FIFO → chaperon validates,
                wraps in sandbox-exec.sh, calls real sbatch → writes
                response to per-request FIFO → stub reads result
              - stub srun (login node) → prints "use sbatch" → exits 1
              - stub srun (compute node, SLURM_JOB_ID set) → validates
                flags against whitelist → execs real srun for step launching
```

### Component Roles

| Component | Location | Role |
|---|---|---|
| **chaperon.sh** | Outside sandbox | Main loop: reads requests, dispatches to handlers, writes responses |
| **protocol.sh** | Shared (both sides) | `CHAPERON/1` wire protocol: base64 encode/decode, message framing |
| **handlers/sbatch.sh** | Outside sandbox | Validates sbatch args, wraps job in sandbox-exec.sh, submits to real sbatch |
| **handlers/blocked.sh** | Outside sandbox | Returns "command not allowed" for unsupported Slurm commands |
| **handlers/_handler_lib.sh** | Outside sandbox | Argument whitelist, CWD validation, wrapper script generation |
| **handlers/scancel.sh** | Outside sandbox | Validates job scope, cancels via real scancel |
| **stubs/sbatch** | Inside sandbox | Parses user's sbatch invocation, sends request via named pipe |
| **stubs/srun** | Inside sandbox | Login node: blocks with error. Compute node: validates flags, execs real srun for step launching |
| **stubs/scancel** | Inside sandbox | Sends cancel requests to chaperon via named pipe |
| **stubs/_stub_lib.sh** | Inside sandbox | Stub-to-chaperon communication helpers |

## File Structure

```
chaperon/
├── chaperon.sh              # Main loop (runs OUTSIDE sandbox)
├── protocol.sh              # Read/write protocol messages (shared)
├── handlers/
│   ├── _handler_lib.sh      # Arg whitelisting, CWD validation, job wrapping
│   ├── sbatch.sh            # Validates, wraps, submits via real sbatch
│   ├── scancel.sh           # Validates job scope, cancels via real scancel
│   └── blocked.sh           # Generic "blocked" response
└── stubs/
    ├── _stub_lib.sh          # Stub→chaperon communication
    ├── sbatch                # PATH-shadowing stub (talks to chaperon)
    ├── scancel               # Sends cancel requests to chaperon
    └── srun                  # Standalone blocked stub (no chaperon)
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
RESP_FIFO <path>      # path to per-request response FIFO
END
```

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
3. **Per-request response pipes**: Each stub creates a response FIFO with an unpredictable name (`mktemp -u`), sends the path in the request, and reads the response from it. This prevents response mixing between concurrent requests.
4. **No FD inheritance needed**: Unlike socketpairs, FIFOs are filesystem-backed and survive bwrap's FD closing (which closes all FDs > 2). No exemptions needed.
5. **Cleanup on exit**: The chaperon's EXIT trap removes the entire FIFO directory.

## Chaperon Lifecycle

1. **Creation**: `sandbox-exec.sh` creates a FIFO directory via `mktemp -d` and a request pipe via `mkfifo`, launches `chaperon.sh` as a background process, and exports `_CHAPERON_FIFO_DIR` for the sandbox.
2. **Orphan prevention**: The chaperon sets `PR_SET_PDEATHSIG` via Python/ctypes so it receives SIGTERM if its parent (sandbox-exec.sh) dies. This prevents orphaned chaperon processes.
3. **Signal handling**: SIGTERM and SIGINT are trapped for clean shutdown (FD cleanup).
4. **Main loop**: Reads requests via `chaperon_read_request()`, dispatches to the appropriate handler, captures stdout/stderr, and sends the response.
5. **Exit**: On read error, parent death (liveness polling), or signal, the chaperon removes the FIFO directory and exits 0.

## Handler Dispatch

Filesystem-based: when a request for command `X` arrives, the chaperon looks for `handlers/X.sh` and calls `handle_X()`. If no handler exists, `handlers/blocked.sh` is used.

This design makes it trivial to add support for new commands (drop a handler file) or block them (they're blocked by default).

### sbatch Handler

The sbatch handler (`handlers/sbatch.sh`) performs three validation steps before submission:

1. **Argument whitelisting**: Every flag is checked against `_SBATCH_ALLOWED_FLAGS` (~40 safe flags). Denied flags cause immediate rejection with a clear error message.
2. **CWD validation**: The requested working directory must be a physical path under the project directory (resolves symlinks to prevent escape).
3. **Job wrapping**: The user's script is written to a temp file, and a wrapper script is generated that runs it inside `sandbox-exec.sh --project-dir $PROJECT_DIR`. The wrapper is submitted to the real sbatch.

### Job Tagging via `--comment`

Every job submitted through the chaperon is tagged with a structured `--comment`:

```
chaperon:sid=<session_id>,proj=<project_hash>[,user=<original_comment>]
```

| Field | Content | Purpose |
|---|---|---|
| `sid` | `<PID>.<epoch>` | Unique per chaperon instance (session scope) |
| `proj` | First 12 hex of `md5(project_dir)` | Groups jobs by project (project scope) |
| `user` | User's original `--comment` value (percent-encoded) | Preserves user metadata |

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

#### scancel Scope Levels

Configured via `CHAPERON_SCANCEL_SCOPE` in `sandbox.conf`:

| Scope | Behavior | squeue filter |
|---|---|---|
| `session` (default) | Only jobs from THIS sandbox session | `chaperon:sid=<this_session>` |
| `project` | Jobs from any sandbox with same project dir | `chaperon:.*proj=<hash>` |
| `user` | Any chaperon-submitted job of this user | `chaperon:` prefix |

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

## What Gets Blocked Inside the Sandbox

| Resource | bwrap | firejail | landlock |
|---|---|---|---|
| `/run/munge/` (auth socket) | Hidden (tmpfs /run, not re-mounted) | `--blacklist=/run/munge` | Not granted (EACCES) |
| `/usr/bin/{sbatch,scancel,...}` | `--ro-bind /dev/null` | `--blacklist=` | Not blocked (known limitation) |
| `/usr/bin/srun` | Blocked at original path; exposed at `/run/sandbox/srun-real` for step stub | Not blacklisted (stub controls access) | Not blocked (stub controls access) |
| `/etc/slurm/`, `/etc/slurm-llnl/` | `--tmpfs` | `--blacklist=` | Not blocked |
| Munge auth capability | **None** — can't auth without socket | **None** | **None** — EACCES on socket |

**Compute-node exception**: When `SLURM_JOB_ID` is set (inside a Slurm allocation), munge and slurm config are exposed read-only so that `srun` can launch job steps within the existing sandboxed allocation. This is safe because the allocation itself was approved by the chaperon, and the srun stub validates all flags.

**Defense in depth**: Without the munge socket (login node), even finding a Slurm binary (on Landlock where `/usr/bin` can't be blocked) is useless — authentication will fail. The chaperon is the only path to job submission.

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
4. **CWD validation**: The working directory is resolved to a physical path (following symlinks) and validated as being under the project directory.
5. **Always wrapped**: Every job submitted through the chaperon is wrapped in `sandbox-exec.sh`, ensuring compute-node execution inherits sandbox restrictions.
6. **FIFO security**: Communication uses named pipes in a per-session temp directory with 700 permissions. Response FIFOs use unpredictable names (mktemp) and are validated against path traversal.
7. **Die-with-parent**: The chaperon sets `PR_SET_PDEATHSIG` and polls parent liveness every 5 seconds as a fallback.
8. **Handler dispatch validation**: Command names are validated against `^[a-z_][a-z0-9_]*$` to prevent path traversal in handler lookup.
9. **TOCTOU prevention**: Response FIFOs are opened to a held FD immediately after validation, and writes go through the FD (not the path).
10. **#SBATCH directive filtering**: `#SBATCH` directives are filtered against the flag whitelist — safe directives pass through, dangerous ones are stripped.
11. **Atomic request writes**: Request messages are built into a buffer and written atomically (single write for messages under PIPE_BUF, flock for larger ones).
12. **scancel scoping**: Job cancellation is restricted to jobs submitted by this session/project/user, preventing cancellation of other users' jobs.

## Testing

The test suite (`test.sh` sections 5–6) verifies:

- PATH shadowing resolves to chaperon stubs
- Munge socket is hidden/blocked inside sandbox
- Slurm binaries are blocked inside sandbox (bwrap/firejail)
- Slurm config is hidden inside sandbox (bwrap/firejail)
- `srun` prints helpful error suggesting `sbatch`
- `_CHAPERON_FIFO_DIR` is set inside sandbox
- Chaperon request FIFO exists inside sandbox
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

To block a command without proxying it (like srun), create a standalone stub that prints an error without sourcing `_stub_lib.sh`.

### Adding a new allowed sbatch flag

Add the flag to `_SBATCH_ALLOWED_FLAGS` in `handlers/_handler_lib.sh`. If it takes a value argument, also add it to `_SBATCH_VALUE_FLAGS`.

### Configuring scancel scope

Set `CHAPERON_SCANCEL_SCOPE` in `sandbox.conf`:

```bash
# Only cancel jobs submitted by this sandbox session (default)
CHAPERON_SCANCEL_SCOPE="session"

# Cancel jobs submitted by any sandbox with the same project dir
CHAPERON_SCANCEL_SCOPE="project"

# Cancel any chaperon-submitted job of the current user
CHAPERON_SCANCEL_SCOPE="user"
```

### Querying sandbox jobs

The `--comment` tag makes it easy to filter squeue from outside:

```bash
# All sandbox jobs for this user
squeue --me -o "%.18i %.9P %.8j %.2t %.10M %k" | grep chaperon:

# Jobs from a specific project
squeue --me -h -o "%i %k" | grep "proj=<hash>"
```
