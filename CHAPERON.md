# Chaperon: Secure Slurm Proxy for Sandboxed Sessions

## Problem

The previous Slurm isolation model exposed the munge authentication socket (`/run/munge`) read-only inside the sandbox, allowing the PATH-shadowing wrappers to authenticate with slurmctld. This meant anything inside the sandbox that could talk to munge — a crafted binary, Python ctypes, a direct `socat` call — could submit jobs without going through the sandbox wrappers. PATH shadowing was a speed bump, not a wall.

The chaperon replaces this with a **zero-trust architecture**: all Slurm authentication assets are blocked inside the sandbox, and a proxy process running *outside* the sandbox validates, wraps, and submits jobs on behalf of the sandboxed process.

## Architecture

```
sandbox-exec.sh
  │
  ├── python3 socketpair() → parent_fd, child_fd
  ├── fork chaperon (holds parent_fd, outside sandbox)
  ├── close parent_fd in child
  ├── close FDs 3+ EXCEPT child_fd
  ├── export _CHAPERON_FD=child_fd
  └── backend_exec → enters sandbox
        │
        └── Inside sandbox:
              - /run/munge BLOCKED (no munge auth)
              - /usr/bin/{sbatch,srun,...} BLOCKED
              - /etc/slurm/ BLOCKED
              - stub sbatch → writes to _CHAPERON_FD → chaperon validates,
                wraps in sandbox-exec.sh, calls real sbatch → returns result
              - stub srun → prints "use sbatch instead" → exits 1
```

### Component Roles

| Component | Location | Role |
|---|---|---|
| **chaperon.sh** | Outside sandbox | Main loop: reads requests, dispatches to handlers, writes responses |
| **protocol.sh** | Shared (both sides) | `CHAPERON/1` wire protocol: base64 encode/decode, message framing |
| **handlers/sbatch.sh** | Outside sandbox | Validates sbatch args, wraps job in sandbox-exec.sh, submits to real sbatch |
| **handlers/blocked.sh** | Outside sandbox | Returns "command not allowed" for unsupported Slurm commands |
| **handlers/_handler_lib.sh** | Outside sandbox | Argument whitelist, CWD validation, wrapper script generation |
| **stubs/sbatch** | Inside sandbox | Parses user's sbatch invocation, sends request over socketpair |
| **stubs/srun** | Inside sandbox | Standalone error — doesn't talk to chaperon |
| **stubs/_stub_lib.sh** | Inside sandbox | Stub-to-chaperon communication helpers |

## File Structure

```
chaperon/
├── chaperon.sh              # Main loop (runs OUTSIDE sandbox)
├── protocol.sh              # Read/write protocol messages (shared)
├── handlers/
│   ├── _handler_lib.sh      # Arg whitelisting, CWD validation, job wrapping
│   ├── sbatch.sh            # Validates, wraps, submits via real sbatch
│   └── blocked.sh           # Generic "blocked" response
└── stubs/
    ├── _stub_lib.sh          # Stub→chaperon communication
    ├── sbatch                # PATH-shadowing stub (talks to chaperon)
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

## Socketpair Design

The communication channel is a Unix socketpair created by Python's `socket.socketpair()` before the sandbox is entered. This is critical for security:

1. **No filesystem path**: unlike Unix domain sockets bound to a path, socketpairs exist only as file descriptors. There is no path to discover, connect to, or race against.
2. **Inherited across fork**: the parent FD goes to the chaperon process, the child FD passes into the sandbox via `_CHAPERON_FD`.
3. **FD closing exemption**: sandbox-exec.sh closes all FDs > 2 before entering the sandbox to prevent FD-based escape. The chaperon FD is explicitly exempted.
4. **EOF on death**: when either side dies, the other gets EOF. The chaperon exits cleanly on EOF (sandbox died); the stub gets a read error if the chaperon dies.

## Chaperon Lifecycle

1. **Creation**: `sandbox-exec.sh` creates the socketpair via Python, forks `chaperon.sh` as a background child, closes the parent FD in the child process, and exports `_CHAPERON_FD` for the sandbox.
2. **Orphan prevention**: The chaperon sets `PR_SET_PDEATHSIG` via Python/ctypes so it receives SIGTERM if its parent (sandbox-exec.sh) dies. This prevents orphaned chaperon processes.
3. **Signal handling**: SIGTERM and SIGINT are trapped for clean shutdown (FD cleanup).
4. **Main loop**: Reads requests via `chaperon_read_request()`, dispatches to the appropriate handler, captures stdout/stderr, and sends the response.
5. **Exit**: On EOF (socketpair closed) or signal, the chaperon closes its FD and exits 0.

## Handler Dispatch

Filesystem-based: when a request for command `X` arrives, the chaperon looks for `handlers/X.sh` and calls `handle_X()`. If no handler exists, `handlers/blocked.sh` is used.

This design makes it trivial to add support for new commands (drop a handler file) or block them (they're blocked by default).

### sbatch Handler

The sbatch handler (`handlers/sbatch.sh`) performs three validation steps before submission:

1. **Argument whitelisting**: Every flag is checked against `_SBATCH_ALLOWED_FLAGS` (~40 safe flags). Denied flags cause immediate rejection with a clear error message.
2. **CWD validation**: The requested working directory must be a physical path under the project directory (resolves symlinks to prevent escape).
3. **Job wrapping**: The user's script is written to a temp file, and a wrapper script is generated that runs it inside `sandbox-exec.sh --project-dir $PROJECT_DIR`. The wrapper is submitted to the real sbatch.

### scancel Handler

The scancel handler (`handlers/scancel.sh`) allows the sandbox to cancel Slurm jobs, scoped to prevent cancelling other users' or sessions' jobs:

1. **Argument whitelisting**: Only safe scancel flags are forwarded (`--name`, `--partition`, `--state`, `--signal`, etc.). Flags like `--user`, `--me`, `--account` are denied — scope is controlled by the chaperon, not by the user.
2. **Job ID validation**: All positional arguments must be numeric job IDs.
3. **Scope filtering**: Job IDs are checked against a tracking list before being passed to the real scancel.

#### scancel Scope Levels

Configured via `CHAPERON_SCANCEL_SCOPE` in `sandbox.conf`:

| Scope | Behavior | Tracking |
|---|---|---|
| `session` (default) | Only jobs submitted by THIS sandbox session | `$FIFO_DIR/jobs` (per-session temp) |
| `project` | Jobs submitted by ANY sandbox with the same project dir | `~/.claude/sandbox/chaperon-jobs-<hash>` |
| `user` | All jobs of the current user (no filtering) | None — equivalent to `scancel --me` |

Job IDs are recorded by the sbatch handler after each successful submission. For `session` scope, the tracking file is ephemeral (deleted with the FIFO directory when the sandbox exits). For `project` scope, the file persists across sessions.

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

Unknown flags (not in the whitelist) are also rejected.

## What Gets Blocked Inside the Sandbox

| Resource | bwrap | firejail | landlock |
|---|---|---|---|
| `/run/munge/` (auth socket) | Hidden (tmpfs /run, not re-mounted) | `--blacklist=/run/munge` | Not granted (EACCES) |
| `/usr/bin/{sbatch,srun,...}` | `--ro-bind /dev/null` | `--blacklist=` | Not blocked (known limitation) |
| `/etc/slurm/`, `/etc/slurm-llnl/` | `--tmpfs` | `--blacklist=` | Not blocked |
| Munge auth capability | **None** — can't auth without socket | **None** | **None** — EACCES on socket |

**Defense in depth**: Without the munge socket, even finding a Slurm binary (on Landlock where `/usr/bin` can't be blocked) is useless — authentication will fail. The chaperon is the only path to job submission.

## Comparison with Previous Architecture

| Aspect | Previous (PATH wrappers) | Chaperon |
|---|---|---|
| Munge socket | **Exposed** (read-only inside sandbox) | **Blocked** (not mounted/blacklisted) |
| Slurm binaries | **Relocated** (bwrap) or **available** (others) | **Blocked** (all backends) |
| Bypass via crafted binary | **Possible** (munge auth available) | **Impossible** (no munge, no binaries) |
| Bypass via `/usr/bin/sbatch` | **Possible** (firejail/landlock) | **Impossible** (blocked/blacklisted) |
| Argument injection | **Possible** (wrappers pass-through) | **Blocked** (whitelist rejects unknown flags) |
| Communication channel | PATH ordering (soft) | Socketpair (no filesystem path) |
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
10. **#SBATCH directive stripping**: All `#SBATCH` directives are stripped from user scripts, preventing whitelist bypass via embedded directives.
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
2. Create `chaperon/stubs/newcmd` that uses `_stub_lib.sh` to send the request
3. The chaperon's filesystem-based dispatch will automatically route requests

### Adding a new allowed sbatch flag

Add the flag to `_SBATCH_ALLOWED_FLAGS` in `handlers/_handler_lib.sh`. If it takes a value argument, also add it to `_SBATCH_VALUE_FLAGS`.

### Configuring scancel scope

Set `CHAPERON_SCANCEL_SCOPE` in `sandbox.conf`:

```bash
# Only cancel jobs submitted by this sandbox session (default)
CHAPERON_SCANCEL_SCOPE="session"

# Cancel jobs submitted by any sandbox with the same project dir
CHAPERON_SCANCEL_SCOPE="project"

# Cancel any job of the current user (no filtering)
CHAPERON_SCANCEL_SCOPE="user"
```
