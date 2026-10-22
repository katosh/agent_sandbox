# Live reload

A config change normally reaches only **new** sessions. For a long-running agent session, restarting means losing its context. `agent-sandbox reload` applies the *mount-level* part of a config change to a **running bwrap** session, from the host, without restarting it.

```bash
agent-sandbox sessions                      # live sessions of this user on this host
agent-sandbox reload                        # the session of the current directory's project
agent-sandbox reload 3fa9c1d2               # by id (a unique prefix is enough)
agent-sandbox reload --project ~/work/proj  # by project directory
agent-sandbox reload --dry-run              # print the plan, change nothing
agent-sandbox reload --force-detach         # see "Revoking" below
```

`reload` with no argument refuses if more than one live session matches; name one.

## What it does

1. Re-runs the **same config load and validation as a launch** for that project (user config, `conf.d`, admin pins and harden-only narrowing, `DENIED_WRITABLE_PATHS`), in a child process, with the config environment the session was started with (`SANDBOX_CONF` and a `HOME_ACCESS` override are recorded). Other launch-time environment overrides (`PRIVATE_TMP`, `NETWORK_FILTER_MODE`, ...) are read from the shell you run `reload` in, so run it from a shell with the same overrides. Config warnings are printed.
2. Builds the desired mount set with the **same builder as the launch** and compares it with the mounts the session was started (or last reloaded) with.
3. Applies the difference from outside, through the helper the mount guard uses (`backends/mount-repair.py`, which enters the sandbox's user and mount namespaces; no privilege is needed because you own them):
    * **Additions**, in launch order: new writable binds first, then any protective overlay (read-only overlay, mask) that falls inside them. A new bind on a parent would hide mounts the session already has below it; those are re-created on top of it, and if one cannot be re-created the addition is refused.
    * **Removals** of a writable path are a revocation (see below).
4. Tells the running **mount guard** and **chaperon** to re-read their view (SIGUSR1; each re-reads a host-only file itself). The guard then guards the new set (new mounts are repaired if lost, revoked paths are expected read-only) and says so; the chaperon's list of writable paths follows.

Only paths the sandbox **can already see** can be added live (for example a directory under a path listed in `READONLY_MOUNTS`, or anywhere under `$HOME` with `HOME_ACCESS=read` or `write`). A path that is not visible at all, or a non-bind mount, needs a restart; `reload` says so and leaves the session as it was.

## Revoking write access

A writable path that left the config is remounted **read-only** (`MS_REMOUNT|MS_BIND|MS_RDONLY`). It is not detached. If processes have files open for writing through that mount the kernel refuses (`EBUSY`); `reload` reports `BUSY`, leaves the path **writable** and exits 3. Close the files and run `reload` again.

`--force-detach` detaches the mount instead (and puts a read-only overlay where possible). Be clear about what that does: a detach hides the path, but file descriptors that are **already open keep their write access**, and so do processes whose working directory is there. It is the right tool when you know nothing important holds the path, or when stopping *new* access matters more than the open handle. It does not take back what a running process already holds; only a restart does.

If a path is removed from the config but still lies under another writable path of the new config (for example `~/proj/sub` when `~/proj` is writable), its own bind is kept and reported.

## What cannot be reloaded

Reported as "needs restart", never applied:

* environment and process-level settings: `SANDBOX_ENV`, `PATH`, `ALLOWED_ENV_VARS` / `BLOCKED_ENV_*`, `DEVICES`, `PRIVATE_TMP`, `PRIVATE_IPC`, `FILTER_PASSWD`, network filter and mail-block mode, `ENABLED_AGENTS`, seeded files. No running process can pick up a changed environment;
* a protection that was **removed** from the config (a `BLOCKED_FILES` or `EXTRA_BLOCKED_PATHS` entry): it stays enforced until restart. Loosening is never done live;
* a mount whose kind changed in a way that is not an addition or a revocation;
* any change on the `landlock` or `firejail` backends: `reload` prints "not supported, restart" and exits non-zero. Landlock rules cannot be changed after the fact, and firejail's namespaces belong to root;
* a session started by a different agent-sandbox version than the one installed.

## Exit status

| Status | Meaning |
|---|---|
| `0` | applied, or nothing to do (also for `--dry-run`) |
| `1` | error; nothing was applied (no such session, ambiguous, unsupported backend, config did not load) |
| `2` | usage |
| `3` | applied partly: some change was refused, busy, or needs a restart |

## Security model

* **The trigger is host-only.** The sandbox has its own PID namespace, so nothing inside can signal the guard or the chaperon, and the session records live in `$XDG_RUNTIME_DIR/agent-sandbox/sessions/`, which does not exist inside (`/run` is a fresh tmpfs). Without `XDG_RUNTIME_DIR` they are kept in `${XDG_STATE_HOME:-~/.local/state}/agent-sandbox/sessions/` and the bwrap backend masks that directory with an empty tmpfs. The chaperon FIFO is never used: an agent cannot ask for a reload, and a request in it would be ignored.
* **A reload cannot widen what the config allows.** The desired set comes from the validated launch-time builder; admin pins and `DENIED_WRITABLE_PATHS` apply as at launch. A revocation only removes write access.
* **Records are data.** Every field of a session record is validated before use, a signal is sent only to a process whose pid, start time and parentage match the record, and the helper refuses to act unless the namespace is owned by your uid and is not the host's.
* **Only bwrap sessions are registered.** Only bwrap hides the registry from the agent; on landlock and firejail an agent with a writable `$HOME` could otherwise read and forge records.
* **The recorded `SANDBOX_CONF` is checked.** It is sourced as you, so `reload` refuses one that is not a file you own. Records are host-only, so the agent cannot change which file is named; a config file inside the project is trusted as it is at launch.
* **The registry stays hidden.** An addition that would cover the registry's mask (a writable ancestor of the registry directory) is refused.
* **The guard waits while a reload applies.** A marker (reloader pid and start time, ignored once that process is gone) pauses the guard's checks, so it cannot "repair" a revocation back to writable. `--force-detach` is refused for a path with protections mounted inside it, because a detach would drop those too.
* A session record is removed when the session ends; records of dead launchers are ignored and pruned by `sessions` and `reload`.

`MOUNT_GUARD=off` sessions can still be reloaded; the new mounts are simply not watched. With `MOUNT_GUARD_REBIND=false` the guard does not repair writable binds, new or old.
