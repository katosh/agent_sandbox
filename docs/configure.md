# Configuration

Every knob the sandbox honours, what it does, what it defaults to, whether an admin can lock it down, and a runnable example. Edit `~/.config/agent-sandbox/sandbox.conf` (deployed automatically on first run); changes take effect the next time you start a sandbox — no reinstall.

## How config is loaded

```
1. Defaults                                     (sandbox-lib.sh, hard-coded)
2. Admin baseline   /app/lib/agent-sandbox/sandbox.conf   (if present, root-owned)
3. User config      ~/.config/agent-sandbox/sandbox.conf  (or user.conf when admin baseline exists)
4. Per-project      ~/.config/agent-sandbox/conf.d/*.conf (sourced in lexical order)
```

Each layer adds to the previous. The admin layer (when present) is the **security baseline**: certain values land in the layer-2 snapshot and the user's layer-3/4 entries are merged on top such that the user can append but not remove. See [admin enforcement](#admin-enforcement-model) below for the exact rules.

User config is loaded in an isolated subprocess (no eval in the parent), then variable values are extracted via a three-layer-validated `declare -p` round-trip. Configs cannot mutate the sandbox via shell-level side effects — `set`, `trap DEBUG`, `IFS=`, exports, `eval` overrides, background jobs, etc. all stay inside the subprocess and are dropped. Unknown variable names produce a one-line warning at startup so stale config from older versions surfaces instead of silently breaking.

## Admin enforcement model

When `/app/lib/agent-sandbox/sandbox.conf` exists, it is sourced first as a trusted file, then snapshotted. The user's layer-3/4 config runs in the isolated subprocess described above, and after extraction the policy enforcer (`_enforce_admin_policy` in `sandbox-lib.sh`) merges per these rules:

**Enforced arrays** — admin entries are restored, user entries are appended on top. User cannot remove an admin entry; attempting it produces a `WARNING: removed admin-enforced X entry '…' — restored.` line on stderr.

| Array | Why locked down |
|---|---|
| `BLOCKED_FILES` | Admin can pin specific files (e.g. site-wide instruction files) hidden from agents. |
| `BLOCKED_ENV_VARS` | Site-wide env-var blocklist. |
| `BLOCKED_ENV_PATTERNS` | Site-wide credential-pattern globs. |
| `EXTRA_BLOCKED_PATHS` | Site-wide path blocklist (e.g. clinical data, regulated datasets). |
| `DEVICES_BLACKLIST` | Site-wide device-node blocklist (e.g. `/dev/pts` to refuse the kernel-<6.2 TIOCSTI workaround). |

**Enforced scalars** (security-critical booleans) — admin can set to `true` and the user cannot weaken to `false`. Attempting it produces `WARNING: weakened admin-enforced X=true → restored.` and the value is restored.

| Scalar | Effect when admin sets `true` |
|---|---|
| `PRIVATE_TMP` | `/tmp` isolated per sandbox (locked on). |
| `PRIVATE_IPC` | IPC namespace isolated per sandbox (locked on). |
| `FILTER_PASSWD` | LDAP/AD user enumeration filtered (locked on). |

**`HOME_READONLY` → `HOME_WRITABLE` escalation prevented** — if the admin lists an entry in `HOME_READONLY`, the user cannot move it to `HOME_WRITABLE`. The sandbox warns and reverts.

**`DENIED_WRITABLE_PATHS`** — admin-only deny-list (no user-side equivalent). Any user `EXTRA_WRITABLE_PATHS` or `HOME_WRITABLE` entry that resolves under a denied path is stripped with a warning. Symlinks are resolved on both sides so a writable path can't bypass the blocklist by pointing at a denied target.

Without an admin baseline, `~/.config/agent-sandbox/sandbox.conf` is the only config and there is no enforcement layer — the user's configuration is the effective policy in full. See [Admin Install](admin/install.md) for setting up an admin baseline.

## Variables index

| Variable | Type | Admin-enforced? | Default |
|---|---|---|---|
| [`ALLOWED_PROJECT_PARENTS`](#allowed_project_parents) | array | additive merge | `/fh/fast`, `/fh/scratch`, `$HOME` |
| [`READONLY_MOUNTS`](#readonly_mounts) | array | additive merge | system paths + `/app` |
| [`HOME_ACCESS`](#home_access) | scalar | no | `tmpwrite` |
| [`HOME_READONLY`](#home_readonly) | array | RO→WR escalation blocked | shell + tool defaults |
| [`HOME_WRITABLE`](#home_writable) | array | additive; admin RO entries can't move here; respects `DENIED_WRITABLE_PATHS` | `.cache/uv` + agent profile additions |
| [`HOME_SEEDED_FILES`](#home_seeded_files) | array | additive | `.gitconfig` |
| [`EXTRA_BLOCKED_PATHS`](#extra_blocked_paths) | array | **yes** (admin entries restored) | `()` |
| [`EXTRA_WRITABLE_PATHS`](#extra_writable_paths) | array | additive; respects `DENIED_WRITABLE_PATHS` | `()` |
| [`DENIED_WRITABLE_PATHS`](#denied_writable_paths) | array | **admin-only** | `()` |
| [`BLOCKED_FILES`](#blocked_files) | array | **yes** | `()` + per-agent additions |
| [`DEVICES`](#devices) | array | additive; vetoed by `DEVICES_BLACKLIST` | NVIDIA driver nodes |
| [`DEVICES_BLACKLIST`](#devices_blacklist) | array | **yes** | `/dev/{mem,kmem,port,pts,sd*,nvme*,loop*}` |
| [`BIND_DEV_PTS`](#bind_dev_pts-deprecated) | scalar | no (deprecated, kernel-aware shim) | `false` |
| [`BLOCKED_ENV_VARS`](#blocked_env_vars) | array | **yes** | service-credential names |
| [`BLOCKED_ENV_PATTERNS`](#blocked_env_patterns) | array | **yes** | `SSH_*`, `*_TOKEN`, `*_SECRET`, … |
| [`ALLOWED_ENV_VARS`](#allowed_env_vars) | array | additive | agent API-key names |
| [`SANDBOX_ENV`](#sandbox_env) | array | additive | `()` |
| [`SANDBOX_BACKEND`](#sandbox_backend) | scalar | no | `auto` (bwrap → firejail → landlock) |
| [`SANDBOX_PREFERRED_BACKENDS`](#sandbox_backend) | (set inline via `SANDBOX_BACKEND` only) | — | — |
| [`SANDBOX_MODULES`](#sandbox_modules) | array | additive | `()` |
| [`PRIVATE_TMP`](#private_tmp) | scalar | **harden-only** (admin `true` is sticky) | `true` |
| [`PRIVATE_IPC`](#private_ipc) | scalar | **harden-only** | `true` |
| [`FILTER_PASSWD`](#filter_passwd) | scalar | **harden-only** | `true` |
| [`SANDBOX_NPROC_LIMIT`](#sandbox_nproc_limit) | scalar | no | `""` (unlimited) |
| [`SANDBOX_QUIET`](#sandbox_quiet) | scalar | no | `false` |
| [`SLURM_SCOPE`](#slurm_scope) | scalar | no | `project` |
| [`CHAPERON_LOG_LEVEL`](#chaperon_log_level) | scalar | no | `info` |
| [`CHAPERON_LOG_RETAIN_DAYS`](#chaperon_log_retain_days) | scalar | no | `7` |
| [`ENABLED_AGENTS`](#enabled_agents) | array | additive | `claude`, `codex`, `gemini` |
| [`SUPPRESS_AGENT_WARNINGS`](#suppress_agent_warnings) | array | additive | `()` |

---

## Project & home

### `ALLOWED_PROJECT_PARENTS`

**Type** array · **Admin-enforced** additive merge · **Default** `("/fh/fast" "/fh/scratch" "$HOME")`

The sandbox grants write access to exactly one directory — the **project dir**, set with `--project-dir` or defaulting to `$PWD`. For safety, that path must resolve under one of the entries listed here. A project dir outside this set is rejected at sandbox start.

Set this to the parents under which projects live on your system. On non-Fred-Hutch hosts the defaults can be replaced (`+=` to append, plain `=` to replace).

```bash
ALLOWED_PROJECT_PARENTS=(
    "$HOME"
    "/data/myorg"
    "/scratch/myorg"
)
```

### `HOME_ACCESS`

**Type** scalar · **Admin-enforced** no · **Default** `tmpwrite`

Controls how much of `$HOME` the agent sees and whether unlisted writes persist. Override per-session via `HOME_ACCESS=read agent-sandbox bash`.

| Mode | Real files visible? | Agent can write? | Writes persist? | Use case |
|---|---|---|---|---|
| `tmpwrite` (default) | Only listed paths | Anywhere in `$HOME` | **No** — lost on exit | Recommended. Agents create lock files, caches, temp dirs without errors; nothing leaks. |
| `restricted` | Only listed paths | Only `HOME_WRITABLE` + project | Yes | Maximum lockdown. Unlisted writes return `EROFS`. |
| `read` | Everything | Only `HOME_WRITABLE` + project | Yes | Agent needs to read arbitrary dotfiles or configs. |
| `write` | Everything | Everything | Yes | Full access — use with caution. |

Credential dirs (`.ssh`, `.aws`, `.gnupg`) are always blocked, regardless of mode.

### `HOME_READONLY`

**Type** array · **Admin-enforced** RO→WR escalation blocked · **Default** shell + tool config dotfiles (`.bashrc`, `.zshrc`, `.vimrc`, `.tmux.conf`, `.linuxbrew`, `.local/bin`, `micromamba`, `.condarc`, …)

Subdirectories and files of `$HOME` to mount **read-only** inside the sandbox. Each entry is `$HOME`-relative (no leading `/`). Missing entries are silently skipped, so listing dotfiles you might not have is safe.

Per-agent read-only entries (e.g. `.aider.conf.yml`) are folded in automatically from each enabled agent profile — see [`ENABLED_AGENTS`](#enabled_agents).

```bash
HOME_READONLY+=(
    ".config/gh"        # GitHub CLI config (also add GITHUB_TOKEN to ALLOWED_ENV_VARS)
    ".config/nvim"      # neovim config
)
```

### `HOME_WRITABLE`

**Type** array · **Admin-enforced** additive; admin `HOME_READONLY` entries cannot move here; respects `DENIED_WRITABLE_PATHS` · **Default** `(.cache/uv)` + per-agent additions from enabled profiles

Subdirectories and files of `$HOME` with **read+write** access. Missing entries are auto-created as empty dirs before the sandbox launches, so first-time in-sandbox auth works for agents.

If the admin baseline lists an entry in `HOME_READONLY`, the user cannot promote it to `HOME_WRITABLE` — the sandbox warns and reverts.

```bash
HOME_WRITABLE+=(
    ".cache"
    ".my_tool_state"
)
```

### `HOME_SEEDED_FILES`

**Type** array · **Admin-enforced** additive · **Default** `(.gitconfig)`

Files whose **content** is read from the host but materialised into the per-session tmpfs `$HOME` as a writable copy. The agent can edit them without touching the real host file — writes land in the tmpfs and are discarded on sandbox exit. Use this for dotfiles tools want to write but you don't want the agent to mutate persistently (`gh auth setup-git` rewriting `.gitconfig`, IDE git plugins, package-manager telemetry).

**Conflict rule:** an entry in `HOME_SEEDED_FILES` wins over the same entry in `HOME_READONLY` (the read-only mount is skipped).

**Backend support:**

- bwrap — full support via `--file FD DEST` (writable tmpfs copy).
- firejail — degrades to read-only with a startup warning.
- Landlock — degrades to read-only with a startup warning (no mount namespace).

```bash
HOME_SEEDED_FILES=(
    ".gitconfig"
    ".npmrc"
    ".yarnrc"
)
```

---

## Mounts

### `READONLY_MOUNTS`

**Type** array · **Admin-enforced** additive merge · **Default** `("/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc" "/app")`

Directories the agent can **read** but never write. The system paths are required for basic functionality (the sandbox warns if they are missing on the host). Add data directories the agent needs to read.

The agent cannot access anything not listed here, so apply the principle of least privilege: mount only what the task needs. Mounting an entire lab share is convenient but exposes everything under it.

```bash
READONLY_MOUNTS+=(
    "/fh/fast/mylab/user/me"            # just your user dir — recommended
    "/fh/fast/shared/reference_genomes" # site-wide reference data
)
```

### `EXTRA_WRITABLE_PATHS`

**Type** array · **Admin-enforced** additive; entries under `DENIED_WRITABLE_PATHS` are stripped with a warning · **Default** `()`

Directories the agent can **read and write** in addition to the project directory. Use for shared output directories, pipeline scratch space, or other locations the agent must modify but that aren't the project dir. Each entry expands the agent's write surface — only add directories the agent genuinely needs.

```bash
EXTRA_WRITABLE_PATHS=(
    "/fh/scratch/delete30/mylab/agent-output"
)
```

### `DENIED_WRITABLE_PATHS`

**Type** array · **Admin-enforced** **admin-only** (no user-side counterpart; the variable is editable in user config but only the admin snapshot is honoured) · **Default** `()`

Paths that must **never** be writable, regardless of user config. After the user/project layers are merged, any `EXTRA_WRITABLE_PATHS` or `HOME_WRITABLE` entry that resolves under a denied path is stripped with a warning. Both literal strings and resolved symlink targets are checked, so a writable entry pointing a symlink at a denied target is rejected.

Set this in the admin baseline only; user-set values do not survive admin enforcement.

```bash
# /app/lib/agent-sandbox/sandbox.conf (admin)
DENIED_WRITABLE_PATHS=(
    "/etc"
    "/usr"
    "/fh/fast/restricted_clinical"
)
```

### `EXTRA_BLOCKED_PATHS`

**Type** array · **Admin-enforced** **yes** · **Default** `()`

Paths **outside** `$HOME` that should be hidden inside the sandbox. Each path is overlaid with an empty tmpfs (bwrap/firejail) — the path appears to exist but resolves to an empty directory. Use to carve sensitive subdirectories out of otherwise-visible mounts (e.g. clinical data under a lab storage path).

```bash
EXTRA_BLOCKED_PATHS=(
    "/fh/fast/setty_m/restricted_clinical_data"
)
```

### `BLOCKED_FILES`

**Type** array · **Admin-enforced** **yes** · **Default** `()` (per-agent instruction files added automatically)

Specific **files** inside readable or writable directories that should be hidden. Each file is overlaid with `/dev/null` — it appears to exist but is empty. Useful when a parent directory must be accessible but a specific file within it should be protected.

Per-agent instruction files (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, etc.) are added automatically by `_apply_agent_profiles` from each enabled agent's `config.conf`. The agent's overlay then exports a `*_CONFIG_DIR` env var so the agent reads the sandbox-merged copy instead — see `agents/<name>/config.conf` for the schema.

**Backend limitation:** only respected by bwrap and firejail. Landlock cannot block individual files under directories it has already granted access to (no mount namespace, no overlays).

```bash
BLOCKED_FILES+=(
    "$HOME/notes/secret.md"
)
```

---

## Devices

### `DEVICES`

**Type** array · **Admin-enforced** additive; vetoed by `DEVICES_BLACKLIST` · **Default**

```bash
DEVICES=(
    /dev/nvidia*
    /dev/nvidia-uvm
    /dev/nvidia-uvm-tools
    /dev/nvidia-modeset
    /dev/nvidiactl
)
```

Device nodes to expose inside the sandbox. **bwrap only** — firejail and Landlock have their own device-handling models. Each entry is bind-mounted via `bwrap --dev-bind PATH PATH` after `bwrap --dev /dev` has set up the minimal devtmpfs.

Glob patterns are expanded against the host `/dev` at sandbox spawn time; entries that match nothing are silently dropped (so the NVIDIA defaults are a safe no-op on CPU-only nodes). After expansion, `DEVICES_BLACKLIST` is enforced — any resolved path matching a blacklist glob is dropped with a stderr notice.

The defaults expose the recurring HPC use case (NVIDIA driver nodes). Extend for AMD/Intel/sound/DRI/etc. as your workload requires:

```bash
DEVICES+=(/dev/snd /dev/dri/* /dev/kvm)
```

To replace defaults entirely (uncommon):

```bash
DEVICES=(/dev/something-specific)
```

See [Device Passthrough](reference/device-passthrough.md) for the full design rationale and per-backend behaviour.

### `DEVICES_BLACKLIST`

**Type** array · **Admin-enforced** **yes** · **Default**

```bash
DEVICES_BLACKLIST=(
    /dev/mem        # direct kernel-memory access
    /dev/kmem
    /dev/port
    /dev/pts        # TIOCSTI keystroke injection on kernel < 6.2; also
                    # shadows bwrap's auto-mounted user-ns devpts on >= 5.4
    /dev/sd*        # raw block devices — filesystem bypass
    /dev/nvme*
    /dev/loop*
)
```

Devices that **must not** be bind-mounted, regardless of `DEVICES`. Admin baselines lock this in: users add but cannot remove admin-set entries. Without an admin install these defaults are the safety baseline.

To extend:

```bash
DEVICES_BLACKLIST+=(/dev/fuse)
```

### `BIND_DEV_PTS` (deprecated)

**Type** scalar · **Admin-enforced** no (deprecated, kernel-aware shim) · **Default** `false`

Historical knob: when `true`, bound the entire host `/dev` into the sandbox. Replaced by `DEVICES`. For backward compatibility `BIND_DEV_PTS=true` is shimmed at config-load time:

- On kernel < 5.4 it appends `/dev/pts` to `DEVICES` (the historical pty workaround — `tmux` needs the host devpts because bwrap's user-ns devpts on those kernels reports `ptmxmode=000`).
- On kernel ≥ 5.4 it is a logged no-op. bwrap auto-mounts a working user-ns devpts on those kernels, and binding the host `/dev/pts` on top would shadow it with `ptmxmode=000` and silently break pty allocation (`tmux` exits "create session failed"; `script(1)` reports "Permission denied").

**Migration:** drop the line. On kernel ≥ 5.4 you do not need it; on kernel < 5.4 bwrap's auto-devpts is fine for pty in most cases. Only add `DEVICES+=(/dev/pts)` if you're on a pre-5.4 kernel and `tmux` fails inside the sandbox without it; expect the TIOCSTI security caveat (kernel < 6.2) in return.

---

## Environment

### `BLOCKED_ENV_VARS`

**Type** array · **Admin-enforced** **yes** · **Default** service-credential names not caught by `BLOCKED_ENV_PATTERNS` (e.g. `GITHUB_PAT`, `AWS_ACCESS_KEY_ID`, `DATABASE_URL`, `PGPASSWORD`, `KRB5CCNAME`, `TMUX`, `OLDPWD`, …)

Explicit env-var names to strip from the sandbox environment. Names like `GITHUB_TOKEN`, `OPENAI_API_KEY`, `AWS_SESSION_TOKEN`, `SSH_*` etc. are already matched by [`BLOCKED_ENV_PATTERNS`](#blocked_env_patterns) globs and don't need duplicating here. Use this for credentials with non-standard names (no `_TOKEN` / `_SECRET` / `_KEY` suffix).

To audit your environment for entries that might slip through both sets:

```bash
env | grep -iE 'token|key|secret|pat|auth'
```

### `BLOCKED_ENV_PATTERNS`

**Type** array · **Admin-enforced** **yes** · **Default**

```bash
BLOCKED_ENV_PATTERNS=(
    "SSH_*"
    "*_TOKEN"  "*_SECRET"  "*_PASSWORD"  "*_CREDENTIAL"
    "*_API_KEY"  "*_SECRET_KEY"  "*_PRIVATE_KEY"
    "AZURE_*"  "GCP_*"  "GCLOUD_*"  "GOOGLE_CLOUD_*"
    "DOCKER_*"  "REGISTRY_*"
    "CI_*"  "GITLAB_*"  "JENKINS_*"  "BUILDKITE_*"  "CIRCLECI_*"
)
```

Glob patterns that block any matching env var. Patterns catch the common credential conventions automatically. Use [`ALLOWED_ENV_VARS`](#allowed_env_vars) to exempt a specific variable matched by these patterns.

The startup banner (unless [`SANDBOX_QUIET=true`](#sandbox_quiet)) reports how many env vars were blocked by pattern, so missing vars are diagnosable without leaking the names of credentials.

### `ALLOWED_ENV_VARS`

**Type** array · **Admin-enforced** additive · **Default** `("ANTHROPIC_API_KEY" "OPENAI_API_KEY" "CODEX_API_KEY" "GOOGLE_API_KEY")`

Variables listed here are **never** blocked, even if they appear in `BLOCKED_ENV_VARS` or match a `BLOCKED_ENV_PATTERNS` glob. The agent-API-key defaults are enabled so agents that use env-var auth (Codex, Aider, OpenCode, Gemini) work on first launch. Comment out any line to block that variable instead.

```bash
ALLOWED_ENV_VARS+=(
    "GITHUB_TOKEN"     # for `gh` CLI inside the sandbox
    "MY_APP_API_KEY"   # site-specific
)
```

### `SANDBOX_ENV`

**Type** array of `KEY=VALUE` strings · **Admin-enforced** additive · **Default** `()`

Per-project environment variables applied to the host environment **before** the backend runs, so backend `PATH` prepends (chaperon stubs, sandbox bin) layer on top naturally. Set in `conf.d/*.conf` files guarded by `_PROJECT_DIR` so they only fire for the matching project.

```bash
# conf.d/genomics.conf
[[ "$_PROJECT_DIR" == /fh/fast/mylab/genomics/* ]] || return 0
SANDBOX_ENV+=(
    "PATH=/fh/fast/mylab/genomics/bin:${PATH}"
    "MY_PIPELINE_REF=/fh/fast/shared/reference_genomes/hg38"
)
```

---

## Backend & isolation

### `SANDBOX_BACKEND`

**Type** scalar · **Admin-enforced** no · **Default** auto (priority `bwrap → firejail → landlock`)

Which isolation backend to use. Overridable by `--backend bwrap` on the command line or by exporting `SANDBOX_BACKEND` in the environment — both override config-file values, since explicit selection should win over config defaults.

| Value | Backend | Notes |
|---|---|---|
| `auto` (or empty) | best available | bwrap → firejail → landlock |
| `bwrap` | Bubblewrap | primary, recommended dependency |
| `firejail` | Firejail | fallback (setuid root) |
| `landlock` | Landlock LSM | fallback (kernel ≥ 5.13, no mount/PID namespaces; documented gaps) |

```bash
SANDBOX_BACKEND="bwrap"          # force bwrap; fail if unavailable
```

### `SANDBOX_MODULES`

**Type** array · **Admin-enforced** additive · **Default** `()`

Lmod modules to load before backend detection. Use this on HPC systems where sandbox dependencies (e.g. a newer bubblewrap) are only available via `module load`. The sandbox sources lmod init from common locations (`/etc/profile.d/lmod.sh`, `/usr/share/lmod/lmod/init/sh`, `/app/lmod/lmod/init/sh`) if `module` isn't already on PATH.

```bash
SANDBOX_MODULES=("bubblewrap/0.11.1-GCCcore-12.3.0")
```

### `PRIVATE_TMP`

**Type** scalar · **Admin-enforced** **harden-only** (admin `true` is sticky) · **Default** `true`

Isolate `/tmp` with a private tmpfs. Each sandbox gets its own `/tmp`. Set to `false` if the sandboxed process needs shared `/tmp` access — MPI shared-memory transport (OpenMPI, MVAPICH) and NCCL inter-GPU sockets put files there.

**Backend support:** bwrap (`--tmpfs /tmp`) and firejail (`--private-tmp`). Landlock has no mount namespace — the value is honoured at config level but `/tmp` is not actually isolated; the docs site's [Known Limitations table](reference/security.md#known-limitations) lists this as a Landlock gap.

### `PRIVATE_IPC`

**Type** scalar · **Admin-enforced** **harden-only** · **Default** `true`

Isolate the SysV IPC namespace and `/dev/shm`. Each sandbox gets its own IPC namespace, preventing the agent from reading or corrupting shared memory of processes outside the sandbox. MPI/NCCL within a single Slurm job are unaffected — all ranks share one sandbox.

**Backend support:** bwrap (`--unshare-ipc` + private `/dev/shm` tmpfs) and firejail (`--ipc-namespace`). Landlock cannot isolate IPC.

### `FILTER_PASSWD`

**Type** scalar · **Admin-enforced** **harden-only** · **Default** `true`

Generate a minimal `/etc/passwd` (system UIDs < 1000 + the current user) and override `/etc/nsswitch.conf` to use `files` only (no `ldap`/`sss`). Prevents LDAP/AD user enumeration via `getent passwd`, `finger`, etc. — `getent passwd` returns ~35 entries instead of every user on the directory.

**Backend support:**

- bwrap — overlays `/etc/passwd` + `/etc/nsswitch.conf` via `--ro-bind`.
- firejail — blocks NSS daemon sockets (`nscd`, `nslcd`, `sssd`).
- Landlock — not supported (no mount namespace; user enumeration succeeds).

Munge, Slurm, and normal user/group resolution are unaffected. Set `false` if the sandboxed process needs LDAP user lookups (rare).

> On bwrap, `id` shows supplementary groups as `nogroup` (65534) regardless of this setting. Cosmetic only — the kernel uses host credentials for filesystem access, so file permissions still work correctly.

### `SANDBOX_NPROC_LIMIT`

**Type** scalar (integer or empty) · **Admin-enforced** no · **Default** `""` (no limit)

Defense-in-depth against fork bombs. Caps the total processes the sandbox user can run via `RLIMIT_NPROC` (`ulimit -u` for bwrap/Landlock, `firejail --rlimit-nproc` for firejail). Note that `RLIMIT_NPROC` counts per-UID **system-wide**, not per-sandbox — a fork bomb inside the sandbox can fill the per-UID limit and kill the user's shells/editors outside the sandbox. Admin cgroups with `pids.max` are the primary defense; this is supplemental.

```bash
SANDBOX_NPROC_LIMIT="4096"
```

### `SANDBOX_QUIET`

**Type** scalar · **Admin-enforced** no · **Default** `false`

Suppress the one-line startup banner that shows backend, project dir, and home-access mode, plus the count of env vars blocked by pattern. Useful inside scripts and CI where the banner is noise.

---

## Slurm

### `SLURM_SCOPE`

**Type** scalar · **Admin-enforced** no · **Default** `project`

Which jobs the chaperon-proxied `squeue`, `scancel`, `scontrol`, and `sstat` can see and operate on. The proxy filters output and validates targets against the configured scope.

| Value | What's visible / cancellable |
|---|---|
| `session` | Only jobs submitted by **this** sandbox session (one shell). |
| `project` (default) | Jobs from any sandbox session with the **same project dir** — survives reconnects, multi-window workflows. |
| `user` | All of the calling user's jobs, including non-sandbox ones. |
| `none` | No restriction (full access to your own jobs — `squeue --me` semantics). |

`sacct` is always scoped to the current user (`--user=$(whoami)` injected by the chaperon); `--allusers` and cross-user `--user=...` are denied with an actionable hint. `sacctmgr` user/account enumeration is denied entirely.

Override per-session via env: `SLURM_SCOPE=session agent-sandbox claude`.

### `CHAPERON_LOG_LEVEL`

**Type** scalar · **Admin-enforced** no · **Default** `info`

Verbosity of the chaperon's per-session log file (one file per sandbox session at `~/.local/state/agent-sandbox/chaperon/<hostname>_<PID>_<timestamp>.log`).

| Level | What lands in the log |
|---|---|
| `debug` | All requests, full handler exit codes, protocol details (script content captured). |
| `info` (default) | Startup, shutdown, each request, non-zero handler exits. |
| `warn` | Timeouts, validation failures, non-zero handler exits. |
| `error` | Only security rejections and hard failures. |

### `CHAPERON_LOG_RETAIN_DAYS`

**Type** scalar (integer) · **Admin-enforced** no · **Default** `7`

How many days of chaperon logs to keep. Older logs are pruned at each chaperon startup. A total size cap of 50 MiB is also enforced (oldest-first deletion when exceeded). Filenames include the hostname for NFS-safe uniqueness across machines.

---

## Agent profiles

### `ENABLED_AGENTS`

**Type** array · **Admin-enforced** additive · **Default** `("claude" "codex" "gemini")`

Names of agent profiles in `agents/<name>/` to enable. Each enabled agent contributes:

- Writable paths (e.g. `~/.claude`, `~/.codex`) folded into `HOME_WRITABLE`.
- Read-only paths folded into `HOME_READONLY`.
- Per-agent instruction files folded into `BLOCKED_FILES` (the overlay then exports a `*_CONFIG_DIR` env var pointing at the sandbox-merged copy).

Disabled agents contribute **nothing** — their config dirs stay invisible inside the sandbox. Enable only the agents you actually use, so `~/.pi` or `~/.config/opencode` (which could be unrelated user data) doesn't become writable for users who don't run those agents.

Built-in profiles: `claude`, `codex`, `gemini` (default-enabled), `aider`, `opencode`, `pi` (opt-in).

```bash
ENABLED_AGENTS+=("aider")              # add to defaults
ENABLED_AGENTS=("claude")              # solo-claude profile
```

Adding support for a new tool: drop in `agents/<name>/{config.conf,overlay.sh,agent.md}`, then add `"<name>"` to this list. See `agents/claude/config.conf` for the schema.

### `SUPPRESS_AGENT_WARNINGS`

**Type** array · **Admin-enforced** additive · **Default** `()`

Silence per-agent credential/path warnings emitted at startup. The sandbox checks each enabled agent profile and warns if the declared credentials/paths look unreachable (missing env vars **and** no writable auth directory). Useful when you intentionally isolate an agent (e.g. dropped `~/.claude` from `HOME_WRITABLE` to force a fresh login each session).

```bash
SUPPRESS_AGENT_WARNINGS=("claude")     # silence Claude only
SUPPRESS_AGENT_WARNINGS=("all")        # silence every agent
```

---

## Per-project overrides (`conf.d/`)

Different projects often need different data access. Drop files in `~/.config/agent-sandbox/conf.d/*.conf` to add mounts only when the project directory matches. Each file is sourced in lexical order **after** `sandbox.conf`, so use `+=` to append to the global arrays.

```bash
# conf.d/genomics.conf
[[ "$_PROJECT_DIR" == /fh/fast/mylab/genomics/* ]] || return 0

READONLY_MOUNTS+=(
    "/fh/fast/shared/reference_genomes"
)
EXTRA_WRITABLE_PATHS+=(
    "/fh/scratch/delete30/mylab/pipeline-output"
)
SANDBOX_ENV+=(
    "MY_PIPELINE_REF=/fh/fast/shared/reference_genomes/hg38"
)
```

The `_PROJECT_DIR` variable is set by the sandbox before sourcing conf.d files. Returning early when the project doesn't match keeps the file a no-op for unrelated projects.

See `conf.d/example.conf` in the install for a template.

---

## Common customizations

```bash
# Add a read-only data directory
READONLY_MOUNTS+=("/shared/other_lab/data")

# Add a writable output directory beyond the project dir
EXTRA_WRITABLE_PATHS=("/shared/scratch/agent-output")

# Block a sensitive subdirectory inside an otherwise-visible mount
EXTRA_BLOCKED_PATHS=("/shared/lab/clinical_restricted")

# Allow GitHub CLI inside the sandbox
HOME_READONLY+=(".config/gh")
ALLOWED_ENV_VARS+=("GITHUB_TOKEN" "GH_TOKEN")

# Open an extra device (audio + DRI render nodes)
DEVICES+=(/dev/snd /dev/dri/*)
```

> **SSH keys.** `~/.ssh` is excluded from `HOME_READONLY` by default — the agent cannot see it. **Do not add it.** On HPC clusters with passwordless SSH between nodes, an agent with access to `~/.ssh` can SSH to localhost for an unsandboxed shell. If the agent needs git access, prefer [deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) scoped to a single repo, or HTTPS with a fine-grained token (add the token var to `ALLOWED_ENV_VARS`).

### Claude Code permissions (`settings.json`)

For Claude Code, the sandbox overlays `~/.claude/settings.json` to auto-allow tools (`Bash`, `Read`, `Edit`, `Write`, `Glob`, `Grep`, `NotebookEdit`) that are already restricted by the kernel-enforced filesystem isolation. Your existing rules (including `deny`) are preserved. Customise via `~/.config/agent-sandbox/agents/claude/settings.json`.

---

## Cross-references

- [Admin install layout & config hierarchy](admin/install.md) — where the admin baseline lives, who can write it, how it's protected.
- [Device passthrough rationale](reference/device-passthrough.md) — full design of `DEVICES` / `DEVICES_BLACKLIST` and the `BIND_DEV_PTS` deprecation.
- [Chaperon protocol](reference/chaperon.md) — exactly what each Slurm stub allows and denies, with examples.
- [Architecture reference](reference/architecture.md) — per-resource isolation matrix across backends.
- [Sandbox config guide for in-sandbox agents](admin/sandbox-help.md) — the same content from the agent's perspective (the file an agent reads from inside the sandbox to know how to ask the user for permission grants).
