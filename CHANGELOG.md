# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Chaperon `squeue` scope-filter info leak (within-user, cross-project).**
  The `squeue` handler injects the chaperon `--comment` tag into a
  user's `-o` format string and post-filters by scope, but the awk
  filter used a "first column starts with a digit" heuristic to tell
  header rows from data rows. With user formats like `-o "%j %i"` or
  `-o "%u %i"` (job-name or user first), every data row started with a
  letter and was treated as a header — passing through unfiltered. The
  result: a sandboxed agent could see jobs from sibling sandbox
  sessions and other projects of the same Linux user (cross-user is
  still blocked by Slurm's own auth via `--me`, but cross-project /
  cross-session within the user was open). Fixed by replacing the
  heuristic with an explicit header/data discriminator: `_noheader`
  is derived from `validated_flags` and passed into awk via
  `-v noheader=…`; when no header is expected (`-h`/`--noheader`),
  every line is filtered as data; otherwise the first line passes
  through as the header and the rest are filtered. The awk block was
  factored into a `_squeue_filter_scope` helper so it can be unit-
  tested directly. `test.sh §5o` covers numeric-first-with/without-
  header, non-numeric-first-with/without-header, a cross-project mix
  asserting only in-scope rows survive regardless of `-o` order, and
  the no-separator / empty-input edge cases. `chaperon/handlers/squeue.sh`,
  `test.sh`.

- **Chaperon response-FIFO TOCTOU (arbitrary file truncation).** The
  chaperon's response-write path validated `[[ -L $RESP_FIFO ]]` / `[[ -p
  $RESP_FIFO ]]` and then opened the path with bash's `>` redirection,
  which follows symlinks (`O_WRONLY|O_CREAT|O_TRUNC`). A same-UID
  process inside the sandbox could win the race between the check and
  the open by unlinking the stub-created FIFO and dropping in a
  symlink → `~/.bashrc`, `~/.ssh/authorized_keys`, `~/.profile`, etc.
  The chaperon (which runs outside the sandbox as the user) would
  truncate that target and write response-frame bytes into it,
  breaking `bash` startup / locking the user out of SSH /
  corrupting config files — a sandbox-escape of the "damage files
  outside the sandbox" variety. Fixed by moving the response write
  to a python3 helper that opens with `O_WRONLY | O_NOFOLLOW` (no
  `O_CREAT`, no `O_TRUNC`) and re-verifies via `fstat(S_ISFIFO)`,
  so no file outside the validated FIFO can be damaged under any
  race. The pre-open `-L`/`-p` check is kept as an early filter.
  `chaperon/chaperon.sh`.

- **scontrol show-job extra-arg scope bypass.** `scontrol show job
  <JOBID> <JOBID2> ...` is valid Slurm syntax, but the chaperon
  handler only scope-validated `REQ_ARGS[2]` before forwarding the
  full argv. A sandboxed agent could list one of its own jobs as
  the first ID and arbitrary other jobs after it, letting `scontrol`
  return details for out-of-scope jobs (info disclosure of
  partition/comment/node/SubmitLine for sibling projects or other
  sessions). Fixed by rejecting any non-flag positional arg after
  the first job ID. `chaperon/handlers/scontrol.sh`.

- **Seccomp defense-in-depth denylist.** The seccomp filter now
  also denies `bpf`, `mount`, `umount2`, `pivot_root`, `reboot`,
  `swapon`, `swapoff`, `personality`, `acct`, `quotactl`, and
  `kcmp` on both `x86_64` and `aarch64`. All of these were already
  capability-denied at the kernel level inside the sandbox (no
  `CAP_SYS_ADMIN`/`CAP_SYS_BOOT`/`CAP_SYS_PTRACE`/`CAP_SYS_RESOURCE`),
  but adding them to the seccomp blob means they fail at syscall
  dispatch rather than somewhere deeper in the kernel, and narrows
  the kernel attack surface reachable from inside the sandbox.
  New `## Seccomp Filter` section in `SECURITY.md` documents the
  core vs. defense-in-depth split plus the remaining allowed-but-
  risky syscalls (`ptrace`, `perf_event_open`, `process_vm_*`,
  `keyctl`, `unshare`, `setns`) and which kernel-layer mitigation
  still applies to each. `backends/generate-seccomp.py`,
  `backends/landlock-sandbox.py`, `SECURITY.md`, `README.md`,
  `ADMIN_INSTALL.md`.

- **Symlink-resolving enforcement of `DENIED_WRITABLE_PATHS`.**
  `EXTRA_WRITABLE_PATHS`, `HOME_WRITABLE`, and the project dir
  itself are now matched against the admin deny-list in both
  literal and `readlink -f`-resolved forms. This closes the
  bypass where e.g. `EXTRA_WRITABLE_PATHS+=("$HOME/myhack")` with
  `$HOME/myhack -> /etc` would slip past a
  `DENIED_WRITABLE_PATHS=("/etc")` policy — bwrap / firejail
  follow symlinks when bind-mounting, so the literal-string
  match was insufficient. New `test-admin.sh` T14a / T14b
  exercise the `EXTRA_WRITABLE_PATHS` and `HOME_WRITABLE`
  symlink-indirection paths. `sandbox-lib.sh`.

### Fixed

- **`test.sh --quick` passwd assertion was wrong-shape on LDAP hosts.**
  The bwrap branch compared `wc -l < /etc/passwd` host-vs-sandbox, but
  the sandbox's filtered passwd is built from `getent` (LDAP-resolved
  on the host) plus synthetic entries for `dotto`/`slurm`/`munge`/
  `nobody`, so it is naturally larger than the host's tiny local
  `/etc/passwd` on every LDAP-backed system — the comparison made the
  test fail unconditionally on Fred Hutch login nodes. Both bwrap and
  firejail branches now use `getent passwd | wc -l` on both sides and
  assert strict-less-than (`-lt`) so an equal-row outcome correctly
  flags as "no filtering happened" instead of silently passing.
  `test.sh`.

- **`test.sh` `sandbox()` helper timeout 15s → 30s + pre-warm.** The
  helper's `timeout 15` envelope was tighter than the chaperon's own
  30s response-read ceiling (`chaperon/protocol.sh:158`), so first-
  call cold paths (bwrap startup + chaperon spinup + audit-log NFS
  append) could trip the test's timer before the chaperon's own
  diagnostic fired — failure mode "test couldn't tell us what
  happened" instead of a clean error. Bumped to 30s, added a `rc=124`
  branch that surfaces "[sandbox helper: 30s timeout fired]" to
  stderr so future agents don't burn time on "command failed vs.
  envelope too tight", and pre-warmed the sandbox before the squeue
  check in `--quick` (the full path already gets warm-up for free via
  `_ensure_writable_home_dirs`). `test.sh`.

- **`sbatch script.sh arg1 arg2` now forwards script positionals.**
  The chaperon stub captured `SCRIPT_ARGS` (anything after the script
  file) but never forwarded them through the wire protocol, and the
  handler piped the script body to the interpreter via stdin — which
  gives the interpreter no `argv`. The result was that `$1`, `$@`,
  and `$#` were always empty inside a wrapped script, breaking
  parameter-driven workflows. Fixed end-to-end:
  - New `SCRIPT_ARG <b64>` line type in the wire protocol; decoded
    into `REQ_SCRIPT_ARGS`.
  - The stub serialises each captured `SCRIPT_ARGS` element as a
    `SCRIPT_ARG` line (`chaperon/stubs/_stub_lib.sh::chaperon_call`
    reads from `_CHAPERON_SCRIPT_ARGS`).
  - `handle_sbatch` passes `REQ_SCRIPT_ARGS` to
    `create_wrapped_script`, which now emits two wrapper shapes:
    shells (bash/sh/zsh/dash/ksh/ash, plain or via `/usr/bin/env`)
    use `interp -s -- arg1 arg2 …` to keep the existing pipe-via-
    stdin form; non-shells (python, perl, R, …) materialise the
    script body to a per-invocation tmpfs file inside the sandbox
    and exec it directly so `argv[0]` is the path and `argv[1:]`
    are the user's positionals.
  - New `test.sh` cases (6c-sexies) cover bash-shebang, python-
    shebang, no-args, and tricky args (spaces, `$dollar`, quotes).
  `chaperon/stubs/sbatch`, `chaperon/stubs/_stub_lib.sh`,
  `chaperon/protocol.sh`, `chaperon/handlers/sbatch.sh`,
  `chaperon/handlers/_handler_lib.sh`, `test.sh`.

- **`validate_project_dir` now accepts `${HOME}` and `~/` in
  `ALLOWED_PROJECT_PARENTS`.** Previously only the literal `$HOME`
  form was expanded, so admins who wrote `ALLOWED_PROJECT_PARENTS=(
  "${HOME}/projects")` or `("~/projects")` in `sandbox-admin.conf`
  got spurious "Project directory not under an allowed parent path"
  errors. All three forms are now expanded consistently — same
  behaviour the rest of the config loader already uses.
  `sandbox-lib.sh`.

## [0.4.2] - 2026-04-16

### Fixed

- **Spurious "exited with code 1" warnings from every config file.**
  The `_load_untrusted_config` subprocess ended with a single
  `declare -p VAR1 VAR2 ... 2>/dev/null` call covering every
  `_CONFIG_ARRAYS` / `_CONFIG_SCALARS` entry. `declare -p` returns
  exit code 1 when any listed variable is unset (the `2>/dev/null`
  silences the message but not the exit code), so any user or
  project config that did not explicitly set newer entries like
  `CHAPERON_LOG_LEVEL` / `CHAPERON_LOG_RETAIN_DAYS` triggered a
  false "using values it set before exiting" warning on every
  startup. The subprocess now captures the real source exit code
  and iterates `declare -p` per variable with `|| true` so unset
  vars no longer poison the result. Genuine config errors (`exit`
  inside a config, syntax errors, failing commands) still surface.
- **Missing `chaperon/logging.sh` in Homebrew install.** The
  `install-lib` Makefile target copied `chaperon/chaperon.sh`,
  `chaperon/protocol.sh`, and the `handlers/` / `stubs/` trees, but
  never installed `chaperon/logging.sh` (added in 0.4.0). As a
  result, every `brew install agent-sandbox` at 0.4.0 / 0.4.1
  shipped a broken chaperon: `chaperon.sh` died immediately at
  `source "$CHAPERON_DIR/logging.sh"`, and every proxied Slurm call
  (`sbatch`, `srun`, `squeue`, `scancel`, etc.) timed out with
  "chaperon is not responding". The Makefile now installs
  `logging.sh` alongside `protocol.sh`.

## [0.4.1] - 2026-04-16

### Added

- **`ENABLED_AGENTS` array** in `sandbox.conf` (default: `claude codex
  gemini`). Each enabled agent contributes its declared
  writable/readable/blocked paths to the sandbox surface from
  `agents/<name>/config.conf`, and only its `overlay.sh` runs.
  Disabled agents leave their config dirs invisible — so e.g. `~/.pi`
  or `~/.config/opencode` don't become writable for users who don't
  run those agents. Adding support for a new agent is now: drop in
  `agents/<name>/`, append the name to `ENABLED_AGENTS`. See "Adding
  support for a new agent" in the README.
- **`AGENT_BLOCKED_FILES` field** in agent `config.conf`. Each enabled
  agent's blocked files (typically the real `AGENTS.md` / `CLAUDE.md`
  so the sandbox-merged copy wins) are folded into `BLOCKED_FILES`
  automatically.
- **pi-mono agent profile** (`agents/pi/`) for the
  [pi coding agent](https://github.com/badlogic/pi-mono). Ships
  disabled by default; enable with `ENABLED_AGENTS+=("pi")` in
  `sandbox.conf`. Sets `PI_CODING_AGENT_DIR` so pi reads from the
  sandbox-merged config dir.

### Changed

- **Default `ENABLED_AGENTS` is now conservative:** only `claude`,
  `codex`, and `gemini` are enabled by default. `aider`, `opencode`,
  and `pi` ship as opt-in (uncomment the corresponding
  `ENABLED_AGENTS+=("name")` in sandbox.conf). Rationale: every
  enabled agent expands the sandbox writable surface, and dotdir
  names that could plausibly belong to unrelated user data should
  stay invisible until the user opts in. **Migration:** existing
  users with explicit `HOME_WRITABLE` entries for these agents (the
  pre-refactor `sandbox.conf` style) keep working unchanged. Users
  who relied on the implicit defaults need to add the relevant
  agents to `ENABLED_AGENTS` in their sandbox.conf to restore
  behavior.
- Per-agent entries (`.claude`, `.codex`, `.gemini`,
  `.config/opencode`, `.aider.conf.yml`, agent `AGENTS.md` blocks)
  no longer hardcoded in `sandbox.conf` defaults. They now come from
  each enabled agent's `config.conf` via the new `_apply_agent_profiles`
  loader. Existing user `sandbox.conf` files continue to work
  unchanged — explicit entries are merged, not replaced, by the
  agent-derived ones (idempotency check prevents duplicates).
- `AGENT_REQUIRED_WRITABLE_PATHS` / `AGENT_REQUIRED_READABLE_PATHS`
  in agent `config.conf` are now load-bearing (previously
  warning-only). When an agent is enabled, its declared paths are
  granted automatically.

### Fixed

- **Silent death on unavailable lmod modules:** when `SANDBOX_MODULES`
  was set but lmod was not installed (or a specified module did not
  exist), `_load_sandbox_modules` returned exit code 1. Under
  `set -e`, this killed `sandbox-exec.sh` immediately with no error
  message. Module loading is now best-effort: unavailable modules
  emit a warning to stderr and the sandbox continues to start
  normally.
- **OpenCode XDG dir drift:** newer OpenCode releases (1.x) `mkdir`
  four XDG directories on startup (`~/.config/opencode`,
  `~/.local/share/opencode`, `~/.cache/opencode`,
  `~/.local/state/opencode`) and write `auth.json` to the data dir,
  but only the first was previously writable in the sandbox. All four
  are now declared in the opencode profile and granted automatically
  when opencode is enabled.
- **Dead chaperon detection:** stubs now timeout the FIFO write after 5 s
  and report a clear error ("chaperon is not responding") instead of
  hanging indefinitely when the chaperon process has died. The response
  FIFO open uses O_RDWR to avoid a second blocking point.
- **Chaperon crash diagnostics:** stderr is redirected to
  `chaperon.err` in the FIFO directory (instead of `/dev/null`) so
  startup failures and `set -e` deaths leave a trace. An `ERR` trap
  in `chaperon.sh` logs the failing line number before exit.
- **Log fallback for nested sandboxes:** when the NFS log directory is
  unreachable (e.g., `$HOME` is tmpfs inside bwrap), `chaperon_log_init`
  falls back to writing logs in the FIFO directory. Nested chaperons
  now produce discoverable diagnostics instead of failing silently.
## [0.4.0] - 2026-04-15

### Added

- **Chaperon audit logging:** every proxied Slurm request is now logged to
  a per-session file at `~/.local/state/agent-sandbox/chaperon/`. Each log
  entry records the command, full arguments, working directory, and script
  size with shebang. Handler denials (`_sandbox_deny` / `_sandbox_warn`)
  are captured at WARN level, providing a persistent security audit trail.
  Configurable via `CHAPERON_LOG_LEVEL` (debug/info/warn/error, default
  info) and `CHAPERON_LOG_RETAIN_DAYS` (default 7) in `sandbox.conf`.
  Filenames include hostname for NFS-safe uniqueness across concurrent
  sandboxes on multiple machines. Logs are auto-pruned by age and a
  50 MiB total size cap. Script body content is intentionally not logged
  to prevent secret/credential exposure. Log files and directory are
  restricted to owner-only access (700/600).

## [0.3.3] - 2026-04-15

### Fixed

- **sbatch shebang ignored:** the chaperon wrapper always ran user scripts
  via `sh -c`, ignoring the script's `#!` line. Bash features (`source`,
  arrays, `[[ ]]`) failed silently and non-shell shebangs
  (`#!/usr/bin/env python3`) were completely ignored. The wrapper now
  extracts the interpreter from the shebang and pipes the script to it
  via stdin. Falls back to `/bin/sh` when no shebang is present,
  matching Slurm's default behavior.

- **sbatch CWD mismatch:** the chaperon's `sbatch` handler now `cd`s to
  the agent's working directory before calling real `sbatch`. Previously,
  Slurm inherited the chaperon's CWD, causing `SLURM_SUBMIT_DIR` to
  point to the wrong directory on compute nodes and relative
  `--output`/`--error` paths to resolve incorrectly. The `srun` handler
  already handled this correctly.

- **Clarify `home: tmpwrite` banner label:** the startup banner now
  expands each `HOME_ACCESS` mode into a descriptive label (e.g.,
  `home: tmpwrite (~ visible, writes to tmpfs — not persisted)`) to
  prevent agents from misinterpreting `tmpwrite` as an empty tmpfs.
  Added a HOME_ACCESS modes reference table to `agents/sandbox-help.md`.

### Changed

- **`lab` utility removed:** the JupyterLab management CLI (`bin/lab`,
  `bin/_lab_kernel.py`, `agents/lab.md`, `test-lab.sh`) has been extracted
  to its own project ([katosh/labsh](https://github.com/katosh/labsh)).
  All lab-specific references removed from agent instructions, README,
  and sandbox-help. The sandbox no longer ships or promotes any
  JupyterLab tooling.

## [0.3.2] - 2026-04-13

### Added

- **Lmod module loading:** new `SANDBOX_MODULES` config array loads
  user-specified lmod modules before backend detection, so
  module-provided binaries (e.g., a newer bubblewrap on HPC systems)
  appear on PATH automatically. The `module` command is sourced from
  common init locations if not already available.
- **AppArmor diagnostic:** when the bwrap smoke test fails, the sandbox
  now checks `kernel.apparmor_restrict_unprivileged_userns` and prints
  an actionable message pointing admins to install an AppArmor profile
  (Ubuntu 24.04+).

## [0.3.1] - 2026-04-13

### Fixed

- Makefile `install-lib` failed on some filesystems: `chmod -x` on
  `_handler_lib.sh` and `_stub_lib.sh` produced inconsistent permission
  bits. Now installs sourced library files with `644` directly instead
  of `755` + `chmod -x`.

## [0.3.0] - 2026-04-12

User-customizable agent files (`agent.md`, `settings.json`) now live in
`~/.config/agent-sandbox/agents/<name>/` instead of the install directory.
Config files auto-deploy on first run and auto-update on upgrade when
unmodified. A minimal `sandbox-admin.conf` skeleton replaces the full
config copy for admin installs, letting users control everything the
admin doesn't explicitly enforce.

### Changed

- **Auto-init on first run:** `sandbox.conf` and agent templates
  (`agent.md`, `settings.json`) are automatically deployed to
  `~/.config/agent-sandbox/` on first sandbox start. On upgrade,
  unmodified copies are silently updated; user-edited files are
  preserved with a message pointing to the new upstream version.
  Tracking uses `.origin-sha256` sidecar files. Force reset with
  `make install-conf FORCE=1`.
- **Admin config skeleton:** new `sandbox-admin.conf` contains only
  enforcement knobs (`DENIED_WRITABLE_PATHS`, `BLOCKED_*`,
  `ALLOWED_PROJECT_PARENTS`). Admins copy it over `sandbox.conf` in the
  install dir. Users always get the full documented config via
  `sandbox.conf.template`, independent of what the admin sets.
- Chaperon allows `--export` in sbatch/srun. The flag was previously
  blocked to prevent env var injection, but compute-node jobs run inside
  `sandbox-exec.sh` which filters env vars regardless.
- Agent credential warnings now fire only when the sandbox actively
  blocks credentials that are present, not when credentials are simply
  absent. Auth marker files suppress the warning.

### Fixed

- Firejail `HOME_ACCESS=read/write` no longer fails when agent config
  dirs are present (`--whitelist` triggered tmpfs HOME in these modes).
- Firejail `/dev/shm` POSIX shared memory writes no longer leak to host
  (`--blacklist=/dev/shm` added; `--tmpfs` is silently ignored on `/dev`).
- `--verbose` test output no longer dumps chaperon denial messages on
  every sandbox invocation (stderr captured in `OUTPUT_ERR`, shown only
  on failure).
- sbatch script file tests now create scripts in `PROJECT_DIR` instead
  of `/tmp` (invisible inside sandbox with `--private-tmp`).

### Documentation

- Admin install simplified: `sudo make install PREFIX=/app` replaces
  manual cp/chown steps. Dropped `install.sh (legacy)` from README.
- Updated overlay description to reflect subshell isolation.

### CI

- Credential fixture files (`.ssh`, `.aws`, `.gnupg`, `.netrc`, `.kube`,
  `.config/gcloud`, etc.) created in CI setup, eliminating ~10 skipped
  tests per backend.
- Cross-user Slurm job visibility test: CI creates `slurm-testuser`
  and verifies their jobs are invisible inside the sandbox.
- Composite action (`setup-sandbox-host`) added to firejail and landlock
  CI jobs (was only on bwrap).

## [0.2.0] - 2026-04-12

All sandbox permissions (readable/writable paths, blocked files, allowed
env vars) now live in the sandbox configuration layer — `sandbox.conf`
plus the admin config and per-project `conf.d/*.conf` overrides.
Per-agent profiles are strictly declarative; each `overlay.sh` runs in a
subshell so mutations to permission globals are structurally impossible.
Agent API keys are allowed by default so agents work out of the box.

### Security

- **Admin-bypass fix:** the old `_apply_agent_profiles` could remove
  admin-enforced entries from `BLOCKED_ENV_VARS` via
  `AGENT_UNBLOCK_ENV_VARS`. Agent overlays now run in subshells with
  outputs marshalled via a tagged-line stdout protocol, so mutations to
  permission globals (`BLOCKED_FILES`, `BLOCKED_ENV_VARS`,
  `BLOCKED_ENV_PATTERNS`, `ALLOWED_ENV_VARS`, `EXTRA_BLOCKED_PATHS`,
  `HOME_READONLY`, `HOME_WRITABLE`, `EXTRA_WRITABLE_PATHS`,
  `READONLY_MOUNTS`, `DENIED_WRITABLE_PATHS`) are structurally
  unrepresentable rather than caught after the fact.
- **Firejail /var/tmp write leak:** firejail's `--private-tmp` only
  isolates `/tmp`, leaving `/var/tmp` writable on the host. Added
  `--blacklist=/var/tmp` to match bwrap/landlock isolation.
- **Firejail /dev/shm write leak:** firejail's `--ipc-namespace` does
  not mount a private `/dev/shm`. Added `--blacklist=/dev/shm` so
  POSIX shared memory writes cannot leak to the host.

### Changed (breaking)

- Removed agent detection (`agents/*/detect.sh`, `_detect_agents`,
  `_DETECTED_AGENTS`). All `agents/*/` profiles are prepared on every
  sandbox start.
- `agents/*/config.conf` is now declarative metadata only:
  `AGENT_CREDENTIAL_ENV_VARS`, `AGENT_AUTH_MARKERS`,
  `AGENT_REQUIRED_WRITABLE_PATHS`, `AGENT_REQUIRED_READABLE_PATHS`,
  `AGENT_LOGIN_HINT`. The old keys
  (`AGENT_HOME_WRITABLE`, `AGENT_HOME_READONLY`, `AGENT_HIDE_FILES`,
  `AGENT_UNBLOCK_ENV_VARS`) are removed. Sites that maintain custom
  agent profiles must migrate permissions into `sandbox.conf`.
- Default `ALLOWED_ENV_VARS` now includes `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `CODEX_API_KEY`, `GOOGLE_API_KEY` so agents that
  use env-var auth work on first launch. Comment out entries to block.
- Agent auth directories (`~/.claude`, `~/.codex`, `~/.gemini`,
  `~/.config/opencode`) are now listed explicitly in `HOME_WRITABLE`.
- Agent instruction files (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`,
  `~/.gemini/GEMINI.md`, `~/.config/opencode/AGENTS.md`) are listed
  explicitly in `BLOCKED_FILES`.
- Chaperon now allows `--export` in sbatch/srun. The flag was
  previously blocked to prevent env var injection, but compute-node
  jobs run inside `sandbox-exec.sh` which filters env vars regardless.
- **sandbox-notify rewrite:** removed the chaperon notify relay
  (`chaperon/handlers/notify.sh`, `chaperon/stubs/notify`, FD-4
  plumbing). Notification now uses two native paths: direct `/dev/tty`
  bell for interactive shells, and `tmux new-window -d` IPC fallback
  for subprocesses without a controlling terminal. Relies on tmux's
  built-in `bell-action` propagation to the outer session.

### Added

- `SUPPRESS_AGENT_WARNINGS` config array — silence per-agent credential
  /path warnings. Accepts agent names or `"all"`.
- Startup warning when the sandbox actively blocks credentials the
  agent has set (env vars present but filtered). No longer warns about
  simply absent credentials. Auth markers suppress the warning.
- Auto-creation of missing `$HOME` `HOME_WRITABLE` directories so
  first-time in-sandbox auth persists across sessions.
- `_check_agent_requirements`, `_env_var_reachable`, `_path_is_writable`,
  `_path_is_readable`, `_ensure_writable_home_dirs` helpers.

### Fixed

- Built-in defaults in `sandbox-lib.sh` aligned with `sandbox.conf`:
  `ALLOWED_ENV_VARS`, `HOME_WRITABLE`, `HOME_READONLY`, and
  `BLOCKED_FILES` now carry the same entries as the shipped config so
  the sandbox works correctly even without a user config file.
- Firejail and landlock agent-config visibility: merged agent config
  dirs (e.g. `~/.claude/sandbox-config`) are now whitelisted/granted
  in both backends so `CLAUDE_CONFIG_DIR` is reachable inside the
  sandbox.
- `sandbox-notify` no longer errors when run without a controlling
  terminal (e.g. from agent hooks that redirect stdout).
- Firejail `HOME_ACCESS=read/write` no longer fails when agent config
  dirs are present (`--whitelist` triggered tmpfs HOME in these modes).
- Firejail `HOME_ACCESS=read/write` credential dirs (`.ssh`, `.aws`,
  `.gnupg`) properly hidden via `--blacklist`.

### CI

- Full test suite on all backends (was `--quick`); added live-Slurm
  job using `koesterlab/setup-slurm-action` with MySQL backend.
- Composite action (`setup-sandbox-host`) for bubblewrap install and
  AppArmor user-namespace sysctl on Ubuntu runners.
- Smoke job (syntax check + shellcheck) gates all backend test jobs.
- Outer tmux session started so socket-isolation tests run.
- JUnit XML output for structured CI reporting.

### Tests

- Test suite expanded from ~2400 to ~3600 lines (+50% coverage).
- CVE-grade escape probes: runc-style `/proc/1/root` traversal, cgroup
  `release_agent` write, NoNewPrivs enforcement.
- Chaperon: PDEATHSIG liveness, `SLURM_SCOPE=session`, `LD_PRELOAD`
  probe, sbatch flag rejection gaps, job-wrapping verification.
- Section 7 (self-protection) expanded to all tamperable sandbox
  surfaces.
- `ALLOWED_PROJECT_PARENTS` rejection, extra credential dirs,
  `AGENT_AUTH_MARKERS` validation.
- `sandbox_must_run` helper for deterministic setup; unified fixture
  cleanup on exit.
- Cross-user Slurm job visibility: CI creates a second OS user with a
  running job and verifies it is invisible inside the sandbox.

## [0.1.0] - 2026-04-11

Initial public release.

### Added

- Three kernel-enforced isolation backends: bubblewrap, firejail, landlock
- Chaperon: zero-trust Slurm proxy with per-handler argument validation
  - 16 request handlers (sbatch, srun, squeue, scancel, scontrol, sacct, etc.)
  - 21 PATH-shadowing stubs with FD-based proxy communication
  - CHAPERON/1 wire protocol (base64-encoded request/response framing)
  - Compute-node jobs inherit sandbox restrictions automatically
- Agent profiles with auto-detection: Claude Code, Codex, Gemini, Aider, OpenCode
  - Per-agent config merging (env vars, home paths, hidden files)
  - Agent-specific overlays (CLAUDE.md, settings.json, etc.)
- Credential hiding: ~/.ssh, ~/.aws, ~/.gnupg blocked by default
- Environment variable filtering with block/allow patterns
- Per-project config overrides (conf.d/*.conf)
- HOME_ACCESS modes: restricted, tmpwrite, read, write
- LDAP/AD user enumeration filtering (FILTER_PASSWD)
- Private /tmp and IPC namespace isolation
- Slurm job scoping (session, project, user)
- JupyterLab kernel CLI for stateful experimentation
- tmux session wrapper with notification support
- Comprehensive test suite (filesystem, credentials, chaperon, escapes, syscalls)
- Admin hardening test suite
- One-command installer with backend detection
- Makefile with PREFIX/DESTDIR support for standard Unix installation

### Documentation

- README with installation, configuration, and troubleshooting
- Chaperon architecture and security analysis (CHAPERON.md)
- Admin hardening guide (ADMIN_HARDENING.md)
- Apptainer/container comparison (APPTAINER_COMPARISON.md)
- Security policy (SECURITY.md)
