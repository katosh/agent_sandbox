# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-04-11

All sandbox permissions (readable/writable paths, blocked files, allowed
env vars) now live in `sandbox.conf` — a single auditable file. Per-agent
profiles are strictly declarative; a guardrail aborts sandbox start if an
agent's `overlay.sh` mutates any permission global. Agent API keys are
allowed by default so agents work out of the box.

### Security

- **Admin-bypass fix:** the old `_apply_agent_profiles` could remove
  admin-enforced entries from `BLOCKED_ENV_VARS` via
  `AGENT_UNBLOCK_ENV_VARS`. Agent profiles can no longer mutate
  permission globals; a snapshot-and-diff guardrail around each
  `overlay.sh` aborts the sandbox start if they try. Affected globals:
  `BLOCKED_FILES`, `BLOCKED_ENV_VARS`, `BLOCKED_ENV_PATTERNS`,
  `ALLOWED_ENV_VARS`, `EXTRA_BLOCKED_PATHS`, `HOME_READONLY`,
  `HOME_WRITABLE`, `EXTRA_WRITABLE_PATHS`, `READONLY_MOUNTS`,
  `DENIED_WRITABLE_PATHS`.

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

### Added

- `SUPPRESS_AGENT_WARNINGS` config array — silence per-agent credential
  /path warnings. Accepts agent names or `"all"`.
- Startup warning when an agent's declared credentials (env vars +
  auth-marker files) look unreachable, with a login hint.
- Auto-creation of missing `$HOME` `HOME_WRITABLE` directories so
  first-time in-sandbox auth persists across sessions.
- `_check_agent_requirements`, `_env_var_reachable`, `_path_is_writable`,
  `_path_is_readable`, `_ensure_writable_home_dirs` helpers.

### Tests

- New section-4 assertions: universal overlay preparation, GOOGLE_API_KEY
  passthrough by default, per-agent credential warning, per-agent and
  `all` suppression, permission-mutation guardrail aborts on a malicious
  overlay, auto-mkdir of `HOME_WRITABLE` entries.

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
