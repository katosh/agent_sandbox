# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
