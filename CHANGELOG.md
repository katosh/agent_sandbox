# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.12.0] - 2026-05-27

### Changed

- **`BLOCKED_FILES` entries: materialize + warn + track, with opt-in
  cleanup (#73).** Before the fix, the bwrap and firejail backends
  silently skipped any `BLOCKED_FILES` entry that didn't exist on host
  (`[[ -e $blocked ]]` guard in `backends/bwrap.sh:525-537` and
  `backends/firejail.sh:360-371`). A user adding `~/secret-future-file`
  to `BLOCKED_FILES` to pre-emptively protect a path they might later
  create got NO enforcement until they touched the file themselves —
  silent no-op disguised as protection. Removing the guard (the
  obvious fix) was rejected because bwrap's `ensure_file → create_file
  → creat()` (called for every `SETUP_RO_BIND_MOUNT` op via
  `bubblewrap.c:1247`) writes to the host backing filesystem during
  mount setup for any path under a host RW bind — empirically
  confirmed for cases 1, 4, 6 in the agent_container CI probe
  (`ci/blockfiles-stub-probe` branch): host stub created, intermediate
  dirs auto-created on host, /tmp leak. Instead, `sandbox-exec.sh` now
  calls `_ensure_blocked_files_exist` (defined in `sandbox-lib.sh`)
  after `_apply_agent_profiles` and before `backend_prepare`. For each
  entry not present on host, the function:
  - runs `mkdir -p "$(dirname X)"` + `touch X` to create a zero-byte
    placeholder under user-controlled permissions,
  - emits a `WARNING:` line on stderr naming every materialized file
    (and every parent directory it had to create), so the user knows
    exactly what host-side state we touched,
  - tracks the created paths in launcher-scoped arrays so an opt-in
    cleanup pass can remove them post-exit.

  If a materialization is impossible (non-writable parent, read-only
  mount), the sandbox refuses to start and prints the full list of
  failing entries with a one-line remediation hint — that case is
  unrecoverable without user action and silent skip would defeat the
  feature.

  `sandbox-exec.sh` accepts a new `--cleanup-materialized` flag (also
  `CLEANUP_MATERIALIZED_BLOCKED_FILES=1` in env or config). When set,
  the launcher does NOT exec into the sandbox; it forks bwrap/firejail
  as a foreground child and runs `_cleanup_materialized_blocked_files`
  in its `EXIT` trap. The cleanup is conservative: a file is removed
  only if it's still 0 bytes; a directory is removed only if `rmdir`
  succeeds (empty). Retentions are reported on stderr with a `kept`
  note. Skipped under Landlock (BLOCKED_FILES has no enforcement
  effect; existing config-load warning is the only signal). Four new
  test sections (S06, S08, S09, S10 in `test.sh`) cover the warn,
  track, cleanup-empty and cleanup-retains paths; S07 covers the
  fail-loud branch for un-materializable entries. The `[[ -e $blocked
  ]]` skip guards in both backends have been removed as dead code.

### Added

- **Default `sbatch --output` now stages + symlinks like an explicit value.**
  Previously, omitting `--output` (and not setting it via `#SBATCH`
  directive) fell through to stock Slurm: `<submit-cwd>/slurm-<jobid>.out`
  written directly by slurmstepd, no chaperon staging, no symlink-plant
  defense. An in-sandbox agent could pre-create
  `slurm-<next-jobid>.out` as a symlink at the predictable cwd path and
  slurmstepd would follow it. `create_wrapped_script` now injects a
  `#SBATCH --output=<staging-path>` directive when neither the CLI nor a
  `#SBATCH` directive supplied one, picking `slurm-%A_%a.out` for array
  jobs (detected by `--array` in `VALIDATED_ARGS`) and `slurm-%j.out`
  otherwise — matching stock Slurm's defaults. The in-sandbox prelude
  plants the symlink at the resolved user path the same way it does for
  explicit `--output` values; the staging file lives in the RO-overlaid
  `.sandbox-state/slurm-logs/` subtree. CLI flag and `#SBATCH` directive
  values still win — the injection only fires when both captures are
  empty. Stderr is not injected separately; stock Slurm merges stderr
  into stdout when only `--output` is set, and the prelude's
  stderr-symlink branch no-ops on empty capture. `srun --output`
  remains out of scope — srun has no staging in 0.11.0 (separate
  follow-on work).

- **`BLOCKED_ENV_PATTERNS` case-insensitivity opt-in via trailing `/i`
  flag.** Patterns stay case-sensitive by default (no admin-baseline
  semantics change on upgrade); appending the industry-standard `/i`
  flag — same convention as sed (`s/.../.../i`), Perl (`qr/.../i`),
  and JavaScript regex (`/.../i`) — opts a single entry into
  case-insensitive matching. Env-var names are restricted to
  `[A-Za-z0-9_]` (POSIX IEEE Std 1003.1 §8.1) and cannot legitimately
  contain `/`, so the suffix is unambiguous. Implemented as a
  per-entry parse in `_is_blocked_by_pattern`: when the glob ends in
  `/i`, the suffix is stripped and `shopt -s nocasematch` is enabled
  for that entry's `case` match, then disabled before the next loop
  iteration. `ALLOWED_ENV_VARS` continues to override pattern
  matches regardless of the case-sensitivity flag.

  Example: `BLOCKED_ENV_PATTERNS+=("app_secret_*/i")` blocks
  `APP_SECRET_X`, `app_secret_x`, and `App_Secret_X`; the same
  pattern without `/i` blocks only the exact-case form.

- **`BLOCKED_ENV_PATTERNS` skeleton ships with `*password*/i`** as
  the default `/i` demonstration entry. The case-sensitive
  `*_PASSWORD` baseline still covers the canonical
  `DB_PASSWORD` / `SMTP_PASSWORD` UPPER-suffix convention; the
  new `*password*/i` sweep also catches the mixed-case and
  lowercase variants that Python `pydantic-settings`, Node
  `dotenv`, and Ruby `dotenv` routinely surface
  (`DB_password`, `password_hash`, `SmtpPassword`). Each
  default pattern group now carries an inline rationale comment
  so a site editing `sandbox.conf` can audit what each entry
  sweeps before keeping or overriding it. `ALLOWED_ENV_VARS`
  precedence preserved — any specific name caught by the new
  pattern can still be exempted explicitly.

## [0.11.0] - 2026-05-20

### Security

- **ASB-2026-001 (HIGH) — close `#SBATCH` directive whitespace-smuggling
  on the chaperon's directive filter (PR #71).** Before the fix,
  `create_wrapped_script` extracted the directive flag name by stripping
  at the first `=`, so a line like
  `#SBATCH --time=01:00 --task-prolog=/evil.sh` was classified as a
  `--time` directive and the smuggled tail was rebuilt verbatim into
  the wrapped script. Slurm's directive parser then whitespace-
  tokenized that body and applied both flags, executing attacker-
  controlled code on the compute node *before* `sandbox-exec.sh` could
  wrap the job — bypassing the CLI deny-list at
  `chaperon/handlers/_handler_lib.sh:451-478`. Three-layer fix in
  `_handler_lib.sh`: (a) a new `_is_denied_flag` helper centralizes the
  security-critical deny-list (`--prolog`, `--epilog`, `--task-prolog`,
  `--task-epilog`, `--get-user-env`, `--bcast`, `--container`,
  `--uid`/`--gid`, `--propagate`, `--burst-buffer-file`/`--bbf`,
  `--wrap`, `--chdir`/`-D`) so both the CLI path
  (`validate_sbatch_args`) and the script-directive path
  (`create_wrapped_script`) consult one source of truth; (b)
  defense-in-depth — any `#SBATCH` directive whose body contains
  `[[:space:]]--` after the leading flag is refused outright with a
  "whitespace-smuggling defense" message, since Slurm whitespace-
  tokenizes the body and one-flag-per-line is the only safe shape; (c)
  the `--output`/`--error` rebuild path now quotes the transformed
  value with `printf %q` so special characters in the value cannot be
  interpreted as flag boundaries by Slurm's tokenizer (belt-and-braces
  behind the body-level rejection).

- **ASB-2026-002 (MEDIUM) — `NETWORK_BLOCKLIST` wildcard-hostname
  entries no longer silently drop in filtered mode (PR #71).** The
  pasta port-exclusion resolver skipped wildcard hostname entries
  (`*.example.com`) and the `*` deny-all entry because they cannot be
  enforced at pasta's port-level layer. The skip-notes at
  `sandbox-lib.sh:2173` (`*` deny-all) and `:2180` (wildcard hostname)
  were gated on `NETWORK_FILTER_VERBOSE=1`, so an operator writing
  `NETWORK_BLOCKLIST+=("*.evil.com")` would reasonably assume
  enforcement and never see a signal that it was a no-op. The fix
  removes both verbose gates so the unenforceable-entry NOTE fires on
  every launch when such entries are present; message wording is
  unchanged so operator-side greps for the existing text keep working.

### Added

- **`.sandbox-state/` — hidden chaperon-owned state convention (#67; PR #68).**
  Adds `$project_dir/.sandbox-state/` as a general-purpose subdir for
  chaperon-managed state: `slurm-logs/` for redirected `sbatch
  --output` / `--error` files (see next entry), `chaperon/` for the
  chaperon's own diagnostic log. bwrap and firejail RO-overlay the
  dir after the writable project bind (path-keyed, later wins) so the
  agent inside the sandbox can read content but not tamper with it.
  Landlock can't RO-overlay a subtree under a writable parent
  (additive-rules limitation) so the dir is sandbox-writable there —
  the chaperon-side feature gated by `$SANDBOX_BACKEND` skips the
  Slurm-output redirection on landlock entirely; chaperon log writes
  fall back to the existing XDG location. Lifecycle: keep forever —
  documented as a sandbox artifact; `rm -rf .sandbox-state/` to
  reclaim. Threat-model framing (load-bearing for the design): the
  RO overlay prevents in-sandbox symlink-plant against the chaperon's
  writes, NOT trust in the dir's content — the submitted job
  determines what slurmstepd writes there, and the chaperon never
  trusts content read back. This is the explicit distinction from
  the reverted PR #50 (which RO-protected user-owned content the
  agent legitimately writes to). See
  `docs/reference/sandbox-state-dir.md` for the full convention.

- **`sbatch --output` / `--error` path transformation + in-sandbox
  symlink (#67; PR #68).** Closes the residual gap left by #65: even with
  the chaperon's cwd validated, `sbatch --output=/etc/cron.d/evil`
  (absolute) and `sbatch --output=../../etc/passwd` (relative
  traversal) escape past the compute-node sandbox because Slurm
  resolves and opens those paths as the user, before the sandbox
  boundary applies. The chaperon now transforms `--output` /
  `--error` values (both command-line and `#SBATCH` directive forms)
  into paths under `$project_dir/.sandbox-state/slurm-logs/` — leading
  `/` encoded as `__abs__/`, `..` components rewritten to `__updir__`,
  `%`-patterns preserved for slurmstepd's runtime substitution. Slurm
  writes to the chaperon-controlled (and bwrap/firejail-RO-overlaid)
  staging path. The in-sandbox wrapper, as its first action, creates
  a **relative** symlink from the user's resolved intended path to
  the staging file — gated by the bind-mount envelope, so if the
  user picked a non-sandbox-writable target (e.g. `/etc/cron.d/evil`)
  the `ln -s` fails gracefully and the log only lives at the
  staging path. No copy, no exit trap, no race with slurmstepd's
  continued writes. Wrapper-side helpers (`_sandbox_slurm_resolve_pat`,
  `_sandbox_link_slurm_output`) resolve `%j`/`%A`/`%a`/`%N`/`%n`/`%t`/
  `%u`/`%x` from the standard `SLURM_*` env vars set by slurmstepd.
  Disabled on landlock (the RO overlay is unavailable; symlink-plant
  defense would be missing). Closes #67.

### Added

- **Claude Code compatibility settings in the injected
  `sandbox-tmux.conf`.** Running Claude Code inside the nested sandbox
  tmux dropped its desktop notifications and progress bar (tmux
  swallows the passthrough escape sequences by default) and couldn't
  distinguish Shift+Enter (newline) from Enter (submit). Per Claude
  Code's [terminal-config docs](https://code.claude.com/docs/en/terminal-config),
  the injected config now sets `allow-passthrough on` (notifications /
  progress reach the outer terminal), `extended-keys on` +
  `terminal-features xterm*:extkeys` (Shift+Enter multiline input),
  `terminal-features *:RGB` (24-bit colour for any outer terminal, not
  just `xterm-256color`), `set-clipboard on` (OSC 52 copy over
  SSH/tmux), and `mouse on` (wheel-scroll / click-to-expand of
  full-screen tool output). The newer option names are wrapped in a
  `%if "#{>=:#{version},3.3}"` guard so older tmux (the sandbox still
  supports back to ~2.6) skips them instead of erroring. Customize in
  `~/.config/agent-sandbox/sandbox-tmux.conf`.

- **`.sandbox-state/` — hidden chaperon-owned state convention (#67).**
  Adds `$project_dir/.sandbox-state/` as a general-purpose subdir for
  chaperon-managed state: `slurm-logs/` for redirected `sbatch
  --output` / `--error` files (see next entry), `chaperon/` for the
  chaperon's own diagnostic log. bwrap and firejail RO-overlay the
  dir after the writable project bind (path-keyed, later wins) so the
  agent inside the sandbox can read content but not tamper with it.
  Landlock can't RO-overlay a subtree under a writable parent
  (additive-rules limitation) so the dir is sandbox-writable there —
  the chaperon-side feature gated by `$SANDBOX_BACKEND` skips the
  Slurm-output redirection on landlock entirely; chaperon log writes
  fall back to the existing XDG location. Lifecycle: keep forever —
  documented as a sandbox artifact; `rm -rf .sandbox-state/` to
  reclaim. Threat-model framing (load-bearing for the design): the
  RO overlay prevents in-sandbox symlink-plant against the chaperon's
  writes, NOT trust in the dir's content — the submitted job
  determines what slurmstepd writes there, and the chaperon never
  trusts content read back. This is the explicit distinction from
  the reverted PR #50 (which RO-protected user-owned content the
  agent legitimately writes to). See
  `docs/reference/sandbox-state-dir.md` for the full convention.

- **`sbatch --output` / `--error` path transformation + in-sandbox
  symlink (#67).** Closes the residual gap left by #65: even with
  the chaperon's cwd validated, `sbatch --output=/etc/cron.d/evil`
  (absolute) and `sbatch --output=../../etc/passwd` (relative
  traversal) escape past the compute-node sandbox because Slurm
  resolves and opens those paths as the user, before the sandbox
  boundary applies. The chaperon now transforms `--output` /
  `--error` values (both command-line and `#SBATCH` directive forms)
  into paths under `$project_dir/.sandbox-state/slurm-logs/` — leading
  `/` encoded as `__abs__/`, `..` components rewritten to `__updir__`,
  `%`-patterns preserved for slurmstepd's runtime substitution. Slurm
  writes to the chaperon-controlled (and bwrap/firejail-RO-overlaid)
  staging path. The in-sandbox wrapper, as its first action, creates
  a **relative** symlink from the user's resolved intended path to
  the staging file — gated by the bind-mount envelope, so if the
  user picked a non-sandbox-writable target (e.g. `/etc/cron.d/evil`)
  the `ln -s` fails gracefully and the log only lives at the
  staging path. No copy, no exit trap, no race with slurmstepd's
  continued writes. Wrapper-side helpers (`_sandbox_slurm_resolve_pat`,
  `_sandbox_link_slurm_output`) resolve `%j`/`%A`/`%a`/`%N`/`%n`/`%t`/
  `%u`/`%x` from the standard `SLURM_*` env vars set by slurmstepd.
  Disabled on landlock (the RO overlay is unavailable; symlink-plant
  defense would be missing). Closes #67.

### Fixed

- **Preserve Slurm submission cwd inside the sandbox (#65; PR #66).** The
  bwrap and firejail backends forced `--chdir $project_dir` /
  `--private-cwd=$project_dir` unconditionally, discarding the cwd
  Slurm preserves natively on the compute node. Result:
  `sbatch --wrap='bash relpath.sh'` submitted from a project
  subdirectory ran the wrap content from `$project_dir`, not the
  submission dir, and exited 127 in ~6s with
  `No such file or directory`. Both backends now route their cwd
  target through a new `_resolve_inherited_cwd` helper in
  `sandbox-lib.sh` that honors `$SLURM_SUBMIT_DIR` when it
  canonicalizes under `$project_dir` (the same security envelope
  `chaperon/handlers/_handler_lib.sh::validate_cwd` enforces on the
  submission side), and falls back to `$project_dir` otherwise.
  `realpath` canonicalization rejects symlink-based prefix-check
  bypass. The Landlock backend is unchanged (it never had a
  `--chdir` surface), but the chaperon-generated wrapper now
  prepends `cd "${SLURM_SUBMIT_DIR:-.}"` before exec'ing into the
  sandbox, so Landlock also lands in the submission dir on
  clusters whose prolog drops cwd to `$HOME`. Makes
  slurm-inside-sandbox indistinguishable from native slurm for
  the cwd surface, without jeopardizing project-dir confinement.

### Security

- **bwrap + firejail RO-overlay `.sandbox-state/` (#67; PR #68).**
  The chaperon `mkdir -p`s the staging parent under
  `$project_dir/.sandbox-state/slurm-logs/` before invoking real
  `sbatch`; without intervention, an agent inside the sandbox could
  `ln -sf /etc/passwd $project_dir/.sandbox-state/slurm-logs/<expected>`
  between the chaperon's `mkdir` and slurmstepd's `open()`, causing
  slurmstepd (running as the user on the compute node, outside the
  sandbox boundary) to follow the symlink and write job output to
  the attacker-chosen target. The bwrap and firejail backends now
  RO-overlay `.sandbox-state/` after the writable project bind
  (path-keyed, later-wins) — the agent can read content (so
  `cat .sandbox-state/slurm-logs/job-123.out` still works for
  debugging) but cannot create, rename, or modify entries. Threat-
  model framing is explicit and load-bearing: the RO overlay
  prevents in-sandbox symlink-plant against chaperon-owned writes
  — it does NOT establish trust in the dir's content (the
  submitted job determines what slurmstepd writes there; the
  chaperon never trusts content read back for any security
  decision). This is the explicit distinction from the reverted
  PR #50, which wanted to RO-protect user-owned content the agent
  legitimately writes to; PR #68 RO-protects chaperon-owned content
  the agent never wrote and never needs to write. Inline rationale
  comments in `sandbox-lib.sh` and `chaperon/handlers/_handler_lib.sh`
  quote the operator's design-discussion ack verbatim so the rule
  isn't reverted on the same grounds.

- **Reject `--project-dir $HOME` — critical home-directory credential
  bypass.** When the project directory was the user's home directory
  itself (the default when an agent is launched from `~`), the bwrap
  backend bound all of `$HOME` writable *after* emitting the
  home-isolation masks (the `--tmpfs $HOME` blank slate in
  restricted/tmpwrite mode, and the `--tmpfs $HOME/.ssh|.aws|.gnupg`
  credential masks in read/write mode). Because bwrap applies its
  arguments left-to-right with last-wins precedence, the project bind
  overlaid those masks and re-exposed the real `~/.ssh/id_rsa`,
  `~/.aws/credentials`, etc. — readable in every mode and *writable*
  in the default `tmpwrite` mode (confirmed: a write to `~/.config/`
  and to `~/.ssh/` persisted to the host, enabling `authorized_keys`
  / `.bashrc` persistence escapes). `validate_project_dir` now
  rejects a project dir that resolves to `$HOME` exactly (it must be a
  subdirectory), with an actionable error; the bwrap backend also
  guards the home-relative project bind (`"$HOME"/*`, never `$HOME`
  itself) as defense in depth. Subdirectories of `$HOME` are
  unaffected and keep their credential masks.

- **Deny `srun --multi-prog` — critical compute-node sandbox bypass.**
  The chaperon's srun handler sandboxes a job by appending
  `-- sandbox-exec.sh --project-dir … -- <command>` to the real srun
  invocation, relying on srun exec'ing `sandbox-exec.sh`. But
  `--multi-prog <cfg>` changes srun's execution model: it launches the
  per-task executables listed in the **agent-supplied config file**,
  so the appended `sandbox-exec.sh …` degrades to inert
  `%`-substitution data and is never exec'd. The config's programs run
  directly under `slurmstepd` on the compute node, unsandboxed, as the
  host user — a full escape. `--multi-prog` is now removed from the
  srun flag whitelist and explicitly denied with an actionable message.

- **Restrict `srun --output` / `--error` / `--input` to the project
  directory.** Slurm's `slurmstepd` opens these files OUTSIDE the
  sandbox, as the host user, before the compute-node sandbox boundary
  applies. An unrestricted path meant the task's (agent-controlled)
  stdout could be written to any host-writable path
  (`--output=~/.ssh/authorized_keys`, `--output=~/.bashrc`) and any
  host-readable file could be piped into the job
  (`--input=~/.aws/credentials`), defeating project-dir confinement
  even though the task itself is sandboxed. The srun handler now
  canonicalizes each `-o/-e/-i` path against the validated submission
  cwd and rejects any that resolve outside the project directory
  (`..`-traversal and sibling-prefix tricks included). Project-relative
  paths — the common case — are unchanged. (The sbatch handler already
  contained these via its `.sandbox-state/slurm-logs` staging
  transform; srun had been missed.)

- **Bind the project dir before the `BLOCKED_FILES` /
  `EXTRA_BLOCKED_PATHS` overlays (bwrap).** For a project directory
  *outside* `$HOME`, the bwrap backend emitted the writable project
  bind *after* the protective overlays. bwrap's last-wins precedence
  meant any `BLOCKED_FILES` or `EXTRA_BLOCKED_PATHS` entry that lived
  inside that project tree was silently re-exposed (writable),
  defeating the block — while the same entries were correctly masked
  for projects under `$HOME` (which were bound earlier). The project
  bind is now emitted once, before the overlays, for both cases, so
  blocked paths inside the project stay masked regardless of the
  project's location. `.sandbox-state/` continues to RO-overlay after
  the project bind.

- **Close credential env-var scrub gaps.** Added to the default
  `BLOCKED_ENV_PATTERNS`: `*_CREDENTIALS` (plural — the existing
  `*_CREDENTIAL` missed `GOOGLE_CREDENTIALS` / `OPENAI_CREDENTIALS`,
  which carry inline service-account JSON), `KUBECONFIG` + `KUBE_*`
  (Kubernetes cluster credentials), and `SLURM_JWT` (Slurm REST API
  token — deliberately the specific name, *not* `SLURM_*`, so the
  legitimate `SLURM_JOB_*` / `SLURM_NTASKS` runtime vars jobs depend
  on are not stripped). Applied to both `sandbox-lib.sh` defaults and
  the shipped `sandbox.conf`.

- **Seccomp: block the new mount API (bwrap).** The generated BPF
  filter blocked `mount(2)` as defense-in-depth (for the "if a kernel
  bug or misconfig ever leaks `CAP_SYS_ADMIN`" case the denylist
  targets) but left its functional replacement — the kernel 5.2+ mount
  API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`,
  `fspick`, `mount_setattr`) — open. A leaked capability could have
  mounted via `fsopen`+`fsconfig`+`fsmount`+`move_mount` instead,
  defeating the `mount(2)` block. All seven are now denied on both
  x86_64 and aarch64 (verified: they return EPERM inside the sandbox
  vs EFAULT/EINVAL outside). Same `CAP_SYS_ADMIN` gating, zero effect
  on HPC/ML workloads.

### Backend asymmetries

- **Landlock disables the `.sandbox-state/` + sbatch output-staging
  feature entirely (#67; PR #68).** Landlock's additive-rules model
  cannot RO-overlay a subtree under a writable parent — there is no
  path-keyed read-only mechanism that would let the chaperon make
  `$project_dir` writable while making
  `$project_dir/.sandbox-state/` read-only. Without the RO overlay,
  the symlink-plant defense above would be missing, so the
  chaperon's sbatch handler skips the `--output` / `--error` path
  transformation when `SANDBOX_BACKEND=landlock` and slurmstepd
  writes to the user-supplied paths directly (pass-through to native
  slurm behaviour). The chaperon's own diagnostic log similarly
  falls back to its existing XDG location instead of relocating
  under `.sandbox-state/chaperon/`. The landlock backend emits a
  one-line `NOTE` at init when `.sandbox-state/` exists, surfacing
  the feature gap to the operator. Operators who need the
  symlink-plant defense on a host should pick bwrap or firejail;
  landlock retains its niche as a no-kernel-namespaces fallback.

### Security

- **Reject `--project-dir $HOME` — critical home-directory credential
  bypass.** When the project directory was the user's home directory
  itself (the default when an agent is launched from `~`), the bwrap
  backend bound all of `$HOME` writable *after* emitting the
  home-isolation masks (the `--tmpfs $HOME` blank slate in
  restricted/tmpwrite mode, and the `--tmpfs $HOME/.ssh|.aws|.gnupg`
  credential masks in read/write mode). Because bwrap applies its
  arguments left-to-right with last-wins precedence, the project bind
  overlaid those masks and re-exposed the real `~/.ssh/id_rsa`,
  `~/.aws/credentials`, etc. — readable in every mode and *writable*
  in the default `tmpwrite` mode (confirmed: a write to `~/.config/`
  and to `~/.ssh/` persisted to the host, enabling `authorized_keys`
  / `.bashrc` persistence escapes). `validate_project_dir` now
  rejects a project dir that resolves to `$HOME` exactly (it must be a
  subdirectory), with an actionable error; the bwrap backend also
  guards the home-relative project bind (`"$HOME"/*`, never `$HOME`
  itself) as defense in depth. Subdirectories of `$HOME` are
  unaffected and keep their credential masks.

- **Deny `srun --multi-prog` — critical compute-node sandbox bypass.**
  The chaperon's srun handler sandboxes a job by appending
  `-- sandbox-exec.sh --project-dir … -- <command>` to the real srun
  invocation, relying on srun exec'ing `sandbox-exec.sh`. But
  `--multi-prog <cfg>` changes srun's execution model: it launches the
  per-task executables listed in the **agent-supplied config file**,
  so the appended `sandbox-exec.sh …` degrades to inert
  `%`-substitution data and is never exec'd. The config's programs run
  directly under `slurmstepd` on the compute node, unsandboxed, as the
  host user — a full escape. `--multi-prog` is now removed from the
  srun flag whitelist and explicitly denied with an actionable message.

- **Restrict `srun --output` / `--error` / `--input` to the project
  directory.** Slurm's `slurmstepd` opens these files OUTSIDE the
  sandbox, as the host user, before the compute-node sandbox boundary
  applies. An unrestricted path meant the task's (agent-controlled)
  stdout could be written to any host-writable path
  (`--output=~/.ssh/authorized_keys`, `--output=~/.bashrc`) and any
  host-readable file could be piped into the job
  (`--input=~/.aws/credentials`), defeating project-dir confinement
  even though the task itself is sandboxed. The srun handler now
  canonicalizes each `-o/-e/-i` path against the validated submission
  cwd and rejects any that resolve outside the project directory
  (`..`-traversal and sibling-prefix tricks included). Project-relative
  paths — the common case — are unchanged. (The sbatch handler already
  contained these via its `.sandbox-state/slurm-logs` staging
  transform; srun had been missed.)

- **Bind the project dir before the `BLOCKED_FILES` /
  `EXTRA_BLOCKED_PATHS` overlays (bwrap).** For a project directory
  *outside* `$HOME`, the bwrap backend emitted the writable project
  bind *after* the protective overlays. bwrap's last-wins precedence
  meant any `BLOCKED_FILES` or `EXTRA_BLOCKED_PATHS` entry that lived
  inside that project tree was silently re-exposed (writable),
  defeating the block — while the same entries were correctly masked
  for projects under `$HOME` (which were bound earlier). The project
  bind is now emitted once, before the overlays, for both cases, so
  blocked paths inside the project stay masked regardless of the
  project's location. `.sandbox-state/` continues to RO-overlay after
  the project bind.

- **Close credential env-var scrub gaps.** Added to the default
  `BLOCKED_ENV_PATTERNS`: `*_CREDENTIALS` (plural — the existing
  `*_CREDENTIAL` missed `GOOGLE_CREDENTIALS` / `OPENAI_CREDENTIALS`,
  which carry inline service-account JSON), `KUBECONFIG` + `KUBE_*`
  (Kubernetes cluster credentials), and `SLURM_JWT` (Slurm REST API
  token — deliberately the specific name, *not* `SLURM_*`, so the
  legitimate `SLURM_JOB_*` / `SLURM_NTASKS` runtime vars jobs depend
  on are not stripped). Applied to both `sandbox-lib.sh` defaults and
  the shipped `sandbox.conf`.

- **Seccomp: block the new mount API (bwrap).** The generated BPF
  filter blocked `mount(2)` as defense-in-depth (for the "if a kernel
  bug or misconfig ever leaks `CAP_SYS_ADMIN`" case the denylist
  targets) but left its functional replacement — the kernel 5.2+ mount
  API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`,
  `fspick`, `mount_setattr`) — open. A leaked capability could have
  mounted via `fsopen`+`fsconfig`+`fsmount`+`move_mount` instead,
  defeating the `mount(2)` block. All seven are now denied on both
  x86_64 and aarch64 (verified: they return EPERM inside the sandbox
  vs EFAULT/EINVAL outside). Same `CAP_SYS_ADMIN` gating, zero effect
  on HPC/ML workloads.

## [0.10.1] - 2026-05-15

### Added

- **`NETWORK_FILTER_MODE=proxied` — host-mediated egress for
  pasta-deficient hosts.** v0.10.0 left operators on legacy-kernel
  hosts (`< 5.7` without `setcap cap_net_raw+ep` on pasta) with a
  binary choice: accept the `open` fallback (host network, threat-
  class ports re-opened) or pin `stricter` and fall to `isolated`
  (no DNS / pip / git inside the sandbox). Neither preserved both
  isolation and usability. `proxied` slots between `filtered` and
  `isolated` in the strictness ordering (`open < filtered <
  proxied < isolated`): the sandbox runs inside `--unshare-net`
  (empty netns — no resolver, no raw sockets, no ICMP), and the
  agent's outbound traffic is mediated by a host-side HTTP CONNECT
  + SOCKS5 daemon (`tools/proxy/agent-sandbox-proxy.py`, single
  Python 3.6+ helper) reached via two bind-mounted Unix sockets
  and an in-sandbox Python TCP↔Unix bridge. `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` are pre-set inside the
  sandbox so curl, pip, conda, git, gh, and the Claude SDK route
  through the proxy without further configuration. The proxy
  enforces `effective_network_blocklist` at CONNECT time — so
  hostname / wildcard / CIDR entries are now load-bearing (under
  `filtered`, these are skipped at pasta's port-only layer). On top
  of the user-supplied policy, the proxy hard-denies a baked-in IP
  floor (`127.0.0.0/8`, `169.254.0.0/16`, RFC1918, IPv6 link-
  local / ULA / cloud-metadata) regardless of `NETWORK_BLOCKLIST`,
  and rejects host-string IPv4 quirks (`2130706433`, `0x7f000001`)
  before resolution. DNS-rebind defence: one resolve per CONNECT,
  IP-floor check on the resolved address, connect to that literal
  IP. The host-side daemon arms `prctl(PR_SET_PDEATHSIG, SIGTERM)`
  as its first action; `sandbox-exec.sh`'s cleanup trap is the
  belt-and-suspenders cover for the pre-exec failure window.

  Opt in via `NETWORK_FILTER_MODE=proxied`, or pin
  `NETWORK_FILTER_FALLBACK=stricter` to land on it automatically
  when pasta degrades — the `stricter` walk now goes least-strict-
  step-up first, so a degraded-pasta host lands on `proxied` before
  `isolated`. Default-config users (`MODE=filtered FALLBACK=open`)
  see ZERO behaviour change: `open` policy never strengthens, so
  the default flip from 0.10.0 (fall to `open` on degraded pasta)
  is preserved. Implements Option C of `docs/admin/hardening.md`
  §4 (previously sketched, now shipped). Trade-off: non-proxy-
  aware tools (`ssh` direct, `dig`, `ping`, raw TCP daemons,
  `bash /dev/tcp/...`) break inside the sandbox — `ssh -o
  ProxyCommand='nc -X 5 -x 127.0.0.1:44890 %h %p'` routes ssh
  through the SOCKS5 bridge; other workloads needing arbitrary TCP
  egress should pin `MODE=open` or `MODE=filtered`. Bwrap only in
  0.10.1; firejail/landlock parity tracked as follow-up.

  Regression tests in `test.sh::11.4` exercise the resolver
  changes (Tests 5d–5g) and the proxy daemon's policy enforcement
  (HTTP CONNECT and SOCKS5 paths, hardened IP floor, IPv4-quirk
  rejection, EXCEPT carve-throughs).

- **`NETWORK_MAIL_BLOCK` — defense-in-depth above the port-level
  SMTP filter.** v0.10.0's network filter closes outbound SMTP at
  the namespace edge (ports 25 / 465 / 587 / 2525 / 24, plus the
  local-MTA loopback variants); an agent that exec's `sendmail`
  hits a connection-refused / ENETUNREACH after a 30-second timeout,
  which reads as a transient network fault and invites retry. The
  new mail-block layer catches the `execve` syscall instead:
  every canonical mailer binary inside the sandbox is replaced
  with a stub (`tools/mail-block/mail-block-stub.sh`, single POSIX
  sh, no bash dependency) that prints a 16-line deterrent message
  to stderr — explicitly addressed to an AI agent reading it,
  foreclosing the search tree ("retrying with another binary,
  another invocation, or another path will produce the same
  result"), enumerating the known-mailer set so the agent doesn't
  burn cycles hunting alternatives, and instructing escalate to
  the user rather than retry. Exit code 77 (sysexits `EX_NOPERM`,
  "permission denied at a higher level" — chosen over `EX_CONFIG`
  because the latter reads as operator misconfiguration and invites
  retry-with-fix).

  Two reinforcing path-resolution layers compose to catch the
  invocation regardless of how `argv[0]` was assembled:

    1. **Absolute-path bind-mounts.** The launcher iterates the
       canonical mailer paths (`/usr/{bin,sbin}/<name>`,
       `/usr/lib/sendmail`, `/var/qmail/bin/qmail-*`) and `--ro-bind`s
       the stub over every entry that exists on the host. Catches
       absolute-path invocations (`/usr/sbin/sendmail -t`,
       `git send-email`'s internal sendmail call, …).
    2. **PATH-prefix symlink farm.** A per-launch tempdir under
       `$TMPDIR` (mode `0700`, same staging area as the chaperon
       FIFO and the proxy socket dir) is populated with one
       symlink per canonical name pointing at the in-sandbox stub
       path. The dir is `--ro-bind`'d at the same path on both sides
       of the bwrap boundary — mirroring the chaperon FIFO pattern,
       so the path resolves identically inside and outside the
       sandbox — and prepended to `PATH` ahead of chaperon stubs and
       the rest of the sandbox `PATH`. Catches PATH lookups that
       land on `/usr/local/bin/<name>`, Lmod-injected
       `/app/software/<pkg>/bin/<name>`, or any other host path the
       bind-mount loop missed.

  Canonical mailer-name set (`_MAIL_BLOCK_STUB_NAMES` in
  `sandbox-lib.sh`): sendmail family (`sendmail`,
  `sendmail.sendmail`, `sendmail.postfix`, `rmail`); mail / mailx
  variants (`mail`, `mailx`, `Mail`, `s-nail`, `nail`, `bsd-mailx`,
  `heirloom-mailx`); mutt family (`mutt`, `neomutt`); SMTP-direct
  clients (`msmtp`, `ssmtp`, `nullmailer-send`, `smtp-cli`); postfix
  admin (`postsuper`, `postdrop`, `postqueue`, `mailq`,
  `newaliases`); test tool (`swaks`); mpack family (`mpack`,
  `metasend`); exim admin (`exim`, `exim4`); DragonFly Mail Agent
  (`dma`); qmail clients (`qmail-inject`, `qmail-qmqpc`,
  `qmail-remote`). 30 names total, composed from a security review
  covering common Debian / Ubuntu / RHEL / Arch / DragonFly mailer
  packaging.

  Argv echo is hardened against control-byte injection. A naive
  stub that prints `argv[1..N]` to stderr would let a hostile
  argument containing `\e[2J\e[H` (ANSI CSI) or OSC-8 hyperlinks
  rewrite the agent's terminal view or smuggle clickable URLs into
  log scrapers. The stub instead reports only `basename "$0"`
  passed through `LC_ALL=C tr -cd '[:graph:]'` (strips every byte
  outside printable ASCII, including ESC `0x1b` and CR / NUL) and
  capped at 64 bytes, plus the argv **count** (so the agent can
  distinguish a probe from a real send attempt) — never the args
  themselves.

  Three-valued knob: `NETWORK_MAIL_BLOCK=auto|on|off`. Default
  `auto` activates the stub whenever the configured
  `NETWORK_FILTER_MODE` OR the resolved one is anything other than
  `open` (strictest-of-both rule) — so the stub is on for the
  default configuration AND stays on when `NETWORK_FILTER_FALLBACK=open`
  degrades a `filtered` request to `open` because the host lacks
  pasta. The fallback policy authorises a degraded network LAYER,
  not a withdrawn egress CONCERN; mail-block doesn't depend on the
  kernel features the network filter gated on, so defense-in-depth
  earns its name precisely when the primary layer collapsed. The
  layer steps aside only when BOTH the configured intent and the
  resolved state are `open` (host-network parity, where the host-
  side mail policy is shaped to handle legitimate mail). `on`
  activates regardless of the network mode; `off` is the escape
  hatch for sites that legitimately need the canonical mailer
  binaries visible (rare — the v0.10.0 port filter already breaks
  them at the socket layer; document the use case if you set
  this). Admin enforcement is harden-only with strictness
  `off < auto < on`, matching the model used by `NETWORK_FILTER_MODE`
  / `_FALLBACK`.

  Backend support: bwrap only in 0.10.1. Firejail / landlock
  parity is mechanically straightforward (both support the same
  bind-mount + PATH-prefix primitives) but deferred so the initial
  release stays auditable; the network-filter port closure still
  applies on the supported backends per their own matrix.

  Tests (`test.sh::11.4.mailblock`): resolver semantics (default
  knob, auto/on/off interaction with the mode axis, invalid-knob
  rejection); stub-direct behaviour (exit 77, deterrent message,
  argv[0] propagation through symlinks under each of 13 canonical
  names); ANSI-sanitization (hostile `argv[0]` containing ESC is
  stripped before stderr emission); end-to-end through bwrap
  (PATH-prefix shadow + deterrent message + exit 77; guarded by
  `is_bwrap && has_mount_ns`); off-escape-hatch (PATH unaffected
  when `MAIL_BLOCK=off`).

### Changed

- **`stricter` fallback walk order** flipped from most-strict-first
  to LEAST-strict-step-up first. The pre-0.10.1 loop walked
  `isolated filtered` (only meaningful when `proxied` did not
  exist); the 0.10.1 loop walks `filtered proxied isolated` with
  the `_try_idx > _req_idx` gate, so a degraded-pasta host pinning
  `MODE=filtered FALLBACK=stricter` lands on `proxied` (smallest
  step up that strengthens) instead of jumping straight to
  `isolated`. The pre-0.10.1 behaviour is recovered by pinning
  `MODE=isolated` directly (or by `setcap cap_net_raw+ep` on
  pasta so the degraded fallback is never taken).

- `_CONFIG_SCALARS` (in `sandbox-lib.sh`) gains
  `NETWORK_MAIL_BLOCK`. No backwards-compat surface — operators
  carrying older `sandbox.conf` files inherit the default `auto`
  silently.

- `sandbox-exec.sh::_sandbox_cleanup` extended to `rm -rf` the
  per-launch mail-block stubs dir, matching the existing pattern
  for the proxy-fallback socket dir.

## [0.10.0] - 2026-05-12

### Changed

- **`NETWORK_FILTER_FALLBACK` default flipped from `stricter` to
  `open`** (in both the shipped `sandbox.conf` skeleton and the
  `sandbox-lib.sh` runtime default). On kernel < 5.7 hosts (common
  on shared HPC login nodes), pasta's `SO_BINDTODEVICE` call needs
  `CAP_NET_RAW` even from an unprivileged process; without admin
  intervention (`setcap cap_net_raw+ep` on the pasta binary) the
  forwarding probe trips and `filtered` is unavailable. Under
  `stricter`, the resolver would then fall to `isolated` — breaking
  DNS / pip / git / API inside the sandbox and effectively refusing
  to run on every legacy-kernel deployment. `open` keeps the
  sandbox usable (loud warning, threat-class ports re-opened)
  instead. Trade-off: out-of-the-box deployments on degraded hosts
  retain host-network reach rather than killing outbound; sites
  where the stronger default-deny posture is mandatory should pin
  `NETWORK_FILTER_FALLBACK="stricter"` (or `strict`) in the admin
  baseline (non-weakening per the admin-enforcement model).
  Resolver unit test in `test.sh::11.4` updated to assert the new
  default.

### Fixed

- **`_pasta_can_forward_outbound` dead-code cleanup.** The post-
  cmdsubst `_rc=$?` was masked by the preceding `|| true` and so
  always read `0`; the `_rc -ne 0` "failed" branch was unreachable.
  Removed `_rc` entirely (the load-bearing signal is the
  `forwarding only 127.0.0.1` stderr match, not pasta's exit code).
  Behaviour is unchanged on the working path; only the dead branch
  goes away. Side-effect contract narrows from
  `"ok"|"degraded"|"failed"` to `"ok"|"degraded"`; no caller read
  `"failed"`.

- **`make install` now installs `tools/pasta/`.** v1.1 ships the
  pasta helper at `tools/pasta/<arch>/pasta` and
  `_resolve_network_helper` looks for it at
  `<SANDBOX_DIR>/tools/pasta/<arch>/pasta`, but the Makefile's
  `install-lib` rule did not copy the `tools/` tree. Result: every
  `make install`-based deployment without a distro `passt` package
  on PATH silently dropped to the resolver's "no helper found"
  fallback path. Fix copies the entire `tools/pasta/{fetch.sh,
  README.md,<arch>/*}` tree to `<prefix>/lib/agent-sandbox/tools/
  pasta/` with executable bits preserved on `fetch.sh` and the
  per-arch `pasta` binary.

- **Helper presence ≠ helper deliverability.** v1.1 declared
  `filtered` supported on any host with an executable pasta. On
  kernels < 5.7 / unprivileged userns / no `CAP_NET_RAW`, pasta
  starts but degrades to loopback-only forwarding — the sandbox
  then launched with the documented filtered argv and the agent
  lost outbound on every port, including ports the blocklist did
  not exclude (silent worst-of-both-worlds). Added
  `_pasta_can_forward_outbound`: probes pasta's stderr for the
  `forwarding only 127.0.0.1` banner; on match the resolver falls
  back per `NETWORK_FILTER_FALLBACK` (default stricter→isolated)
  with the specific degradation reason quoted in the warning.
  Escape hatch: `NETWORK_FILTER_SKIP_HELPER_PROBE=1` for operators
  who have validated pasta out-of-band (`setcap cap_net_raw+ep` or
  newer kernel). CI hosts (Ubuntu 22.04+) are unaffected; HPC
  login-node deployments now degrade gracefully and explicitly.
  Regression test in `test.sh::11.4` stubs a degraded pasta and
  asserts both the fallback and the override behaviour.

### Security

- **Network filter v1.1 — port-level `filtered`-mode enforcement
  via bwrap + pasta.** Builds on the v1.0 configuration surface +
  fallback resolver. Removes the
  `NETWORK_FILTER_ENABLE_HELPER_PROBE=1` gate; `filtered` mode is
  real by default whenever `pasta` is available on the host.
  **No nftables / iptables runtime dependency** — enforcement
  happens at pasta's own outbound forwarding boundary via the
  `-T ~N` (TCP) / `-U ~K` (UDP) port-exclusion syntax.

  **Enforcement flip — read this before upgrading.** v1.0
  deployments running the defaults (`NETWORK_FILTER_MODE=filtered`,
  `NETWORK_FILTER_FALLBACK=stricter`) silently fell back to
  `isolated` because the helper-probe was gated — the layer was
  inert in practice. v1.1 ungates the probe AND ships an in-tree
  pasta binary, so those same deployments will START enforcing real
  `filtered` mode the moment v1.1 lands. If your CI / test runners
  needed a specific outbound port the default blocklist closes, add
  `NETWORK_BLOCKLIST_EXCEPT+=(<port>)` for the bare port or pin
  `NETWORK_FILTER_MODE=open` for those runs.

  **Shipped static `pasta` binary.** The repo ships
  `tools/pasta/x86_64/pasta` (1.2 MiB, statically linked, runnable
  on glibc ≥ 2.17 hosts including Ubuntu 18.04 / RHEL 7 kernels).
  Source is the upstream passt project's official build endpoint at
  https://passt.top/builds/latest/x86_64/pasta. SHA256 is pinned in
  `tools/pasta/x86_64/SHA256SUMS`; license selection (BSD-3-Clause
  arm) and copyright provenance are documented in
  `tools/pasta/x86_64/NOTICE` + `LICENSE-BSD-3-Clause`. Tarball
  growth: ~1.2 MiB. `tools/pasta/fetch.sh` is rewritten to default
  to "download pre-built binary + verify SHA256"; source-build is
  opt-in via `PASTA_BUILD_FROM_SOURCE=1` for sites with strict
  reproducibility / no-binary-redistribution policy. aarch64 not
  shipped in v1.1 — operators on aarch64 use distro `passt` or
  source-build.

  **Composition in `backends/bwrap.sh`.** When `filtered` resolves,
  `backend_prepare` calls `generate_pasta_port_exclusions` to
  produce `-T ~N,~M,...` and `-U ~K,...` SPECs from
  `effective_network_blocklist`; `backend_exec` exec's
  `pasta --foreground --quiet -T <spec> -U <spec> -- bwrap [args]
  -- cmd`. pasta owns the netns (bwrap does NOT add `--unshare-net`
  in this path — that would create a second empty netns and break
  pasta's tap), provisions a tap forwarding to the host network,
  proxies DNS to the host resolver, AND gives the netns its own
  empty loopback so any host MTA on `127.0.0.1` is structurally
  unreachable.

  **Helper-probe ungated.** `_resolve_network_helper` no longer
  requires `NETWORK_FILTER_ENABLE_HELPER_PROBE=1`. Probe order:
  PATH `pasta` → `tools/pasta/<arch>/pasta` → legacy
  `tools/pasta/pasta` (one-release transitional) → PATH
  `slirp4netns` (currently downgrades to isolated mode with a
  warning; slirp4netns CLI shape differs and is follow-up work).

  **Forwarding-capability probe.** Helper presence is now necessary
  but not sufficient. After resolving a pasta binary the resolver
  runs `pasta --foreground --quiet -- true` and inspects stderr for
  the `SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1` banner
  pasta emits when its host-side outbound bind is denied (kernel
  < 5.7 / unprivileged userns / no `CAP_NET_RAW` — typical HPC
  login-node profile). When the probe trips, the resolver treats the
  helper as unavailable, falls back per `NETWORK_FILTER_FALLBACK`,
  and quotes the specific degradation reason in the warning rather
  than the generic "pasta not found" line. Without this probe, v1.1
  would have silently launched the documented pasta argv on degraded
  hosts and left the agent with no outbound on every port — the
  worst-of-both-worlds. Escape hatch:
  `NETWORK_FILTER_SKIP_HELPER_PROBE=1` for operators who have
  validated pasta out-of-band (e.g. via `setcap cap_net_raw+ep`).
  See `docs/reference/network-filter.md` → "Helper validation: the
  forwarding probe" for the full rationale and workarounds.

  **Test coverage.** `test.sh::11.4` is extended with:
  - pasta port-exclusion generator unit tests: bare-port /
    universal-CIDR-port / loopback-host-port → `~N` emission;
    hostname / wildcard / `*` skipped silently by default; verbose
    notes when `NETWORK_FILTER_VERBOSE=1`; bare-port exception
    lifts the corresponding `~N` exclusion.
  - Empirical `filtered`-mode integration (skips cleanly when
    pasta missing from the runner): port 25 must drop;
    github.com:443 must remain reachable through the pasta tap.
  - v1.0 test 2 (`filtered + stricter`) now branches on
    `_test_filtered_deliverable` (resolver's actual verdict on the
    runner, which includes the forwarding probe), not just
    binary-on-disk. Catches the "pasta present but degraded" case
    that the presence-only check would have missed.
  - New regression guard: a stubbed pasta that emits the
    `forwarding only 127.0.0.1` banner triggers the resolver's
    degraded path; assert fallback to isolated AND
    `_NETWORK_HELPER_DEGRADED_REASON` is set. Also asserts
    `NETWORK_FILTER_SKIP_HELPER_PROBE=1` restores filtered.
  - The "strict + unavailable-filtered → must exit" assertion is
    moved from bwrap (which now resolves with the shipped pasta on
    most runners) to landlock (deterministically unsupported on
    every runner).

  **Firejail + landlock parity (unchanged from v1.0).** Firejail's
  `--netfilter` requires a private netns wired to a host bridge
  (`--net=<iface>`); v1.1 does not auto-provision the bridge.
  Firejail `filtered` remains "open and isolated only"; the
  resolver's error message names the bridge dependency. Landlock
  has no netns, unchanged.

  **Enforcement scope — what v1.1 covers, what it doesn't, why
  that's the right shape.** pasta `-T/-U` filters by destination
  port at the netns boundary. It does NOT inspect destination
  hostnames or CIDRs — that's L4-and-up surface, properly handled
  by an SNI-aware proxy or DNS layer (v1.2 scope; R3 in the
  network-survey, deferred per settylab/dotto-nexus#117).

  - **Enforced**: universal bare-port closures (`25`/`465`/`587`/
    `2525` SMTP submission; `853` DoT; `23`/`79`/`113`/`512`/
    `513`/`514` legacy r-services). The identity-hijack threat
    that motivated this feature is fully closed.
  - **Enforced (as port-only)**: loopback `127.0.0.1:N` (also
    structurally unreachable via pasta's empty loopback);
    universal `0.0.0.0/0:N`; site CIDR `10.0.0.0/8:N` (universal
    port portion only — CIDR-specificity is dropped at this
    layer).
  - **Silently skipped** (notes emit only under
    `NETWORK_FILTER_VERBOSE=1`): hostname entries
    (`api.mailgun.net`, `hooks.slack.com`, etc.); wildcard
    hostnames (`*.cloudflare-dns.com`); the `*` deny-all pattern
    (would break DNS through pasta's proxy — use
    `NETWORK_FILTER_MODE=isolated` for hard deny-all).

  **Why no nftables?** An earlier v1.1 draft used a generated
  nftables ruleset inside the netns to express CIDR + resolved-IP
  rules. The simpler design — pasta `-T/-U` port exclusions — was
  picked because (a) the identity-hijack threat is closed by
  port-class closure alone, (b) hostname-resolution-to-IPs was
  already best-effort under nft (IPs rotate; v1.2 L7 work is the
  correct fix), and (c) nft is one runtime dependency we don't
  need to add for the threat surface we cover. The honest
  enforcement scope is the same either way.

- **Network filter — optional default-deny outbound network layer
  with strict-mode enforcement.** Closes the local-MTA identity-hijack
  class that filesystem-level binary blocks cannot reach. The
  abandoned `BLOCK_USER_MAIL` binary-overlay approach is gone — a
  motivated agent inside the sandbox can speak SMTP from any
  TCP-capable language (`bash /dev/tcp/127.0.0.1/25`, Python
  `smtplib`, `nc`, …) and bypass the binary block trivially;
  empirically verified on a shared-HPC compute node where the local
  MTA accepts unauthenticated submission. The fix is to deny the
  TCP path itself at a layer the agent cannot escape.

  **Configuration surface (new):**
  - `NETWORK_FILTER_MODE` (default `filtered`) — `open` | `filtered`
    | `isolated`. `open` = current behaviour (host network shared);
    `filtered` = netns (Linux network namespace — a per-process
    isolated network stack) + helper applying the default-deny floor
    plus user/admin `NETWORK_BLOCKLIST`; `isolated` = netns with no
    network at all.
  - `NETWORK_FILTER_FALLBACK` (default `stricter`) — `strict`
    | `stricter` | `open`. Picks what happens when the requested
    mode can't be delivered on the host (helper missing, kernel too
    old, landlock-only environment). `strict` fails loudly;
    `stricter` falls back ONLY to a MORE-restrictive mode (fails if
    none possible); `open` falls back ONLY to a LESS-restrictive
    mode (never strengthens against user intent — see the
    "less-strict only" sub-bullet below for the rationale).
  - `NETWORK_BLOCKLIST` — host:port / CIDR:port / port / wildcard
    (`*.example.com`, `*`) patterns, additive to the shipped
    `sandbox.conf` floor. Admin entries become a floor user config
    cannot remove.
  - `NETWORK_BLOCKLIST_EXCEPT` — exception list that carves holes in
    `NETWORK_BLOCKLIST` under most-specific-rule-wins precedence
    (see "Wildcard patterns + exception list" sub-bullet). User
    entries covered by any admin-set `NETWORK_BLOCKLIST` are
    stripped at config-load with a loud warning (admin policy is
    absolute).
  - **Floor lives in `sandbox.conf` skel, not `sandbox-lib.sh`.**
    The full identity-bound exfil + lateral-movement surface ships
    as the default `NETWORK_BLOCKLIST=(…)` in the shipped
    `sandbox.conf` so an operator editing their config sees the
    policy directly and can comment-out entries that don't apply.
    `sandbox-lib.sh::_NETWORK_BLOCKLIST_DEFAULTS=()` is now an empty
    sentinel; the floor is just user config. Categories:
      * mail submission ports (24/25/465/587/2525) on loopback and
        outbound to any external MTA (universal — uncommented);
      * Fred Hutch campus mail-relay CIDR `140.107.0.0/16` on the
        same ports (site-specific — **commented out by default**;
        uncomment for FH gizmo and similar campus-trust networks);
      * transactional-email HTTPS APIs (Mailgun, SendGrid, Postmark,
        Resend, Amazon SES) (universal);
      * webhook-as-mail surfaces (Slack, Discord, Teams via Power
        Automate, IFTTT Maker, request-inspecting endpoints)
        (universal);
      * anonymous file-drop endpoints (transfer.sh, file.io, 0x0.st,
        catbox.moe, bashupload.com) (universal);
      * public paste services (pastebin.com, 0bin.net) (universal);
      * DoH resolvers (cloudflare-dns.com, dns.google, dns.quad9.net,
        mozilla.cloudflare-dns.com) + DoT port 853 (universal);
      * legacy r-services (telnet 23, finger 79, ident 113, rexec
        512, rlogin 513, rsh/syslog 514) (universal);
      * SMB/CIFS (139, 445), RDP (3389), VNC (5900–5905)
        (site-specific — **commented out by default**; uncomment
        if no legitimate sandboxed workload needs these);
      * LDAP (389, 636, 3268, 3269) and Kerberos (88, 464)
        (site-specific — commented out by default);
      * Slurm controller/d/dbd (6817–6819) and munge TCP (904)
        (site-specific — commented out by default).
    Each entry carries a one-line rationale comment. Site-specific
    entries are commented by default and clearly annotated; an
    operator on a matching deployment uncomments what applies.

  - **Wildcard patterns + exception list (`NETWORK_BLOCKLIST_EXCEPT`).**
    Blocklist entries can be bash-glob wildcards (`*.example.com`,
    `*`) or CIDR ranges or bare ports. A companion
    `NETWORK_BLOCKLIST_EXCEPT` list carves holes in the blocklist
    under a most-specific-rule-wins precedence model: exact host
    overrides wildcard, more-specific CIDR overrides broader CIDR,
    etc. The "implicit-allowlist" idiom `NETWORK_BLOCKLIST=("*")` +
    `NETWORK_BLOCKLIST_EXCEPT=("github.com" "api.openai.com" …)`
    gives deny-by-default semantics for power users; the default
    deployment remains deny-by-blocklist (no allowlist required).

  - **Admin precedence absolute.** User
    `NETWORK_BLOCKLIST_EXCEPT` entries covered by any admin-set
    `NETWORK_BLOCKLIST` entry (under bash-glob semantics) are
    stripped at config-load with a loud warning. Admin policy
    cannot be carved out by users — same precedence model as
    `PRIVATE_TMP` / `FILTER_PASSWD`. Both admin and user can have
    `NETWORK_BLOCKLIST_EXCEPT` entries; only admin's are absolute.

  - **`NETWORK_FILTER_FALLBACK=open` semantics — less-strict only.**
    The `open` policy now falls back ONLY to a less-restrictive
    mode than requested (never to a stricter one — that's what
    `stricter` is for). Probe order: most-strict-of-the-less-strict
    first (`isolated` requested + `open` policy + bwrap-with-helper
    → falls to `filtered`; same configuration without helper →
    falls to `open` directly). Names match user intent:
    `strict`=never fall, `stricter`=OK to strengthen,
    `open`=OK to weaken.

  - **Resolver pinning is not needed.** Empirically verified on a
    representative HPC node: `/etc/resolv.conf` is a 644 symlink to
    a root-owned target, RO to unprivileged users; `/etc/hosts` and
    `/etc/nsswitch.conf` same. Inside the sandbox `/etc` is
    bind-mounted read-only via `READONLY_MOUNTS`. The
    application-level resolver-evasion surface (Python `dnspython`,
    Go `net.Resolver`, Rust `hickory-dns`, etc.) is what matters,
    and is covered by the DoH-hostname + DoT-port (853) block in
    the default floor.
  - **Initialisation safety:** `NETWORK_BLOCKLIST=()` ships as a
    declared empty indexed array in the lib defaults, and the var
    is registered in `_CONFIG_ARRAYS` so `_load_untrusted_config`
    serialises the parent's empty array into the subprocess before
    any conf.d/*.conf runs. A user's `NETWORK_BLOCKLIST+=("foo:25")`
    in `conf.d/` loads cleanly under `set -u` and the entry lands in
    `effective_network_blocklist`. New regression test in section
    11.4 exercises this end-to-end.

  **Per-backend support in this release:**
  - **bwrap** — `open` and `isolated` (via native `--unshare-net`)
    deliver fully; `filtered` is gated behind
    `NETWORK_FILTER_ENABLE_HELPER_PROBE=1` because the bwrap + pasta
    + nft chain that wires real per-port filtering is reserved for
    v1.1. Default `filtered + stricter` therefore falls back to
    `isolated` with a loud startup warning enumerating every fix
    path.
  - **firejail** — `open` and `isolated` (via `--net=none`); the
    `--netfilter` integration for `filtered` is v1.1.
  - **landlock** — `open` only; no mount or network namespace
    available. `stricter` fallback fails with the explicit
    fix-path enumeration; `open` policy falls back to host network
    with the same loud warning.

  Admin enforcement: `NETWORK_FILTER_MODE`, `NETWORK_FILTER_FALLBACK`,
  `NETWORK_BLOCKLIST`, and `NETWORK_BLOCKLIST_EXCEPT` follow the
  existing admin-vs-user precedence model (`PRIVATE_TMP`,
  `FILTER_PASSWD`, etc.) — admins can pin; users can only request
  equal or stricter values; users cannot remove admin-set blocklist
  entries, and any user exception covered by an admin blocklist
  entry (under bash-glob semantics) is stripped at config-load with
  a loud warning.

  Helper distribution: `tools/pasta/fetch.sh` ships a build-from-
  source recipe for `pasta` (passt project, BSD-3-Clause arm — no
  source-offer obligation, no third-party deps beyond libc, single
  ~1–1.5 MB musl-static binary). PATH-detected `pasta` /
  `tools/pasta/pasta` / `slirp4netns` is the resolved priority order
  once the helper-probe gate flips in v1.1.

  Documentation: new `docs/reference/network-filter.md` covering the
  threat model, mode + fallback matrix, configuration syntax, helper
  install paths, per-backend support table, and troubleshooting.
  Cross-linked from the Reference nav.

  Tests: new `test.sh` section 11.4 covering every directive
  shipped in this PR:
  - resolver unit tests (defaults, all fallback policies on every
    backend, the strict-fails path, the stricter-has-no-stricter-
    on-landlock path);
  - the `open` policy never falls to a stricter mode than requested
    (regression guard for the less-strict-only rule);
  - the shipped `sandbox.conf` floor — every universal category is
    asserted PRESENT in `effective_network_blocklist`, every
    site-specific category is asserted ABSENT (regression guard
    against accidental uncomment-in-skel);
  - integration: `isolated` mode blocks `bash /dev/tcp/127.0.0.1/25`
    and Python `smtplib`;
  - positive-path: `open` mode keeps DNS resolution + HTTPS to
    `github.com` / `pypi.org` reachable;
  - `sandbox-notify` carve-out verified (uses `/dev/tty` + tmux
    IPC, unaffected by netns isolation);
  - conf.d/*.conf safety: `NETWORK_BLOCKLIST+=()` loads cleanly
    under `set -u` with the new vars properly initialised
    upstream of project-config load;
  - wildcard pattern matching (`*.suffix` / exact / `*`) behaves
    as documented;
  - admin-precedence: user exceptions covered by admin blocklist
    are stripped with the expected warning;
  - `effective_network_exception_list` emits the merged exceptions.

  Tracking: settylab/dotto-nexus#117. Previous binary-only PR closed
  per user direction; this layer is the actual fix.

## [0.9.0] - 2026-05-10

### Security

- **bwrap: deny `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)` via seccomp
  arg-inspection.** Closes the same-session keystroke-injection
  primitive (CVE-2017-5226 family — TIOCSTI, CVE-2023-1523 —
  TIOCLINUX). On every kernel that still permits these ioctls
  (`CONFIG_LEGACY_TIOCSTI=y` LTS kernels before 6.2, and 6.2+ with
  `dev.tty.legacy_tiocsti=1` active), a sandboxed agent sharing the
  user's controlling pty could push attacker-chosen characters into
  the outer shell's input queue with `ioctl(fd, TIOCSTI, byte)` —
  bytes that execute at host privilege the moment the user touches
  the terminal. The seccomp generator now folds an arg-inspection
  chain into the `ioctl` syscall: loads the low 32 bits of
  `args[1]`, masks for 32-bit cmd values (forecloses the high-bit
  bypass class behind CVE-2019-10063), rejects the x32 ABI on
  x86_64, and returns `EPERM` on TIOCSTI and TIOCLINUX cmds.
  **Scope:** blocks the direct `ioctl(TIOCSTI)` primitive from
  inside the sandbox. The cross-pane variant — a sandboxed process
  using `tmux send-keys` to inject into a sibling tmux pane via the
  user's tmux AF_UNIX socket — is a different attack class and is
  outside this PR's scope. Source:
  [`nikvdp/cco@9744b9f` `seccomp/tiocsti_filter.c`](https://github.com/nikvdp/cco/blob/9744b9fce8f8db1deae20be4dfe430b7a05c2f53/seccomp/tiocsti_filter.c)
  ([`nikvdp/cco#14`](https://github.com/nikvdp/cco/pull/14)),
  MIT-licensed; AS folds the same BPF shape into its existing Python
  `generate-seccomp.py` rather than vendoring the C source. (#49)

### Added

- **Probe-and-explain bwrap startup** — when the bwrap backend
  cannot start, agent-sandbox now classifies the failure (missing
  binary, version-too-old, AppArmor/LSM userns block,
  `No permitted_caps`, clone EPERM, mount-namespace denial, or
  unknown) by parsing bwrap's stderr and prints an actionable
  explanation alongside the existing host/kernel/LSM diagnostic.
  The reason token also feeds the auto-mode `Tried:` table so a
  user staring at "no sandbox backend available" sees, for
  example, `bwrap — blocked by AppArmor / LSM userns restriction`
  rather than a generic `failed (check user namespace support)`.
  Closes the support loop today routed through
  `docs/admin/sandbox-help.md` for users who can't read dmesg. New
  section "bwrap startup errors" in the help doc cross-references
  each pattern. Source:
  [`nikvdp/cco@9744b9f` `cco:148-162`](https://github.com/nikvdp/cco/blob/9744b9fce8f8db1deae20be4dfe430b7a05c2f53/cco#L148-L162)
  (commit
  [`8c2cecf`](https://github.com/nikvdp/cco/commit/8c2cecfc89ea0ef8e0f55ad11b5c88f1815614a9)),
  MIT-licensed; AS extends cco's 2-mode classifier (AppArmor uid-map
  vs. first-stderr-line fallback) to 7-mode + unknown-pattern
  fallback. (#48)
- **Landlock ABI hard-requirement probe.** The Landlock helper now
  refuses to start (default-on, knob-controlled) when the running
  kernel's Landlock ABI is below what AS's policy relies on. ABI v1
  (RHEL 8, Ubuntu 22.04 GA — kernel ~5.13–5.15) silently drops
  `LANDLOCK_ACCESS_FS_REFER` (`rename`/`link` can cross sandbox rule
  boundaries) and `LANDLOCK_ACCESS_FS_TRUNCATE` (`ftruncate(2)` on a
  read-only mount succeeds even when `WRITE_FILE` is denied —
  silent zeroing of files the operator believes are read-only); ABI
  v2 (5.19–6.1) drops `TRUNCATE`. Previously the helper quietly
  scaled the rights bitmask down to match the advertised ABI;
  `--check` reported `landlock: ABI vN` and exited 0 regardless,
  leaving admins on stale HPC nodes convinced their `--ro` mounts
  were enforced when they weren't. New `LANDLOCK_HARD_REQUIREMENT`
  knob (default `on`; set `off` for legacy-kernel sites that
  knowingly accept the degraded surface) makes the gap loud. Probe
  is exercised by a `LANDLOCK_FAKE_ABI` test seam plus
  `tests/test_landlock_abi_probe.sh`. (#47)
- **`BLOCKED_ENV_PATTERNS` defaults broadened — `AWS_*`, `AMAZON_*`,
  `EC2_*`, `MSAL_*`, `VAULT_*`.** A single prefix per cloud provider
  sweeps a long tail of env vars that previously slipped through
  the pattern list and were not in the explicit `BLOCKED_ENV_VARS`
  array. Most importantly, `AWS_SECRET_ACCESS_KEY` (matched none of
  the credential-suffix globs — `*_TOKEN`, `*_SECRET`, `*_API_KEY`
  — and was absent from `BLOCKED_ENV_VARS`, which only carried
  `AWS_ACCESS_KEY_ID` / `AWS_SESSION_TOKEN`); also `AWS_PROFILE`,
  `AWS_DEFAULT_REGION`, `AMAZON_*`, `EC2_*`, `MSAL_*`,
  `VAULT_ADDR`, `VAULT_NAMESPACE`. Probed against 33 representative
  cloud-provider env vars on the unmodified defaults: 7 leaked
  pre-patch, 0 post-patch. `ALLOWED_ENV_VARS` remains the per-key
  opt-in escape hatch for benign vars (e.g. `AWS_DEFAULT_REGION`)
  that a workflow legitimately needs inside the sandbox. Source:
  [`bindsch/scode`](https://github.com/bindsch/scode) `scode:113-158`
  env-scrub wildcard set — the `AWS_*` prefix is lifted from there;
  `AMAZON_*`, `EC2_*`, `MSAL_*`, and `VAULT_*` are adjacent
  expansions. (#46)
- `test-admin-narrowing.sh` — unit tests for the narrowing merge,
  the missing-vs-malformed admin-config boundary, the `/foo` vs
  `/foobar` path-component trap, and symlink-escape rejection. The
  tests use a `_SANDBOX_LIB_NO_INIT=1` test-harness seam in
  `sandbox-lib.sh` so they run without root or a deployed admin
  install.
- `test.sh` — regression cases for failure modes documented by
  `anthropic-experimental/sandbox-runtime` issues that don't
  translate to AS today but should stay broken if the assumption
  shifts. (1) `HOME_SEEDED_FILES (symlink)` proves a symlinked
  `~/.gitconfig` is seeded by content (not by bind-mounting the
  symlink, which fails on bwrap with ENOTSUP) — the
  sandbox-runtime#185 shape. (2) Missing-SANDBOX_CONF probe asserts
  the credential-dir hide stays in effect when the config file is
  absent — sandbox-runtime#122/#211 shape (fail-closed reads, not
  silent fall-through to permissive defaults).
- `test.sh` `S05` — regression case for the symlinked-ancestor
  `BLOCKED_FILES` bypass. Proves the leaf is unreadable when the
  agent accesses via the symlinked path.
- `docs/reference/security.md` — new "Tamper resistance" section
  documenting the no-in-process-bypass property: once the sandbox
  is up, the agent inside cannot weaken isolation (no
  `dangerouslyDisableSandbox`-style knob, irrevocable mount/PID/
  seccomp/Landlock state). Names this as a deliberate design
  property rather than an implementation detail. Surfaced by the
  triage of `anthropic-experimental/sandbox-runtime` issues #13 /
  #97 (`settylab/dotto-nexus#103`) where agents were instructed to
  "retry with sandbox disabled" on permission denials.
- `docs/reference/security.md` — new "Cooperative reinforcement"
  section documenting the per-agent `agent.md` injection that
  merges a Sandbox Integrity block into each agent's instruction
  file at spawn time (`agents/<name>/overlay.sh`). Names this as
  defense in depth on top of kernel-enforced isolation: a
  cooperating agent stops wasting turns trying to "fix" denials,
  and any contrary instruction becomes a recognizable prompt-
  injection signal with a documented `logger`/mail response
  recipe. Explicitly not a primary defense — the kernel layer
  contains the sandbox; the injection is for normal operation
  and observability.

### Changed

- **Breaking (admin-mode only):** `ALLOWED_PROJECT_PARENTS` admin/user
  merge is now **narrowing-only**. Previously the user config could
  ADD project parents to admin's list (additive merge); now the user
  can only NARROW admin's list. A user-supplied path is admissible
  iff its canonical resolution (via `realpath`) is identical to or a
  path-component subdir of the canonical resolution of one of admin's
  allowed parents. Symlinks that escape admin's tree are rejected.
  In absence of an admin specification we assume `/` (no narrowing),
  preserving the user-only-install path. User-only installs without
  an admin baseline are unaffected.
- **Admin-config parse errors fail closed.** A malformed admin
  `sandbox.conf` (syntax error, runtime error during source, or a
  malformed `ALLOWED_PROJECT_PARENTS` — non-array, non-absolute paths,
  command substitution) now refuses sandbox startup with a clear
  error rather than falling through to a permissive default. The
  missing-vs-malformed boundary is explicit: a missing admin file
  defaults to `/`; a present-but-malformed admin file fails closed.
- If the admin/user merge yields an empty `ALLOWED_PROJECT_PARENTS`
  (e.g. the user requested only paths outside admin's tree, or
  cleared the array), the sandbox refuses to start instead of
  silently continuing with no admissible project locations.

### Fixed

- **bwrap: `BLOCKED_FILES` bypass when an ancestor is a symlink.**
  Previously `backends/bwrap.sh` resolved the leaf via `readlink -f`
  and bound `/dev/null` only on the resolved path. When a path
  component lived inside a writable bind (e.g. `~/.claude` is in
  `HOME_WRITABLE` and exists on the host as a symlink to
  `~/dotfiles/claude/`), the agent could read or write the file via
  the symlinked path because mount overlays are path-keyed, not
  inode-keyed — the resolved-path mount never applied. Fix: bind
  `/dev/null` at the literal leaf path in addition to the resolved
  path. Both binds are emitted unless they collapse to the same
  path. See `settylab/dotto-nexus#103` for the comparison report
  that surfaced this gap.

## [0.8.0] - 2026-05-05

### Added

- Documentation site at https://katosh.github.io/agent_sandbox/.
  Built with mkdocs-material and auto-deployed to GitHub Pages on
  every push to `main`. The README is now a tight front page with a
  prominent disclaimer; the full configuration reference, security
  model, HPC integration guide, troubleshooting, and admin install
  paths live on the site.

### Fixed

- `install.sh` step-list text was inconsistent between the header
  comment and the `--help` output (the header had a duplicated step,
  `--help` skipped step 5 entirely). Both blocks now agree on six
  steps and both name the Pi agent profile and the `conf.d/`
  directory.

### Removed

- Removed the eBPF/SPANK admin-hardening construct (the `slurm-enforce/`
  subsystem and its `SANDBOX_BYPASS_TOKEN` / `TOKEN_FILE` integration
  in the sandbox). The chaperon has been the supported boundary for
  sandboxed agent Slurm calls since v0.5; the token construct was
  largely superseded on bwrap/firejail and partial on Landlock, and
  shipping it alongside the chaperon doubled the surface admins had
  to reason about. Sites that depended on the eBPF/SPANK layer can
  pin to v0.7.0. Affected surfaces: `slurm-enforce/` directory
  (deleted), `SANDBOX_BYPASS_TOKEN` defaults / snapshot / restore
  paths in `sandbox-lib.sh`, the bypass-token hide in
  `backends/{bwrap,firejail}.sh`, the `TOKEN_FILE` example in
  `sandbox-admin.conf`, and the corresponding tests in `test.sh` /
  `test-admin.sh`. `sbatch-sandbox.sh` / `srun-sandbox.sh` no longer
  source the admin config to look up `REAL_SBATCH` / `REAL_SRUN`.

## [0.7.0] - 2026-05-05

### Removed

- Removed unused host-library configuration surface. The sandbox no
  longer materializes a private symlink dir of host driver libraries
  or prepends one to `LD_LIBRARY_PATH`. Stale entries in user configs
  are silently ignored with the existing unknown-variable warning.
  The literal NVIDIA device-node default
  `DEVICES=(/dev/nvidia* /dev/nvidia-uvm /dev/nvidia-uvm-tools
  /dev/nvidia-modeset /dev/nvidiactl)` is unchanged.

## [0.6.1] - 2026-05-05

### Fixed

- **`BIND_DEV_PTS=true` is now a kernel-aware no-op on kernel >= 5.4.**
  v0.6.0 shipped the deprecation shim as an unconditional
  `DEVICES+=(/dev/pts)`. On kernel >= 5.4 bwrap auto-mounts a working
  user-namespace devpts, and binding the host `/dev/pts` on top
  shadows it with `ptmxmode=000` — pty allocation silently breaks
  (`tmux` exits "create session failed"; `script(1)` reports
  "Permission denied"). The default `DEVICES_BLACKLIST` masks this
  for fresh installs, but the trap fires on migration paths from
  v0.4.x configs that set `BIND_DEV_PTS=true` AND override
  `DEVICES_BLACKLIST` without copying the upstream defaults. The
  shim now splits on `uname -r`: kernel >= 5.4 logs a "no-op, drop
  the line" notice and declines to append; kernel < 5.4 keeps the
  historical behaviour.

  An explicit `DEVICES+=(/dev/pts)` on kernel >= 5.4 also now emits
  a stderr warning at every spawn explaining the same shadowing
  trap. The entry is preserved (we do not override explicit user
  intent), but the user is told why their tmux is broken instead of
  silently puzzling over "Permission denied". New `_kernel_at_least`
  helper in `sandbox-lib.sh` for downstream use. Tests `DEV08` /
  `DEV09` / `DEV10` cover the no-op branch, the helper itself, and
  the shadow warning; `DEV06` mocks `uname` via a PATH shim so the
  legacy < 5.4 branch is exercised on kernel-6 CI runners. See
  [DEVICE_PASSTHROUGH.md](docs/reference/device-passthrough.md). PR #18.

## [0.6.0] - 2026-05-04

### Added

- **`DEVICES` — targeted /dev passthrough with NVIDIA defaults +
  admin-enforceable `DEVICES_BLACKLIST`.** Replaces the binary
  `BIND_DEV_PTS` toggle. The bwrap backend now starts with the
  minimal devtmpfs (`bwrap --dev /dev`) and bind-mounts only the
  nodes listed in `DEVICES`. Globs in `DEVICES` expand against the
  host `/dev` at sandbox spawn — `/dev/nvidia*` defaults are a
  no-op on CPU-only hosts. `DEVICES_BLACKLIST` is in
  `_ENFORCED_ARRAYS`: users add but never remove admin-set entries.
  Defaults block `/dev/mem`, `/dev/kmem`, `/dev/port`, `/dev/pts`
  (TIOCSTI on kernel < 6.2), `/dev/sd*`, `/dev/nvme*`, `/dev/loop*`.

  Closes the GPU-vs-TIOCSTI dilemma: pre-this-change, exposing
  `/dev/nvidia*` required `BIND_DEV_PTS=true`, which also exposed
  `/dev/pts` and on kernel < 6.2 left the sandbox usable for
  TIOCSTI keystroke injection into the user's other terminals.
  Now NVIDIA passthrough works without any pty exposure.

  Migration: `BIND_DEV_PTS=true` is rewritten to
  `DEVICES+=(/dev/pts)` at config-load time with a deprecation
  notice; the admin blacklist still applies. See
  [DEVICE_PASSTHROUGH.md](docs/reference/device-passthrough.md) for the full
  design and [sandbox.conf](sandbox.conf) for the user template.
  PR #14.

- **Rust + common dev-tool cache dirs in `HOME_READONLY` defaults.**
  The shipped `sandbox.conf` template now includes `.cargo`, `.rustup`,
  `.npm`, and `go` as active read-only entries — a fresh install
  gives the agent visibility of pre-installed Rust toolchains and
  cached deps without hand-editing. Commented opt-in entries cover
  `.gem`, `.gradle`, `.m2`, `.julia`, `.tox`, `.pyenv`, `.bun`,
  `.yarn`, `.pnpm-store`. Read-only by design (matches the existing
  `.linuxbrew`/`micromamba` convention); writable promotion or a
  separate `~/.cache/<tool>` writable subdir documented in the
  config comments. Library defaults in `sandbox-lib.sh` left
  unchanged so existing users with no `sandbox.conf` see no
  behaviour change. `sandbox.conf`. PR #13.

### Deprecated

- **`BIND_DEV_PTS=true`** scalar is deprecated in favour of
  `DEVICES+=(/dev/pts)`. A back-compat shim rewrites the legacy
  value to the `DEVICES` array entry at config-load time with a
  stderr warning; the admin `DEVICES_BLACKLIST` still applies on
  locked-down installs (so `BIND_DEV_PTS=true` becomes a logged
  no-op there, which is a strict security improvement over the old
  bypass behaviour). Migration table in the v0.6.0 PR #14 body and
  in [DEVICE_PASSTHROUGH.md](docs/reference/device-passthrough.md).

### Fixed

- **`test.sh` S02 symlink-bypass test is now config-aware.** The S02
  case (symlink in `PROJECT_DIR` pointing at `~/.ssh`) used to assert
  BLOCKED unconditionally, false-failing for users who intentionally
  expose `~/.ssh` via `HOME_READONLY` / `HOME_WRITABLE` — the same
  config-blind shape that PR #8 fixed for the credential-block tests.
  S02 now consults `_home_dir_intentional ".ssh"`: default-deny still
  asserts BLOCKED (real symlink bypass would leak `id_rsa`), but
  opt-in users now assert VISIBLE — the symlink correctly reflects
  the exposure, which is the desired behaviour for that config.
  `test.sh`.

## [0.5.0] - 2026-04-29

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

### Added

- **`HOME_SEEDED_FILES` config knob — writable per-session copies of
  host dotfiles.** Until now `~/.gitconfig` lived in `HOME_READONLY`
  and was bind-mounted read-only inside the sandbox, so anything that
  wrote to it (`gh auth setup-git`, `git config --global`, IDE git
  plugins) failed with `Device or resource busy`. The new
  `HOME_SEEDED_FILES` array reads the file's content from the host
  but seeds it into the per-session tmpfs `$HOME` as a writable copy:
  the agent can edit it freely, writes are discarded on sandbox exit,
  and the real host file is never modified. `bwrap` implements this
  natively via `--file FD DEST` (full support); `firejail` and
  `landlock` lack the primitives for a writable per-session copy and
  degrade to read-only with a one-time stderr warning. Conflict rule:
  an entry in `HOME_SEEDED_FILES` wins over the same entry in
  `HOME_READONLY`. Default: `HOME_SEEDED_FILES=(".gitconfig")`.
  `backends/bwrap.sh`, `backends/firejail.sh`, `backends/landlock.sh`,
  `sandbox-lib.sh`, `sandbox.conf`, `test.sh`.

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

- **sacct: accept self-scoped `--user` / `--me` / `--uid` instead
  of bouncing them.** The chaperon already auto-injects
  `--user=$(whoami)`, so passing `--user $USER`, `--user=$USER`,
  `--me`, or `--uid $(id -u)` is semantically a no-op — but the old
  flat deny phrased as "not allowed for security" caused agents to
  abandon valid `sacct` calls instead of just dropping the
  redundant flag. Now self-scoped values are silently accepted and
  dropped from the forwarded argv (no duplicate `--user` reaches
  real sacct); only cross-user values are denied, and the new
  message leads with the actionable fix ("drop the flag, or pass
  `--me`") rather than the security framing. `--me` is also
  added to the allow-list. `chaperon/handlers/sacct.sh`,
  `test.sh` (5i/5o), `CHAPERON.md`, `README.md`.

- **`test.sh` credential-block tests are now config-aware.** The
  `~/.ssh` quick-mode block and the full-mode `test_blocked_dir`
  helper used to assert BLOCKED/HIDDEN unconditionally, which
  false-failed for users who intentionally expose `~/.ssh`,
  `~/.aws`, or `~/.gnupg` in their sandbox config (legitimate
  use cases — e.g. git-push or `aws ecr login` from inside the
  sandbox). The tests now consult `HOME_READONLY` / `HOME_WRITABLE`
  in the loaded config (`$SANDBOX_CONF`) and assert VISIBLE for
  opt-in entries, BLOCKED otherwise — validating both the
  default-deny posture and the config-driven exposure plumbing.
  Quick-mode also now loops over all three credential dirs
  instead of just `~/.ssh`. `test.sh`.

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
