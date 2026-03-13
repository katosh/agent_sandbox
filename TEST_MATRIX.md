# Sandbox Test Matrix and Escape Attempt Catalogue

This document covers the multi-level config system in `sandbox-lib.sh`,
all three backends (bwrap, firejail, landlock), and creative escape attempts
an agent might try against the sandbox.

---

## How to Run Tests

Tests run on an Ubuntu Lima VM. Access via:

```bash
limactl shell ubuntu -- bash -c '...'
```

or SSH into the VM directly.

**Layout:**

- Admin install at `/app/lib/agent-sandbox/`, symlink at `/app/bin/sandbox-exec`
- User data at `~/.claude/sandbox/` (user.conf, conf.d/)

**Test pattern:** each test writes a user.conf, runs the sandbox, checks output, and cleans up.

```bash
# Write test user.conf
cat > ~/.claude/sandbox/user.conf << 'CONF'
BLOCKED_ENV_VARS=()
CONF

# Run and capture stderr
output=$(/app/bin/sandbox-exec -- bash -c 'echo ${GITHUB_TOKEN:-UNSET}' 2>&1)

# Check
echo "$output" | grep -q "WARNING.*removed.*BLOCKED_ENV_VARS" && echo "PASS: warning emitted" || echo "FAIL: no warning"
echo "$output" | grep -q "UNSET" && echo "PASS: token blocked" || echo "FAIL: token leaked"

# Clean up
rm ~/.claude/sandbox/user.conf
```

---

## OUTPUT 1: Test Matrix

### Category A — Admin Config Enforcement (Enforced Arrays)

These arrays must survive user config tampering: `BLOCKED_FILES`,
`BLOCKED_ENV_VARS`, `EXTRA_BLOCKED_PATHS`.

---

**T01**
- **Category**: Admin enforcement — BLOCKED_ENV_VARS removal
- **Description**: User config explicitly sets `BLOCKED_ENV_VARS=()`, clearing the admin list.
- **Admin config snippet**:
  ```bash
  BLOCKED_ENV_VARS=("GITHUB_TOKEN" "AWS_SECRET_ACCESS_KEY")
  ```
- **User config snippet**:
  ```bash
  BLOCKED_ENV_VARS=()
  ```
- **Expected behavior**: Post-merge `BLOCKED_ENV_VARS` still contains both admin entries. Warning printed to stderr: `WARNING: User config removed admin-enforced BLOCKED_ENV_VARS entry 'GITHUB_TOKEN' — restored.`
- **How to verify**: After sourcing sandbox-lib.sh, `printf '%s\n' "${BLOCKED_ENV_VARS[@]}" | grep -c GITHUB_TOKEN` equals 1. Inside a running sandbox, `echo ${GITHUB_TOKEN:-UNSET}` prints `UNSET`.

---

**T02**
- **Category**: Admin enforcement — BLOCKED_ENV_VARS removal by reassignment
- **Description**: User config reassigns the array using declare syntax to bypass the simple `=` check.
- **Admin config snippet**:
  ```bash
  BLOCKED_ENV_VARS=("ANTHROPIC_API_KEY")
  ```
- **User config snippet**:
  ```bash
  declare -a BLOCKED_ENV_VARS=()
  ```
- **Expected behavior**: Admin entry restored by `_enforce_admin_policy` (compares against admin snapshot, merges back missing entries). Warning emitted.
- **How to verify**: `printf '%s\n' "${BLOCKED_ENV_VARS[@]}"` contains `ANTHROPIC_API_KEY`.

---

**T03**
- **Category**: Admin enforcement — BLOCKED_ENV_VARS additive user addition preserved
- **Description**: User config adds an extra token to block. The admin entry must survive and the user addition must be kept.
- **Admin config snippet**:
  ```bash
  BLOCKED_ENV_VARS=("GITHUB_TOKEN")
  ```
- **User config snippet**:
  ```bash
  BLOCKED_ENV_VARS+=("MY_LAB_API_KEY")
  ```
- **Expected behavior**: Final array contains both `GITHUB_TOKEN` and `MY_LAB_API_KEY`. No warnings emitted.
- **How to verify**: Array length ≥ 2; both entries present.

---

**T04**
- **Category**: Admin enforcement — BLOCKED_FILES removal
- **Description**: User config empties `BLOCKED_FILES` to expose an admin-blocked credential file.
- **Admin config snippet**:
  ```bash
  BLOCKED_FILES=("$HOME/.netrc")
  ```
- **User config snippet**:
  ```bash
  BLOCKED_FILES=()
  ```
- **Expected behavior**: `BLOCKED_FILES` is restored to contain `$HOME/.netrc`. Warning emitted.
- **How to verify**: Inside bwrap sandbox, `cat ~/.netrc` returns empty (overlaid with `/dev/null`).

---

**T05**
- **Category**: Admin enforcement — EXTRA_BLOCKED_PATHS removal
- **Description**: User config removes an admin-blocked sensitive data path.
- **Admin config snippet**:
  ```bash
  EXTRA_BLOCKED_PATHS=("/fh/fast/lab/restricted_clinical_data")
  ```
- **User config snippet**:
  ```bash
  EXTRA_BLOCKED_PATHS=()
  ```
- **Expected behavior**: Path is restored into `EXTRA_BLOCKED_PATHS`. Warning emitted.
- **How to verify**: Inside bwrap sandbox, `ls /fh/fast/lab/restricted_clinical_data` returns empty (tmpfs overlay); path appears to exist but is empty.

---

**T06**
- **Category**: Admin enforcement — BLOCKED_FILES user addition preserved
- **Description**: User config adds an extra file to block. Both entries should survive policy enforcement.
- **Admin config snippet**:
  ```bash
  BLOCKED_FILES=("$HOME/.netrc")
  ```
- **User config snippet**:
  ```bash
  BLOCKED_FILES+=("$HOME/.my-personal-secret")
  ```
- **Expected behavior**: Both entries present in final `BLOCKED_FILES`. No warnings.
- **How to verify**: Both files overlaid with `/dev/null` inside the sandbox.

---

**T07**
- **Category**: Admin enforcement — duplicate detection (no double-add)
- **Description**: User config += adds an entry that is already in the admin array. Entry must not be duplicated.
- **Admin config snippet**:
  ```bash
  BLOCKED_ENV_VARS=("GITHUB_TOKEN")
  ```
- **User config snippet**:
  ```bash
  BLOCKED_ENV_VARS+=("GITHUB_TOKEN")
  ```
- **Expected behavior**: `GITHUB_TOKEN` appears exactly once in the final array.
- **How to verify**: `printf '%s\n' "${BLOCKED_ENV_VARS[@]}" | grep -c '^GITHUB_TOKEN$'` equals 1.

---

### Category B — HOME_READONLY / HOME_WRITABLE Escalation

---

**T08**
- **Category**: HOME_READONLY → HOME_WRITABLE escalation blocked
- **Description**: User config copies an admin-readonly item into HOME_WRITABLE to gain write access to a config file.
- **Admin config snippet**:
  ```bash
  HOME_READONLY=(".gitconfig" ".bashrc")
  ```
- **User config snippet**:
  ```bash
  HOME_WRITABLE+=(".gitconfig")
  ```
- **Expected behavior**: `.gitconfig` removed from `HOME_WRITABLE` during `_enforce_admin_policy`. Warning: `WARNING: User config moved admin HOME_READONLY entry '.gitconfig' to HOME_WRITABLE — reverted.`
- **How to verify**: Final `HOME_WRITABLE` does not contain `.gitconfig`. Inside bwrap, `touch ~/.gitconfig` fails with EROFS.

---

**T09**
- **Category**: HOME_READONLY → HOME_WRITABLE escalation — full replacement of HOME_WRITABLE
- **Description**: User sets `HOME_WRITABLE` to a new array that includes an admin-readonly item, bypassing `+=`.
- **Admin config snippet**:
  ```bash
  HOME_READONLY=(".bashrc")
  HOME_WRITABLE=(".claude" ".claude.json")
  ```
- **User config snippet**:
  ```bash
  HOME_WRITABLE=(".claude" ".claude.json" ".bashrc")
  ```
- **Expected behavior**: `.bashrc` stripped from `HOME_WRITABLE`. All valid entries (`.claude`, `.claude.json`) preserved.
- **How to verify**: `printf '%s\n' "${HOME_WRITABLE[@]}"` does not contain `.bashrc`.

---

**T10**
- **Category**: HOME_WRITABLE additive user addition preserved
- **Description**: User adds a legitimate writable directory that is not in admin's HOME_READONLY.
- **Admin config snippet**:
  ```bash
  HOME_READONLY=(".bashrc" ".gitconfig")
  HOME_WRITABLE=(".claude")
  ```
- **User config snippet**:
  ```bash
  HOME_WRITABLE+=(".my-project-output")
  ```
- **Expected behavior**: `.my-project-output` remains in `HOME_WRITABLE`. No escalation warning.
- **How to verify**: Inside sandbox, `touch ~/.my-project-output/test` succeeds.

---

**T11**
- **Category**: HOME path conflict — item in both HOME_READONLY and HOME_WRITABLE (admin-set)
- **Description**: Admin config itself lists the same path in both arrays (configuration error). Writable mount wins in bwrap (later arg). Warning should be emitted.
- **Admin config snippet**:
  ```bash
  HOME_READONLY=(".cache/claude")
  HOME_WRITABLE=(".cache/claude")
  ```
- **User config snippet**: *(none)*
- **Expected behavior**: `WARNING: $HOME/.cache/claude is in both HOME_READONLY and HOME_WRITABLE (writable wins).`
- **How to verify**: Warning appears on stderr during sandbox startup.

---

### Category C — DENIED_WRITABLE_PATHS Enforcement

---

**T12**
- **Category**: DENIED_WRITABLE_PATHS — EXTRA_WRITABLE_PATHS stripped
- **Description**: User config adds a path that falls under an admin-denied zone to EXTRA_WRITABLE_PATHS.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("/fh/fast/lab/restricted_clinical_data")
  ```
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/lab/restricted_clinical_data/patient_001")
  ```
- **Expected behavior**: Entry stripped from `EXTRA_WRITABLE_PATHS` with warning: `WARNING: ... added EXTRA_WRITABLE_PATHS entry '...' under denied path '...' — removed.`
- **How to verify**: Path not present in final `EXTRA_WRITABLE_PATHS`. Not writable in sandbox.

---

**T13**
- **Category**: DENIED_WRITABLE_PATHS — exact match stripped
- **Description**: User config adds the exact denied path (not a subpath) to EXTRA_WRITABLE_PATHS.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("/fh/fast/lab/restricted_clinical_data")
  ```
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/lab/restricted_clinical_data")
  ```
- **Expected behavior**: Entry stripped. Warning emitted.
- **How to verify**: `printf '%s\n' "${EXTRA_WRITABLE_PATHS[@]}"` is empty (or does not contain the path).

---

**T14**
- **Category**: DENIED_WRITABLE_PATHS — HOME_WRITABLE entry stripped
- **Description**: User adds a HOME_WRITABLE entry that, when expanded with `$HOME`, falls under a denied path.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("$HOME/.ssh")
  ```
- **User config snippet**:
  ```bash
  HOME_WRITABLE+=(".ssh/known_hosts")
  ```
- **Expected behavior**: Entry stripped from `HOME_WRITABLE` with warning.
- **How to verify**: `~/.ssh/known_hosts` not writable inside sandbox.

---

**T15**
- **Category**: DENIED_WRITABLE_PATHS — trailing slash in denied path
- **Description**: Denied path has trailing slash; user path should still match.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("/fh/fast/lab/restricted/")
  ```
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/lab/restricted/subdir")
  ```
- **Expected behavior**: `_ADMIN_DENIED_WRITABLE_PATHS` normalisation strips trailing slash (`_denied="${_denied%/}"`), so match succeeds and entry is stripped.
- **How to verify**: Entry not in final `EXTRA_WRITABLE_PATHS`.

---

**T16**
- **Category**: DENIED_WRITABLE_PATHS — path adjacent to denied path (no false match)
- **Description**: User adds a path that shares a prefix with a denied path but is not under it.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("/fh/fast/lab/restricted")
  ```
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/lab/restricted_other")
  ```
- **Expected behavior**: `/fh/fast/lab/restricted_other` is **not** stripped — it is not under the denied path (boundary check: `"$_item" == "$_denied/"*` requires a `/` separator).
- **How to verify**: Entry remains in `EXTRA_WRITABLE_PATHS`.

---

### Category D — Scalar Protection (TOKEN_FILE, SANDBOX_BYPASS_TOKEN)

---

**T17**
- **Category**: Scalar protection — SANDBOX_BYPASS_TOKEN override by user
- **Description**: User config tries to redirect the bypass token to an attacker-controlled path.
- **Admin config snippet**:
  ```bash
  SANDBOX_BYPASS_TOKEN="/run/slurm/tokens/bypass.tok"
  ```
- **User config snippet**:
  ```bash
  SANDBOX_BYPASS_TOKEN="/tmp/evil/fake.tok"
  ```
- **Expected behavior**: After `_enforce_admin_policy`, `SANDBOX_BYPASS_TOKEN` is restored to the admin value. Warning emitted.
- **How to verify**: `echo "$SANDBOX_BYPASS_TOKEN"` equals the admin path, not `/tmp/evil/fake.tok`. Inside bwrap, `/run/slurm/tokens/bypass.tok` is overlaid with `/dev/null`.

---

**T18**
- **Category**: Scalar protection — TOKEN_FILE override by user
- **Description**: User config sets `TOKEN_FILE` to an empty string to prevent token hiding.
- **Admin config snippet**:
  ```bash
  TOKEN_FILE="/run/slurm/tokens/bypass.tok"
  ```
- **User config snippet**:
  ```bash
  TOKEN_FILE=""
  ```
- **Expected behavior**: After `_enforce_admin_policy`, `TOKEN_FILE` restored. Warning emitted. Token remains hidden.
- **How to verify**: `echo "${TOKEN_FILE}"` equals the admin path.

---

**T19**
- **Category**: Scalar protection — no admin value set, user sets freely
- **Description**: Admin does not set `SANDBOX_BYPASS_TOKEN`. User config sets it. This should be allowed (no admin value to protect).
- **Admin config snippet**: *(no `SANDBOX_BYPASS_TOKEN` line)*
- **User config snippet**:
  ```bash
  SANDBOX_BYPASS_TOKEN="/run/slurm/tokens/bypass.tok"
  ```
- **Expected behavior**: No warning. User's value is used (`_ADMIN_SANDBOX_BYPASS_TOKEN` is empty string, so the restore condition `[[ -n "$_ADMIN_SANDBOX_BYPASS_TOKEN" ]]` is false).
- **How to verify**: `echo "$SANDBOX_BYPASS_TOKEN"` equals the user-specified path.

---

### Category E — HOME Resolution

---

**T20**
- **Category**: HOME resolution — environment HOME override
- **Description**: `$HOME` is set to `/tmp/evil` before the sandbox script runs.
- **Admin config snippet**: *(standard)*
- **User config snippet**: *(none)*
- **Expected behavior**: `sandbox-lib.sh` resolves HOME via `getent passwd "$(id -un)"`, ignoring the environment value. `/tmp/evil` is never used.
- **How to verify**: Inside the sandbox, `echo $HOME` equals the passwd-database home. `_USER_DATA_DIR` path does not contain `/tmp/evil`.

---

**T21**
- **Category**: HOME resolution — HOME unset
- **Description**: `unset HOME` before running the sandbox.
- **Admin config snippet**: *(standard)*
- **User config snippet**: *(none)*
- **Expected behavior**: `getent passwd` resolves HOME. Fallback `HOME="$(cd ~ && pwd)"` (which uses `~` from passwd entry, not `$HOME`) activates if getent fails.
- **How to verify**: Sandbox starts successfully. `echo $HOME` returns a valid directory, not empty.

---

**T22**
- **Category**: HOME resolution — user config sets HOME to evil path
- **Description**: `user.conf` exports `HOME=/tmp/evil` to try redirecting the `_USER_DATA_DIR` computation.
- **Admin config snippet**: *(standard)*
- **User config snippet**:
  ```bash
  export HOME=/tmp/evil
  ```
- **Expected behavior**: HOME was resolved before user config was loaded (lines 29–34 of sandbox-lib.sh). User config runs in an isolated subprocess via `_load_untrusted_config()`, so its `export HOME=/tmp/evil` only affects the subprocess. The parent shell's HOME is unchanged. `_enforce_admin_policy` uses the admin snapshot and does not re-compute `_USER_DATA_DIR`. Only validated `declare -p` output of known config variables is extracted from the subprocess — HOME is not a known config variable and is not imported.
- **How to verify**: Verify `_USER_DATA_DIR` still points to the original home. Check whether bwrap mount args reference `/tmp/evil` or the real home.

---

### Category F — _USER_DATA_DIR Split / Bootstrap

---

**T23**
- **Category**: Bootstrap — first run seeds sandbox-claude.md
- **Description**: `~/.claude/sandbox/sandbox-claude.md` does not exist. Sandbox is run from admin install path.
- **Admin config snippet**: Admin install at `/app/lib/agent-sandbox/` with `sandbox-claude.md` present.
- **User config snippet**: *(none)*
- **Expected behavior**: `~/.claude/sandbox/sandbox-claude.md` is created by copying the admin template. Admin template unchanged.
- **How to verify**: After first run, file exists at `~/.claude/sandbox/sandbox-claude.md`. File at `/app/lib/agent-sandbox/sandbox-claude.md` has same content.

---

**T24**
- **Category**: Bootstrap — existing user file not overwritten
- **Description**: User has already customized `~/.claude/sandbox/sandbox-claude.md`.
- **Admin config snippet**: Admin install with `sandbox-claude.md`.
- **User config snippet**: *(user file exists with custom content)*
- **Expected behavior**: User file not overwritten. Only checked with `[[ ! -f "$_USER_DATA_DIR/$_seed_file" ]]`.
- **How to verify**: Fingerprint (checksum) of user file before and after sandbox run is unchanged.

---

**T25**
- **Category**: _USER_DATA_DIR split — SANDBOX_DIR is admin-owned, not writable by user
- **Description**: Admin install at `/app/lib/agent-sandbox/`. User has no write access to that directory.
- **Admin config snippet**: *(standard admin install)*
- **User config snippet**: *(none)*
- **Expected behavior**: Sandbox still runs. `_USER_DATA_DIR` is `~/.claude/sandbox/` (user-writable). No writes attempted to `/app/lib/agent-sandbox/`.
- **How to verify**: Run sandbox as non-root user. Verify no files created in `/app/lib/agent-sandbox/`.

---

**T26**
- **Category**: SANDBOX_CONF env var override — backward compat path
- **Description**: `SANDBOX_CONF` is set to a custom path (not the default user path). Should use single-config mode.
- **Admin config snippet**: *(admin install exists but SANDBOX_CONF overrides)*
- **User config snippet**: *(the file at `$SANDBOX_CONF`)*
- **Expected behavior**: Both `_ADMIN_CONF` and `_USER_CONF` logic correctly routes: if `SANDBOX_CONF` differs from the default user path, it is used as `_USER_CONF` (backward compat single-config mode, no admin enforcement).
- **How to verify**: `echo "$_ADMIN_CONF"` is empty. Config at custom path is used.

---

### Category G — Per-Project Config (conf.d/)

---

**T27**
- **Category**: conf.d — project-specific mounts applied
- **Description**: `conf.d/genomics.conf` adds a read-only mount when project is under `/fh/fast/lab/genomics/`.
- **User conf.d snippet** (`~/.claude/sandbox/conf.d/genomics.conf`):
  ```bash
  [[ "$_PROJECT_DIR" == /fh/fast/lab/genomics/* ]] || return 0
  READONLY_MOUNTS+=("/fh/fast/shared/reference_genomes")
  ```
- **Expected behavior**: When project dir is `/fh/fast/lab/genomics/project1`, `/fh/fast/shared/reference_genomes` is mounted read-only. When project dir is elsewhere, it is not.
- **How to verify**: `--dry-run` output shows `--ro-bind /fh/fast/shared/reference_genomes ...` only for matching project dir.

---

**T28**
- **Category**: conf.d — admin enforcement re-applied after conf.d
- **Description**: A `conf.d` file tries to remove an admin-blocked env var.
- **Admin config snippet**:
  ```bash
  BLOCKED_ENV_VARS=("GITHUB_TOKEN")
  ```
- **conf.d snippet**:
  ```bash
  BLOCKED_ENV_VARS=()
  ```
- **Expected behavior**: `_enforce_admin_policy` is called after conf.d files are loaded. `GITHUB_TOKEN` is restored. Warning emitted with label `"Project config"`.
- **How to verify**: `GITHUB_TOKEN` unset inside sandbox. Warning visible in stderr.

---

**T29**
- **Category**: conf.d — DENIED_WRITABLE_PATHS enforced after conf.d
- **Description**: A `conf.d` file tries to add an EXTRA_WRITABLE_PATHS entry under a denied path.
- **Admin config snippet**:
  ```bash
  DENIED_WRITABLE_PATHS=("/fh/fast/lab/restricted")
  ```
- **conf.d snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/lab/restricted/subdir")
  ```
- **Expected behavior**: `_enforce_admin_policy` strips the entry. Warning emitted.
- **How to verify**: Entry absent from final `EXTRA_WRITABLE_PATHS`.

---

**T30**
- **Category**: conf.d — syntax error causes abort
- **Description**: A `conf.d/*.conf` file has a bash syntax error.
- **conf.d snippet**:
  ```bash
  READONLY_MOUNTS+=("/valid/path"
  ```
- **Expected behavior**: `bash -n` pre-check detects the error. Error printed to stderr. Sandbox exits with code 1.
- **How to verify**: Exit code is 1. Error message names the file.

---

**T31**
- **Category**: conf.d — no conf.d files (empty or absent directory)
- **Description**: `~/.claude/sandbox/conf.d/` does not exist.
- **Expected behavior**: `load_project_config` checks `[[ -d "$_conf_d" ]]` and skips the loop gracefully.
- **How to verify**: Sandbox starts and runs normally. No errors.

---

**T32**
- **Category**: conf.d — wildcard expansion with no matching files
- **Description**: `conf.d/` exists but contains no `*.conf` files (only `.example`).
- **Expected behavior**: `for _f in "$_conf_d"/*.conf` expands to a literal glob string; the `[[ -f "$_f" ]] || continue` guard skips it. No error.
- **How to verify**: Sandbox starts normally.

---

### Category H — Path Array Validation

---

**T33**
- **Category**: Path validation — command substitution in ALLOWED_PROJECT_PARENTS
- **Description**: User config inserts `$(malicious_command)` into a path array.
- **User config snippet**:
  ```bash
  ALLOWED_PROJECT_PARENTS+=("/safe/path/$(id)")
  ```
- **Expected behavior**: The shell expands `$(id)` at config-source time inside the isolated subprocess. The command runs in the subprocess only (cannot affect the parent). `_validate_path_array` detects the literal `$(` string in the resulting value and exits with an error.
- **How to verify**: Sandbox exits with `Error: Command substitution in ALLOWED_PROJECT_PARENTS`. Note: the command ran in the subprocess — this is a defense-in-depth check for literals that survived unexpanded (e.g., set with single quotes).

---

**T34**
- **Category**: Path validation — backtick in path array value
- **Description**: A conf.d file sets a path containing a backtick expression in single quotes (so it survives literally).
- **conf.d snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=('/fh/fast/\`id\`')
  ```
- **Expected behavior**: `_validate_path_array` detects the backtick and exits.
- **How to verify**: Exit code 1, error message naming the array.

---

**T35**
- **Category**: Path validation — paths with spaces
- **Description**: User config adds a path containing spaces.
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/my lab/project dir")
  ```
- **Expected behavior**: Path is accepted (no space prohibition). bwrap args are correctly quoted via array expansion.
- **How to verify**: `--dry-run` output shows `--bind "/fh/fast/my lab/project dir" ...` (or equivalent). If the directory exists, the mount succeeds.

---

**T36**
- **Category**: Path validation — relative path in ALLOWED_PROJECT_PARENTS
- **Description**: User config adds a relative path like `./projects`.
- **User config snippet**:
  ```bash
  ALLOWED_PROJECT_PARENTS+=("./projects")
  ```
- **Expected behavior**: `validate_project_dir` compares against the literal string. `PROJECT_DIR` is resolved to an absolute path via `cd ... && pwd -P` in `sandbox-exec.sh`. The relative parent will not match an absolute project dir.
- **How to verify**: Running sandbox with `--project-dir /home/alice/projects/foo` fails validation even though `./projects` is in the list.

---

**T37**
- **Category**: Path validation — symlink as project dir
- **Description**: `--project-dir` is a symlink to a directory inside an allowed parent.
- **Expected behavior**: `PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd -P)"` resolves the physical path. Validation runs against the resolved path. If the physical path is under an allowed parent, it succeeds.
- **How to verify**: Create symlink `/tmp/link -> /fh/fast/lab/project`. Run `sandbox-exec.sh --project-dir /tmp/link`. Validation should succeed (physical path `/fh/fast/lab/project` matches allowed parent `/fh/fast`).

---

**T38**
- **Category**: Path validation — symlink to disallowed location
- **Description**: `--project-dir` is a symlink pointing outside all allowed parents.
- **Expected behavior**: Physical path resolution exposes the real destination; `validate_project_dir` fails.
- **How to verify**: Create symlink `/fh/fast/lab/escape_link -> /etc`. Run with `--project-dir /fh/fast/lab/escape_link`. Should fail: `Error: Project directory not under an allowed parent path.`

---

### Category I — Backend-Specific Tests

---

**T39**
- **Category**: Backend — bwrap BLOCKED_FILES overlaid with /dev/null
- **Description**: A file in `BLOCKED_FILES` is inside an otherwise-accessible directory.
- **Admin config snippet**:
  ```bash
  BLOCKED_FILES=("$HOME/.netrc")
  ```
- **Expected behavior**: `~/.netrc` exists on host. Inside bwrap sandbox, reading it returns empty (bound to `/dev/null`). File appears to exist (not ENOENT).
- **How to verify**: Inside sandbox: `[[ -e ~/.netrc ]] && wc -c ~/.netrc` prints `0 ~/.netrc`.

---

**T40**
- **Category**: Backend — bwrap EXTRA_BLOCKED_PATHS creates empty tmpfs overlay
- **Description**: An `EXTRA_BLOCKED_PATHS` directory is overlaid with tmpfs inside bwrap.
- **Expected behavior**: Directory appears to exist (not ENOENT) but is empty. Files within are not accessible.
- **How to verify**: Inside sandbox: `ls /fh/fast/lab/restricted_clinical_data` is empty even though host has files there.

---

**T41**
- **Category**: Backend — bwrap SANDBOX_BYPASS_TOKEN hidden
- **Description**: Admin sets `SANDBOX_BYPASS_TOKEN`. bwrap overlays it with `/dev/null`.
- **Expected behavior**: `cat $SANDBOX_BYPASS_TOKEN` inside sandbox returns empty. File appears present.
- **How to verify**: Token path exists on host; inside sandbox `wc -c $SANDBOX_BYPASS_TOKEN` prints `0`.

---

**T42**
- **Category**: Backend — firejail BLOCKED_FILES uses --blacklist (ENOENT)
- **Description**: Same scenario as T39 but with firejail backend.
- **Expected behavior**: File is blacklisted — `cat ~/.netrc` returns `Permission denied` or the path appears absent depending on firejail version.
- **How to verify**: Inside firejail sandbox, `[[ -e ~/.netrc ]]` returns false (or access denied).

---

**T43**
- **Category**: Backend — landlock BLOCKED_FILES warning
- **Description**: Admin sets `BLOCKED_FILES` but backend is landlock.
- **Expected behavior**: `WARNING: BLOCKED_FILES has no effect with the Landlock backend.` warning at sandbox startup. File is **not** blocked.
- **How to verify**: Warning on stderr. Inside sandbox, `cat ~/.netrc` still returns content.

---

**T44**
- **Category**: Backend — landlock FILTER_PASSWD warning
- **Description**: `FILTER_PASSWD=true` (default) with landlock backend.
- **Expected behavior**: `WARNING: FILTER_PASSWD=true has no effect with the Landlock backend.` Warning at startup. `getent passwd` inside sandbox returns full LDAP user list.
- **How to verify**: Warning on stderr.

---

**T45**
- **Category**: Backend — bwrap BIND_DEV_PTS=true
- **Description**: `BIND_DEV_PTS=true` in config. bwrap uses `--dev-bind /dev /dev`.
- **Expected behavior**: Host `/dev/pts` is visible inside sandbox. `tmux` inside sandbox can allocate pty.
- **How to verify**: `--dry-run` shows `--dev-bind /dev /dev` instead of `--dev /dev`.

---

**T46**
- **Category**: Backend — BIND_DEV_PTS warning for non-bwrap backend
- **Description**: `BIND_DEV_PTS=true` set in config with firejail or landlock backend.
- **Expected behavior**: `WARNING: BIND_DEV_PTS only applies to the bwrap backend.` Warning at startup.
- **How to verify**: Warning on stderr.

---

**T47**
- **Category**: Backend — bwrap PRIVATE_TMP=true (default)
- **Description**: `/tmp` is isolated with a private tmpfs inside bwrap.
- **Expected behavior**: Files created in `/tmp` outside the sandbox are not visible inside it. `/tmp` is writable inside.
- **How to verify**: Create `/tmp/sentinel` on host. Inside sandbox `[[ -e /tmp/sentinel ]]` is false. `touch /tmp/inside-test` succeeds.

---

**T48**
- **Category**: Backend — bwrap PRIVATE_TMP=false
- **Description**: `PRIVATE_TMP=false` in config. `/tmp` is bind-mounted from host.
- **Expected behavior**: Files in host `/tmp` are visible inside sandbox.
- **How to verify**: Create `/tmp/sentinel` on host. Inside sandbox `[[ -e /tmp/sentinel ]]` is true.

---

**T49**
- **Category**: Backend — auto detection order
- **Description**: All three backends may or may not be available. Auto detection should pick bwrap → firejail → landlock.
- **Expected behavior**: When bwrap is functional, `SANDBOX_BACKEND` is set to `bwrap`. When bwrap is unavailable (fake it by unsetting PATH), firejail is tried next, then landlock.
- **How to verify**: Temporarily rename `bwrap` binary. Check `SANDBOX_BACKEND` value after `detect_backend`.

---

**T50**
- **Category**: Backend — explicit backend unavailable
- **Description**: `--backend firejail` specified but firejail is not installed.
- **Expected behavior**: Error: `Requested backend 'firejail' is not available on this system.` Diagnostic info (hostname, kernel, LSMs) printed. Exit 1.
- **How to verify**: Run with `--backend firejail` on a system without firejail. Check exit code and stderr.

---

**T51**
- **Category**: Backend — bwrap SSH_* env var blocking
- **Description**: `SSH_AUTH_SOCK` is set in environment but not explicitly in `BLOCKED_ENV_VARS`.
- **Expected behavior**: bwrap backend iterates `env | SSH_*` and adds `--unsetenv SSH_AUTH_SOCK` dynamically. Inside sandbox `SSH_AUTH_SOCK` is unset.
- **How to verify**: `export SSH_AUTH_SOCK=/tmp/agent.12345` then start sandbox. Inside: `echo ${SSH_AUTH_SOCK:-UNSET}` prints `UNSET`.

---

**T52**
- **Category**: Backend — bwrap /run isolation
- **Description**: Dangerous `/run` sockets (D-Bus, systemd user) are hidden. Munge is exposed.
- **Expected behavior**: `/run/dbus` not accessible inside sandbox. `/run/munge` accessible.
- **How to verify**: Inside bwrap sandbox: `ls /run/dbus` fails or is empty. `ls /run/munge` shows expected socket.

---

**T53**
- **Category**: Backend — bwrap FD closure before exec
- **Description**: Parent process has open file descriptors (3+) that should not leak into the sandbox.
- **Expected behavior**: `sandbox-exec.sh` iterates `/proc/self/fd/*` and closes all FDs > 2 before `backend_exec`. A pre-opened FD to a sensitive file is not accessible inside sandbox.
- **How to verify**: Open a file with `exec 5</etc/shadow` before calling sandbox. Inside sandbox, `cat /proc/self/fd/5` fails (EBADF).

---

**T54**
- **Category**: Backend — firejail /run dangerous socket blacklisting
- **Description**: `/run/user`, `/run/dbus`, `/run/systemd/private` are blacklisted.
- **Expected behavior**: These paths are not accessible inside firejail sandbox.
- **How to verify**: Inside firejail sandbox: accessing `/run/user/1000/systemd/private` returns permission denied.

---

**T55**
- **Category**: Backend — FILTER_PASSWD reduces getent output (bwrap)
- **Description**: `FILTER_PASSWD=true` (default). `/etc/passwd` is overlaid with a filtered version inside bwrap.
- **Expected behavior**: `getent passwd` inside sandbox returns ≤ 35 entries (system + current user). Does not include arbitrary LDAP users.
- **How to verify**: Count `getent passwd | wc -l` inside vs outside sandbox. Inside count should be much lower on LDAP-connected systems.

---

**T56**
- **Category**: Backend — SANDBOX_DIR protected (bwrap)
- **Description**: The admin sandbox directory `/app/lib/agent-sandbox/` is mounted read-only inside the sandbox.
- **Expected behavior**: `BWRAP_ARGS+=(--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR")`. Agent cannot modify sandbox scripts.
- **How to verify**: Inside bwrap sandbox: `echo test > /app/lib/agent-sandbox/sandbox-lib.sh` fails with EROFS.

---

**T57**
- **Category**: Backend — landlock no SANDBOX_DIR protection (documented limitation)
- **Description**: With landlock, the agent can modify sandbox scripts (no mount namespace).
- **Expected behavior**: This is a **known limitation** documented in `ADMIN_HARDENING.md §2`. Landlock rules are additive; subdir cannot be made read-only when parent is writable.
- **How to verify**: Inside landlock sandbox with project dir under home: `echo pwned > /app/lib/agent-sandbox/sandbox-lib.sh` may succeed (filesystem permissions permitting).

---

**T58**
- **Category**: Backend — Slurm binary isolation (bwrap)
- **Description**: `/usr/bin/sbatch` is replaced with a wrapper inside bwrap via `--ro-bind`.
- **Expected behavior**: Inside sandbox, `/usr/bin/sbatch` points to the overlay script (`sandbox-exec.sh`'s generated wrapper), not the real sbatch. The real sbatch is available at `SLURM_REAL_DIR/sbatch`.
- **How to verify**: Inside sandbox: `cat /usr/bin/sbatch` shows the wrapper script. `exec /tmp/.sandbox-slurm-real/sbatch --version` works (real binary).

---

### Category J — Config Loading Edge Cases

---

**T59**
- **Category**: Config edge case — empty arrays (no admin entries)
- **Description**: Admin config sets `BLOCKED_FILES=()` (empty). User config does `BLOCKED_FILES+=("$HOME/.netrc")`.
- **Admin config snippet**:
  ```bash
  BLOCKED_FILES=()
  ```
- **User config snippet**:
  ```bash
  BLOCKED_FILES+=("$HOME/.netrc")
  ```
- **Expected behavior**: No admin entries to protect. User addition survives. Final array contains `$HOME/.netrc`.
- **How to verify**: Array contains user addition after `_enforce_admin_policy`.

---

**T60**
- **Category**: Config edge case — user.conf does not exist
- **Description**: `~/.claude/sandbox/user.conf` is absent.
- **Expected behavior**: Phase 2 `[[ -f "$_USER_CONF" ]]` check skips it. Only admin config and defaults apply.
- **How to verify**: Sandbox starts with admin defaults. No errors about missing file.

---

**T61**
- **Category**: Config edge case — admin config does not exist (user-only install)
- **Description**: `/app/lib/agent-sandbox/sandbox.conf` is absent. User-only install.
- **Expected behavior**: `_ADMIN_CONF` is empty. `_enforce_admin_policy`'s `[[ -n "$_ADMIN_CONF" ]]` check is false — no enforcement. User's `~/.claude/sandbox/sandbox.conf` is the single config.
- **How to verify**: `echo "${_ADMIN_CONF:-empty}"` prints `empty`. User config values are used.

---

**T62**
- **Category**: Config edge case — admin config disappears after Phase 1 (no TOCTOU)
- **Description**: Another process deletes `/app/lib/agent-sandbox/sandbox.conf` after Phase 1 snapshot.
- **Expected behavior**: The admin config is only sourced once in Phase 1 via `_source_trusted_config`. The snapshot is taken immediately. `_enforce_admin_policy` uses the in-memory snapshot — it never re-reads the admin config file. There is no TOCTOU race condition. If the file disappears after Phase 1, enforcement continues normally using the snapshot.
- **How to verify**: In test harness, delete the admin config after snapshot. Confirm sandbox starts successfully and admin policy is enforced from the snapshot.

---

**T63**
- **Category**: Config edge case — IFS manipulation in user config
- **Description**: User config sets `IFS=$'\n'` to alter word splitting in later config processing.
- **User config snippet**:
  ```bash
  IFS=$'\n'
  ```
- **Expected behavior**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The IFS change is confined to the subprocess and does not affect the parent shell. Only validated `declare -p` output of known config variables is extracted and eval'd in the parent, where IFS is unmodified.
- **How to verify**: Run sandbox with the IFS-setting user config. `SANDBOX_BACKEND` and all arrays are correct. Parent shell IFS is unchanged.

---

**T64**
- **Category**: Config edge case — user config sets `set +e` or `set +u`
- **Description**: User config calls `set +euo pipefail` to weaken error handling for subsequent sandbox-lib.sh code.
- **User config snippet**:
  ```bash
  set +euo pipefail
  ```
- **Expected behavior**: User config runs in an isolated `/bin/bash --norc --noprofile` subprocess via `_load_untrusted_config()`. The `set +euo pipefail` only affects the subprocess. The parent shell's options are unchanged. `_enforce_admin_policy` runs in the parent with the original shell options intact.
- **How to verify**: Run sandbox with this user config. Confirm parent shell options are unaffected — the subprocess isolation fully neutralizes this attack.

---

**T65**
- **Category**: Config edge case — user config calls `exit 0`
- **Description**: User config contains `exit 0` to terminate sandbox-lib.sh sourcing early.
- **User config snippet**:
  ```bash
  exit 0
  ```
- **Expected behavior**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The `exit 0` terminates the subprocess, not the parent shell. The parent detects that the subprocess produced no valid `declare -p` output for known config variables and continues with admin defaults. `_enforce_admin_policy` runs normally. This is fully neutralized by subprocess isolation — no longer a DoS.
- **How to verify**: With user.conf containing `exit 0`, run sandbox. Confirm sandbox starts successfully with admin defaults applied.

---

**T66**
- **Category**: Config edge case — user config calls `return 0` at top level
- **Description**: `return` in a sourced file at top level (not inside a function) causes the `source` command to complete early (not an error in bash).
- **User config snippet**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/evil/path")
  return 0
  BLOCKED_ENV_VARS=()   # never runs
  ```
- **Expected behavior**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The `return` affects the sourced file within the subprocess only. Only code before `return` executes in the subprocess. The parent extracts validated `declare -p` output — `EXTRA_WRITABLE_PATHS` contains `/evil/path` but `BLOCKED_ENV_VARS` was never cleared (the clearing line never ran). `_enforce_admin_policy` runs normally.
- **How to verify**: After loading, `EXTRA_WRITABLE_PATHS` contains `/evil/path` (if allowed) but `BLOCKED_ENV_VARS` is intact.

---

### Category K — Bash Version and Portability

---

**T67**
- **Category**: Bash version check
- **Description**: Run sandbox-lib.sh under bash 4.3 or earlier.
- **Expected behavior**: Early version check exits with: `Error: sandbox-lib.sh requires bash >= 4.4`. Exit 1.
- **How to verify**: `bash-4.3 sandbox-lib.sh` fails with the error.

---

**T68**
- **Category**: Critical mount warnings
- **Description**: Admin config or user config removes `/usr` from `READONLY_MOUNTS`.
- **Admin config snippet**:
  ```bash
  READONLY_MOUNTS=("/lib" "/lib64" "/bin" "/sbin" "/etc" "/app")
  ```
- **Expected behavior**: Warning: `WARNING: /usr is not in READONLY_MOUNTS. The sandbox may not function correctly.`
- **How to verify**: Warning appears on stderr. Sandbox may start but programs fail to run.

---

**T69**
- **Category**: Critical HOME_WRITABLE warnings
- **Description**: `.claude` is missing from `HOME_WRITABLE`.
- **Admin config snippet**:
  ```bash
  HOME_WRITABLE=(".cache/uv")
  ```
- **Expected behavior**: Warning: `WARNING: $HOME/.claude is not in HOME_WRITABLE. Claude Code may not function correctly.`
- **How to verify**: Warning appears on stderr.

---

---

## OUTPUT 2: Escape Attempts

### Category α — Config File Injection and Code Execution

---

**A01**
- **Attack ID**: A01
- **Attack vector**: User config sources a second file the agent controls.
- **What the attacker does**:
  ```bash
  # ~/.claude/sandbox/user.conf (under agent's write access via HOME_WRITABLE=".claude")
  source "$HOME/.claude/evil.conf"
  ```
  `evil.conf` contains `BLOCKED_ENV_VARS=()`.
- **Expected defense**: `_load_untrusted_config()` runs user.conf in an isolated `/bin/bash --norc --noprofile` subprocess. The `source evil.conf` runs inside the subprocess — both files are confined. Only validated `declare -p` output of known config variables is extracted. `_enforce_admin_policy` then compares against the admin snapshot and restores any removed admin entries.
- **How to verify the defense works**: After `_enforce_admin_policy`, `GITHUB_TOKEN` is still blocked. Check warning about removed entry.

---

**A02**
- **Attack ID**: A02
- **Attack vector**: User config installs a DEBUG trap to fire on every statement.
- **What the attacker does**:
  ```bash
  trap 'BLOCKED_ENV_VARS=(); HOME_WRITABLE+=(".ssh")' DEBUG
  ```
  The DEBUG trap fires before every command in the current shell — including policy enforcement statements.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The DEBUG trap is confined to the subprocess and cannot fire in the parent shell. There are no trap resets needed — subprocess isolation fully neutralizes this attack. `_enforce_admin_policy` runs in the parent, completely unreachable from the subprocess's traps.
- **How to verify the defense works**: Add a DEBUG trap that logs every execution to a file. After sandbox starts, check that the log has no parent shell entries. Admin arrays are intact.

---

**A03**
- **Attack ID**: A03
- **Attack vector**: User config redefines the `source` function.
- **What the attacker does**:
  ```bash
  source() { echo "source bypassed: $*"; }
  ```
  Hopes that the admin config re-source call gets intercepted.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The `source` function override is confined to the subprocess. The parent shell's `source` builtin is unaffected. There is no `builtin .` re-sourcing of admin config — `_enforce_admin_policy` uses the in-memory snapshot taken in Phase 1.
- **How to verify the defense works**: After sandbox starts with this user.conf, `SANDBOX_BYPASS_TOKEN` and all admin arrays are correctly set to admin values.

---

**A04**
- **Attack ID**: A04
- **Attack vector**: User config redefines the `.` (dot) builtin by creating a shell function named `.`.
- **What the attacker does**:
  ```bash
  .() { echo "dot bypassed"; }
  ```
  `.` and `source` are synonyms in bash; overriding `.` as a function might intercept sourcing.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The `.` function override is confined to the subprocess. There is no `builtin .` re-sourcing of admin config — `_enforce_admin_policy` uses the in-memory snapshot. The function override cannot affect the parent shell.
- **How to verify the defense works**: Admin values are enforced correctly. Test by checking that an admin-set value is restored by `_enforce_admin_policy`.

---

**A05**
- **Attack ID**: A05
- **Attack vector**: User config sets a DEBUG trap on conf.d files to fire during `_enforce_admin_policy`.
- **What the attacker does**:
  Place the DEBUG trap in a `conf.d/*.conf` file:
  ```bash
  trap 'BLOCKED_ENV_VARS=()' DEBUG
  ```
- **Expected defense**: conf.d files are loaded via `_load_untrusted_config()` in an isolated subprocess. The DEBUG trap is confined to the subprocess and cannot fire in the parent shell. No trap resets are needed — subprocess isolation fully neutralizes this attack. `_enforce_admin_policy` runs in the parent, unreachable from the subprocess.
- **How to verify the defense works**: `BLOCKED_ENV_VARS` retains admin entries after `_enforce_admin_policy` runs.

---

**A06**
- **Attack ID**: A06
- **Attack vector**: User config redefines `_enforce_admin_policy` itself.
- **What the attacker does**:
  ```bash
  _enforce_admin_policy() { echo "neutered"; }
  ```
  Hopes to prevent enforcement when called from `load_project_config`.
- **Expected defense**: This attack is completely eliminated by subprocess isolation. User config runs in an isolated subprocess via `_load_untrusted_config()`. The function override is confined to the subprocess. `_enforce_admin_policy` is defined in `sandbox-lib.sh` and runs in the parent shell — it is unreachable from the subprocess. The parent's function definition is never affected.
- **How to verify the defense works**: After loading user config, confirm `declare -f _enforce_admin_policy` in the parent shell shows the original function body. Admin enforcement works correctly.

---

**A07**
- **Attack ID**: A07
- **Attack vector**: User config redefines `_snapshot_admin_config` to capture a weakened snapshot.
- **What the attacker does**:
  ```bash
  _snapshot_admin_config() {
      _ADMIN_BLOCKED_ENV_VARS=()
      _ADMIN_HOME_READONLY=()
  }
  ```
  Because `_snapshot_admin_config` is called in Phase 1 (before user config), this redefinition arrives too late to affect the snapshot that was already taken. However, if user config is sourced first (edge case in single-config mode), the redefinition would apply.
- **Expected defense**: In admin install mode, Phase 1 runs `_snapshot_admin_config` before user config is loaded. User config runs in an isolated subprocess via `_load_untrusted_config()`, so the function redefinition is confined to the subprocess and cannot affect the parent's snapshot. In single-config mode, there is no admin enforcement, so the attack is moot.
- **How to verify the defense works**: Verify that `_ADMIN_BLOCKED_ENV_VARS` contains the real admin values after user config is loaded.

---

**A08**
- **Attack ID**: A08
- **Attack vector**: User config redefines `_validate_path_array` to be a no-op.
- **What the attacker does**:
  ```bash
  _validate_path_array() { return 0; }
  ```
  Then adds `ALLOWED_PROJECT_PARENTS+=("$(malicious)")` in single quotes as a literal string, hoping the validator won't catch it.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The function redefinition is confined to the subprocess. `_validate_path_array` in the parent shell is unaffected. Command substitution in path values expands inside the subprocess — the malicious command runs there, not in the parent. The validator in the parent still catches literal `$(` strings in the extracted `declare -p` output (defense in depth).
- **How to verify the defense works**: Confirm `_validate_path_array` in the parent shell retains its original body. Malicious command execution is confined to the subprocess.

---

**A09**
- **Attack ID**: A09
- **Attack vector**: User config creates a background process that modifies arrays after policy enforcement.
- **What the attacker does**:
  ```bash
  (sleep 2; export BLOCKED_ENV_VARS='') &
  ```
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The background process is spawned inside the subprocess — it cannot affect the parent shell's variables. Only validated `declare -p` output is extracted from the subprocess. After `_enforce_admin_policy`, the variables in the parent shell are finalized before `backend_exec`.
- **How to verify the defense works**: After `backend_exec`, inside the sandbox, `GITHUB_TOKEN` is unset despite the background process.

---

**A10**
- **Attack ID**: A10
- **Attack vector**: User config installs a RETURN trap to fire when config loading returns.
- **What the attacker does**:
  ```bash
  trap 'BLOCKED_ENV_VARS=()' RETURN
  ```
  The RETURN trap fires when the current function returns. In the old model, this would fire when sourcing completed in the parent shell.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The RETURN trap is confined to the subprocess and cannot fire in the parent shell. No trap resets are needed — subprocess isolation fully neutralizes this attack.
- **How to verify the defense works**: `BLOCKED_ENV_VARS` is not empty after `_enforce_admin_policy`.

---

**A11**
- **Attack ID**: A11
- **Attack vector**: User config redefines `eval` to intercept the parent's eval-based variable import.
- **What the attacker does**:
  ```bash
  eval() { echo "eval intercepted: $*"; }
  ```
  The parent uses `eval` on validated `declare -p` output from the subprocess to import config variables.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. The `eval` function override is confined to the subprocess. In the parent shell, `eval` is only used on validated `declare -p` output extracted from the subprocess. Even if the child redefines `eval`, it does not affect the parent's `eval` builtin. This attack is fully neutralized by subprocess isolation.
- **How to verify the defense works**: After loading user config with eval override, confirm parent shell's `eval` is the original builtin. Admin arrays are correctly enforced.

---

### Category β — Environment and Path Manipulation

---

**A12**
- **Attack ID**: A12
- **Attack vector**: Pre-sandbox HOME poisoning.
- **What the attacker does**: Before running `sandbox-exec.sh`, the agent sets `export HOME=/tmp/evil` in its shell. `/tmp/evil/.claude/sandbox/user.conf` contains malicious config. This redirects where user config is loaded from.
- **Expected defense**: Lines 29–34 of `sandbox-lib.sh` resolve `HOME` from `getent passwd` before `_USER_DATA_DIR` is computed. The poisoned `$HOME` is overwritten. `_USER_DATA_DIR` becomes the real home's `.claude/sandbox/`.
- **How to verify the defense works**: Run sandbox after `export HOME=/tmp/evil`. Confirm `_USER_DATA_DIR` equals the real home's path.

---

**A13**
- **Attack ID**: A13
- **Attack vector**: SANDBOX_CONF env var redirect.
- **What the attacker does**: Set `SANDBOX_CONF=/tmp/evil/sandbox.conf` (agent-controlled). Agent's sandbox.conf has `BLOCKED_ENV_VARS=()`.
- **Expected defense**: When `SANDBOX_CONF` is set and differs from the default user path, the code enters single-config mode (`_USER_CONF="$SANDBOX_CONF"`, `_ADMIN_CONF=""`). Admin enforcement is disabled. This is **by design** for backward compat, but means an agent that can set env vars before the sandbox starts can disable admin enforcement. However, the agent cannot start the sandbox itself (the sandbox wraps the agent, not vice versa). This vector requires the user (human) to have a poisoned env.
- **How to verify the defense works**: Verify that in normal HPC usage, the human operator does not export `SANDBOX_CONF` to the agent's environment. Document that `SANDBOX_CONF` is a privileged configuration env var.

---

**A14**
- **Attack ID**: A14
- **Attack vector**: SANDBOX_BACKEND env var override.
- **What the attacker does**: Agent sets `SANDBOX_BACKEND=landlock` to force the weakest backend.
- **Expected defense**: `_SANDBOX_BACKEND_OVERRIDE` is captured before any config is loaded (`_SANDBOX_BACKEND_OVERRIDE="${SANDBOX_BACKEND:-}"`). After `_enforce_admin_policy`, if `_SANDBOX_BACKEND_OVERRIDE` is non-empty, it is restored. However, this means if the env var is set, it overrides the admin config's `SANDBOX_BACKEND`. Admin cannot prevent this via config alone. The only prevention is to not allow the agent to set `SANDBOX_BACKEND` in its environment.
- **How to verify the defense works**: Verify whether an admin can force `SANDBOX_BACKEND` via admin config in a way that user/env cannot override. Currently they cannot — env takes precedence.

---

**A15**
- **Attack ID**: A15
- **Attack vector**: PATH manipulation to intercept `getent`, `id`, or `bwrap`.
- **What the attacker does**: Agent sets `PATH=/tmp/evil:$PATH` before sandbox starts. Places a fake `bwrap` at `/tmp/evil/bwrap` that wraps the real bwrap but adds `--bind /etc /etc --rw-bind /etc /etc`.
- **Expected defense**: `sandbox-exec.sh` uses `BWRAP="$(command -v bwrap)"` which resolves via PATH. A poisoned PATH would find the fake bwrap. This is a pre-execution environment attack — the defense is the same as A13: the agent cannot start the sandbox itself. The human operator's PATH is used, not the agent's.
- **How to verify the defense works**: Verify that sandbox is invoked by the human/admin with a clean PATH. Document the trust boundary: the sandbox wraps the agent process, started by the human.

---

**A16**
- **Attack ID**: A16
- **Attack vector**: `LD_PRELOAD` injection to intercept bwrap syscalls.
- **What the attacker does**: Agent sets `LD_PRELOAD=/tmp/evil/libhook.so` before sandbox starts. The shared library intercepts `mount(2)` or `unshare(2)` to weaken isolation.
- **Expected defense**: bwrap is a statically linked binary (or uses secure-exec behavior). Even if dynamically linked, `LD_PRELOAD` is stripped by the dynamic linker when the binary has `CAP_SYS_ADMIN` or uses user namespaces. Additionally, sandbox-exec.sh does not pass `LD_PRELOAD` through. With bwrap `--unsetenv LD_PRELOAD` (if added to `BLOCKED_ENV_VARS`), this is fully defended.
- **How to verify the defense works**: Verify `LD_PRELOAD` is in `BLOCKED_ENV_VARS` or that bwrap binary ignores it. Run `ldd $(which bwrap)` to check if it is dynamically linked.

---

**A17**
- **Attack ID**: A17
- **Attack vector**: Open file descriptor leak to access a pre-opened sensitive file inside the sandbox.
- **What the attacker does**: Before the sandbox starts, open a file descriptor to `/etc/shadow` or the bypass token file (FD 5). The sandbox exec preserves the FD.
- **Expected defense**: `sandbox-exec.sh` iterates `/proc/self/fd/*` and closes all FDs > 2 before `backend_exec` (lines 132–138). The leaked FD is closed.
- **How to verify the defense works**: Open `exec 5</path/to/secret` before sandbox. Inside sandbox, `cat /proc/self/fd/5` fails with EBADF.

---

### Category γ — Filesystem Trickery

---

**A18**
- **Attack ID**: A18
- **Attack vector**: Symlink in HOME_WRITABLE path to escape home isolation.
- **What the attacker does**: Agent creates `~/.claude/escape_link -> /etc` in a previous session. On next sandbox start, `HOME_WRITABLE` contains `.claude`, so `~/.claude` is bind-mounted writable. The symlink at `~/.claude/escape_link` allows reading `/etc` via the writable mount.
- **Expected defense**: bwrap follows symlinks when constructing bind mounts. The symlink target `/etc` is separately mounted read-only via `READONLY_MOUNTS`. bwrap's mount ordering matters — the writable bind of `~/.claude` does not make `/etc` writable because `/etc` has its own `--ro-bind` mount applied before `--tmpfs $HOME` and the writable re-mounts. The read-only mount of `/etc` remains.
- **How to verify the defense works**: Create `~/.claude/escape_link -> /etc`. Inside sandbox, `touch ~/.claude/escape_link/hosts` should fail (EROFS on the `/etc` mount point).

---

**A19**
- **Attack ID**: A19
- **Attack vector**: Hardlink to bypass BLOCKED_FILES.
- **What the attacker does**: Create a hardlink to the bypass token file in a writable directory: `ln /run/slurm/tokens/bypass.tok ~/.claude/bypass_token_copy`.
- **Expected defense**: The `BLOCKED_FILES` mechanism overlays the specific path with `/dev/null`. Hardlinks to the same inode at different paths are not blocked unless those paths are also in `BLOCKED_FILES`. This attack could expose the token content via the hardlink. **Defense gap**: The token path should be in a filesystem that disallows cross-directory hardlinks, or the file should be readable only by root/slurm.
- **How to verify the defense works**: Check if hardlinks from blocked paths can be created in writable directories. If yes, report as a vulnerability.

---

**A20**
- **Attack ID**: A20
- **Attack vector**: Symlink swap on admin config after Phase 1 (no TOCTOU).
- **What the attacker does**: Monitor when Phase 1 reads `/app/lib/agent-sandbox/sandbox.conf`. Atomically replace it with a symlink to `/tmp/evil/sandbox.conf`.
- **Expected defense**: The admin config is only read once in Phase 1 via `_source_trusted_config`. There is no re-sourcing — `_enforce_admin_policy` uses the in-memory snapshot. The TOCTOU race window does not exist. Even if the file were swapped, the snapshot was already taken. Additionally, the admin install directory `/app/lib/agent-sandbox/` is owned by root/admin and not writable by the agent.
- **How to verify the defense works**: Verify `/app/lib/agent-sandbox/` is owned by root and mode 755 or more restrictive. Agent user cannot write to it.

---

**A21**
- **Attack ID**: A21
- **Attack vector**: Agent modifies `user.conf` during sandbox startup (race condition).
- **What the attacker does**: Agent starts a background process that writes to `~/.claude/sandbox/user.conf` while sandbox-lib.sh is sourcing it.
- **Expected defense**: `_load_untrusted_config()` reads the file in an isolated subprocess. The file is read once by bash. Concurrent writes could cause a partial read, but the subprocess isolation means any corruption only affects the subprocess's variable state. Only validated `declare -p` output of known config variables is extracted. `_enforce_admin_policy` uses the in-memory admin snapshot to restore any missing admin values regardless of what the subprocess produced.
- **How to verify the defense works**: Even if user.conf is modified mid-source, `_enforce_admin_policy` ensures admin arrays are intact.

---

**A22**
- **Attack ID**: A22
- **Attack vector**: Agent creates a `conf.d/*.conf` file with glob-expanding path entries.
- **What the attacker does**:
  ```bash
  EXTRA_WRITABLE_PATHS+=("/fh/fast/*")
  ```
  Hopes the glob expands to include `/fh/fast/lab/restricted_clinical_data`.
- **Expected defense**: Glob expansion happens at bash assignment time inside the isolated subprocess. The `*` expands to actual directory names at that moment. If `/fh/fast/restricted_clinical_data` exists, it is added. The `DENIED_WRITABLE_PATHS` check in `_enforce_admin_policy` would then strip it with a warning. The defense depends on the admin having set the denied path correctly.
- **How to verify the defense works**: After loading a conf.d with glob path, `_enforce_admin_policy` strips entries matching denied paths.

---

**A23**
- **Attack ID**: A23
- **Attack vector**: Agent escapes bwrap via `/proc/self/exe` re-exec.
- **What the attacker does**: Inside bwrap sandbox, read `/proc/self/exe` to get the original binary path. Re-execute it without sandbox.
- **Expected defense**: bwrap uses `--unshare-pid`, which means `/proc` inside the sandbox is a new procfs. `/proc/self/exe` points to the sandboxed process binary. If the binary is accessible (under READONLY_MOUNTS), the agent could re-exec it. However, the re-executed process starts inside the same PID namespace but outside bwrap's mount namespace. This is partially mitigated by `--die-with-parent` — if the parent bwrap process dies, child processes also die. But re-exec within the session is possible.
- **How to verify the defense works**: Assess whether `/proc/self/exe` re-exec can escape the mount namespace. On typical systems, `execve` of a new process inherits the current mount namespace.

---

**A24**
- **Attack ID**: A24
- **Attack vector**: systemd-run --user escape (Landlock/firejail backend).
- **What the attacker does**: Inside a landlock sandbox, invoke `systemd-run --user -- bash` to spawn a process outside the Landlock rules (new process, new Landlock domain, unrestricted).
- **Expected defense**:
  - bwrap: `/run/user/<uid>` not mounted (tmpfs /run with selective binds). `systemd-run --user` cannot connect to the user session socket.
  - firejail: `/run/user` is blacklisted.
  - landlock: **No defense**. Landlock cannot block AF_UNIX socket connections. This is a known limitation documented in `ADMIN_HARDENING.md §0` — fix is to disable `user@.service`.
- **How to verify the defense works**: Inside each backend, try `systemd-run --user -- cat /etc/shadow`. Should fail for bwrap and firejail. May succeed for landlock if user@.service is running.

---

**A25**
- **Attack ID**: A25
- **Attack vector**: User config adds `_ADMIN_CONF` to `HOME_WRITABLE` to make admin config writable.
- **What the attacker does**:
  ```bash
  HOME_WRITABLE+=("../../app/lib/agent-sandbox/sandbox.conf")
  ```
  Hopes the relative path traversal allows writing to `/app/lib/agent-sandbox/sandbox.conf` from the home tmpfs.
- **Expected defense**: bwrap bind-mount targets are literal paths, not joined with `$HOME`. The path `$HOME/../../app/lib/agent-sandbox/sandbox.conf` would resolve to `/app/lib/agent-sandbox/sandbox.conf` on the host. bwrap would attempt `--bind "$HOME/../../app/lib/agent-sandbox/sandbox.conf" "$HOME/../../app/lib/agent-sandbox/sandbox.conf"`. Since the admin directory is owned by root and not writable by the user, the bind mount either fails or mounts read-only. Additionally, the admin dir is already mounted `--ro-bind` by the backend (`--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR"`), so the writable bind would conflict.
- **How to verify the defense works**: With this user.conf, confirm the admin conf file remains read-only inside the sandbox.

---

### Category δ — Combination and Chained Attacks

---

**A26**
- **Attack ID**: A26
- **Attack vector**: DEBUG trap + function override combination.
- **What the attacker does**:
  ```bash
  builtin() {
      if [[ "$1" == "." || "$1" == "source" ]]; then
          echo "blocked builtin"
          return 0
      fi
      command builtin "$@"
  }
  trap 'builtin() { :; }' DEBUG
  ```
  Redefines `builtin` as a function, then installs a DEBUG trap to clear it.
- **Expected defense**: User config runs in an isolated subprocess via `_load_untrusted_config()`. Both the `builtin` function override and the DEBUG trap are confined to the subprocess. They cannot affect the parent shell. There is no `builtin .` re-sourcing of admin config — `_enforce_admin_policy` uses the in-memory snapshot. Subprocess isolation fully neutralizes this combination attack.
- **How to verify the defense works**: After loading user config, confirm parent shell's `builtin` keyword and trap state are unaffected. Admin values are enforced correctly.

---

**A27**
- **Attack ID**: A27
- **Attack vector**: eval redefinition + BLOCKED_ENV_VARS removal during policy enforcement.
- **What the attacker does**:
  ```bash
  eval() {
      local cmd="$*"
      # Strip any BLOCKED_ENV_VARS restoration
      [[ "$cmd" == *BLOCKED_ENV_VARS* ]] && return 0
      builtin eval "$cmd"
  }
  ```
- **Expected defense**: See A11. User config runs in an isolated subprocess via `_load_untrusted_config()`. The `eval` function override is confined to the subprocess. In the parent, `eval` is only used on validated `declare -p` output extracted from the subprocess. The parent's `eval` builtin is unaffected by the subprocess's redefinition. This attack is fully neutralized by subprocess isolation.
- **How to verify the defense works**: After loading user config with eval override, confirm parent shell's `eval` is the original builtin. `BLOCKED_ENV_VARS` retains admin entries.

---

**A28**
- **Attack ID**: A28
- **Attack vector**: Slow-read attack — user config contains an infinite loop to stall config loading.
- **What the attacker does**:
  ```bash
  while true; do sleep 1; done
  ```
  Or a very expensive computation. This is denial of service.
- **Expected defense**: `_load_untrusted_config()` runs user config in an isolated subprocess. The infinite loop runs in the subprocess only, so it cannot directly hang the parent. However, the parent waits for the subprocess to complete, so the sandbox still hangs. This remains a DoS (not an escalation). **Recommendation**: Add a timeout to the subprocess (e.g., `timeout 10 /bin/bash --norc --noprofile -c "..."`).
- **How to verify the defense works**: Currently, the subprocess hangs and the parent waits. Adding a timeout to `_load_untrusted_config()` would fully resolve this.

---

**A29**
- **Attack ID**: A29
- **Attack vector**: Conf.d file named `zzz_evil.conf` to run last and override previous conf.d additions.
- **What the attacker does**: Agent creates `~/.claude/sandbox/conf.d/zzz_evil.conf` (alphabetically last). It contains `EXTRA_WRITABLE_PATHS=("/etc")`.
- **Expected defense**: `_enforce_admin_policy` is called after all conf.d files are loaded. The DENIED_WRITABLE_PATHS check strips `/etc` if it is in the deny list. If `/etc` is not in `DENIED_WRITABLE_PATHS` but is in `READONLY_MOUNTS`, the agent gets write access to a separately mounted `/etc` path — bwrap's later bind wins.
- **How to verify the defense works**: Verify that `EXTRA_WRITABLE_PATHS` containing system paths that are also in `READONLY_MOUNTS` is defended by bwrap mount ordering or DENIED_WRITABLE_PATHS enforcement.

---

**A30**
- **Attack ID**: A30
- **Attack vector**: CLAUDE_CONFIG_DIR manipulation to inject persistent CLAUDE.md instructions.
- **What the attacker does**: Inside the sandbox, the agent writes to `$CLAUDE_CONFIG_DIR/CLAUDE.md` to inject persistent instructions that affect future sessions.
- **Expected defense**: `CLAUDE_CONFIG_DIR` points to `~/.claude/sandbox-config/`, which is under `~/.claude` (writable via `HOME_WRITABLE=".claude"`). However, the real `~/.claude/CLAUDE.md` is bind-mounted read-only in bwrap:
  ```bash
  BWRAP_ARGS+=(--ro-bind "$_real_claude_md" "$_real_claude_md")
  ```
  The sandbox-config copy is writable, but `prepare_config_dir` rebuilds it on every sandbox start from the real CLAUDE.md (with stale sandbox injection stripped). Changes to the sandbox-config copy do not persist to the real CLAUDE.md.
- **How to verify the defense works**: Agent writes to `$CLAUDE_CONFIG_DIR/CLAUDE.md`. After sandbox exit and restart, verify the injected content is not present in the new session's CLAUDE.md.

---

**A31**
- **Attack ID**: A31
- **Attack vector**: Python settings.json merge manipulation.
- **What the attacker does**: The agent modifies `~/.claude/sandbox/sandbox-settings.json` (writable via HOME_WRITABLE=".claude") to add permissive rules: `{"permissions": {"allow": ["Bash(*)", "Write(*)"]}}`. This is merged into `settings.json` by `prepare_config_dir`.
- **Expected defense**: `~/.claude/sandbox/` is the `_USER_DATA_DIR`. `HOME_WRITABLE=(".claude")` includes `.claude`, which contains `sandbox/`. If the agent can write to `~/.claude/sandbox/sandbox-settings.json`, it can escalate its own Claude Code permissions. **Defense gap**: The `sandbox-settings.json` file should be owned by the human user and not writable by the agent. Consider making `~/.claude/sandbox/` separately handled or listed in `HOME_READONLY` with only specific subdirectories writable.
- **How to verify the defense works**: Verify filesystem permissions on `~/.claude/sandbox/sandbox-settings.json`. Confirm the agent cannot write to it if the sandbox home mount is configured correctly.

---

**A32**
- **Attack ID**: A32
- **Attack vector**: Nested sandbox to escape outer sandbox.
- **What the attacker does**: Inside a bwrap sandbox, the agent runs `sandbox-exec.sh` again to start a nested sandbox with a different config (e.g., no HOME isolation).
- **Expected defense**: The nested sandbox call sources `sandbox-lib.sh` which reads from `_USER_DATA_DIR` (the user's `~/.claude/sandbox/`). Since `~/.claude` is writable in the outer sandbox, the agent could have modified `user.conf`. However, the nested bwrap starts with the same user's namespaces — bwrap's `--unshare-pid` in the outer sandbox means the inner bwrap creates new namespaces within the existing user namespace. The inner sandbox can be configured to be more permissive than the outer. **Defense gap**: Nesting can potentially weaken isolation if the agent controls `user.conf`.
- **How to verify the defense works**: Start a bwrap sandbox. Inside it, try `sandbox-exec.sh --project-dir /etc -- bash`. Verify the inner sandbox does not provide access to paths blocked by the outer sandbox.

---

**A33**
- **Attack ID**: A33
- **Attack vector**: `io_uring` syscall to bypass filesystem access controls.
- **What the attacker does**: Agent uses `io_uring` to open files asynchronously, potentially bypassing Landlock's `open(2)` interception (if Landlock is only enforced at `openat` level, not `io_uring_enter`).
- **Expected defense**: All three backends block `io_uring` via seccomp-bpf. Firejail: built-in `--seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register`. Landlock: custom filter in `landlock-sandbox.py` (requires kernel ≥ 5.13). Bwrap: generated filter via `generate-seccomp.py`.
- **How to verify the defense works**: Inside each backend, attempt to use `io_uring` for file access. Should fail with EPERM. For bwrap, check stderr for "seccomp" warnings during startup — absence of warnings means the filter is active.

---

**A34**
- **Attack ID**: A34
- **Attack vector**: `userfaultfd` exploitation for race condition in kernel path.
- **What the attacker does**: Agent uses `userfaultfd` to exploit a kernel TOCTOU vulnerability in namespace or mount operations, escaping the sandbox.
- **Expected defense**: All three backends block `userfaultfd` via seccomp-bpf (same mechanism as A33). Additionally, kernels ≥ 5.11 restrict unprivileged `userfaultfd` by default (`vm.unprivileged_userfaultfd=0`).
- **How to verify the defense works**: Inside sandbox, `syscall(SYS_userfaultfd, 0)` returns EPERM.

---

**A35**
- **Attack ID**: A35
- **Attack vector**: `TIOCSTI` ioctl to inject keystrokes into unsandboxed terminal.
- **What the attacker does**: With `BIND_DEV_PTS=true` on kernel < 6.2, the agent accesses the host `/dev/pts` and uses `TIOCSTI` to inject commands into the user's outer terminal session.
- **Expected defense**: `BIND_DEV_PTS=false` (default) — host `/dev/pts` is not exposed. When `BIND_DEV_PTS=true` is required, the sandbox.conf documentation warns that kernel >= 6.2 is required (TIOCSTI disabled by default). Admin should not enable this option on older kernels.
- **How to verify the defense works**: With `BIND_DEV_PTS=false`, `/dev/pts` inside sandbox is a fresh devpts mount (unprivileged) with no access to host ptys.

---

**A36**
- **Attack ID**: A36
- **Attack vector**: Agent submits a Slurm job that runs outside the sandbox.
- **What the attacker does**: Inside a bwrap sandbox, runs `/tmp/.sandbox-slurm-real/sbatch evil_script.sh` using the real sbatch binary mounted at `SLURM_REAL_DIR`. The submitted job runs on a compute node without sandbox.
- **Expected defense**: The bwrap backend moves real sbatch to `SLURM_REAL_DIR=/tmp/.sandbox-slurm-real` and overlays `/usr/bin/sbatch` with a wrapper (`sbatch-sandbox.sh`). The wrapper adds the bypass token and enforces re-sandboxing on the compute node. Direct access to `SLURM_REAL_DIR` is not blocked by bwrap (it is under `/tmp` which is a private tmpfs). The agent inside the sandbox can access the real sbatch at `SLURM_REAL_DIR/sbatch` and submit jobs without the sandbox token.
- **How to verify the defense works**: Inside bwrap sandbox, try `/tmp/.sandbox-slurm-real/sbatch --version`. If it runs, the agent could submit unsandboxed jobs. This is a **known gap** requiring the Slurm-level token enforcement (ADMIN_HARDENING.md §1) as the final defense.

---

*End of test matrix and escape attempt catalogue.*
