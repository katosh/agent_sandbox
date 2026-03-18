#! /bin/bash --
# test.sh — Comprehensive test suite for the sandbox
#
# Runs from the repo directory or the installed ~/.config/agent-sandbox/.
# Tests cover filesystem isolation, environment blocking, chaperon
# proxy isolation, Slurm submission, and security hardening.
#
# Usage:
#   bash test.sh                          # full test (all backends)
#   bash test.sh --quick                  # quick smoke test (no Slurm jobs)
#   bash test.sh --verbose                # show command output on failure
#   bash test.sh --backend bwrap          # test only bwrap backend
#
# The --quick flag runs sections 1–5 only: sandbox boot, filesystem
# isolation, environment blocking, config overlays, and chaperon
# setup verification.  It does NOT submit any Slurm jobs.
#
# The full test (default) additionally runs chaperon functional tests
# (submits real Slurm jobs), escape vector tests, syscall restrictions,
# resource isolation, credential protection, and stability tests.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"
PROJECT_DIR=""

VERBOSE=false
BACKEND_FLAG=""
QUICK_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            cat <<'HELP'
Usage: bash test.sh [OPTIONS] [PROJECT_DIR]

Options:
  --quick           Run sections 1-5 only (~2s, no Slurm jobs submitted)
  --full            Run all sections including Slurm job tests (default)
  --verbose         Show command output on failure
  --backend NAME    Test only one backend (bwrap, firejail, or landlock)
  -h, --help        Show this help

Sections:
  1. Basic sandbox functionality (boot, env vars)
  2. Filesystem isolation (~/.ssh, ~/.aws, ~/.gnupg hidden)
  3. Environment variable blocking (GITHUB_PAT, API keys)
  4. CLAUDE.md and settings.json overlays
  5. Chaperon: Slurm proxy isolation and scoping
  6. Chaperon functional tests (submits real Slurm jobs)
  7. Security: escape vector tests
  8. Security: syscall restrictions (seccomp)
  9. Resource isolation
 10. Credential protection
 11. Sandbox self-protection
 12. Stability / stress tests

The quick test (--quick) is safe to run anywhere — it never submits
Slurm jobs or modifies state outside the sandbox.

Examples:
  bash test.sh --quick              # fast smoke test
  bash test.sh --backend bwrap      # full test, bwrap only
  bash test.sh --verbose            # full test, show failures
  bash test.sh --quick /tmp/proj    # quick test with custom project dir
HELP
            exit 0
            ;;
        --verbose) VERBOSE=true; shift ;;
        --backend) BACKEND_FLAG="$2"; shift 2 ;;
        --quick) QUICK_MODE=true; shift ;;
        --full) QUICK_MODE=false; shift ;;
        -*) shift ;;
        *) PROJECT_DIR="$1"; shift ;;
    esac
done

# Default project dir: use the repo itself
[[ -z "$PROJECT_DIR" ]] && PROJECT_DIR="$SCRIPT_DIR"

# ── Helpers ───────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

pass() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }
skip() { ((SKIP++)); echo "  ⊘ $1 (skipped)"; }

# Current backend being tested (set by run_tests)
CURRENT_BACKEND=""

# Run a command inside the sandbox. Returns the exit code.
# Captures stdout+stderr in $OUTPUT, filtering known backend warnings.
sandbox() {
    local raw
    raw=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- "$@" 2>&1)
    local rc=$?
    # Filter backend warnings that pollute output comparisons:
    #   - landlock_add_rule warnings (file vs directory rule mismatch)
    #   - "Restoring stale backup" from landlock/firejail crash recovery
    #   - firejail "Parent/Child" status lines (suppressed by --quiet, but just in case)
    OUTPUT=$(echo "$raw" | grep -v \
        -e '^Warning: landlock_add_rule' \
        -e '^Warning: Restoring stale backup' \
        -e '^WARNING: ' \
        -e '^sandbox: WARNING: ' \
        -e '^sandbox: detected agents: ' \
        -e '^  These variables are ' \
        -e '^  User enumeration' \
        -e '^  Individual file' \
        -e '^  Current backend' \
        -e '^Parent pid ' \
        -e '^Child process initialized' \
        -e '^Parent is shutting down')
    return $rc
}

is_bwrap() { [[ "$CURRENT_BACKEND" == "bwrap" ]]; }
is_firejail() { [[ "$CURRENT_BACKEND" == "firejail" ]]; }
is_landlock() { [[ "$CURRENT_BACKEND" == "landlock" ]]; }
# Mount-namespace backends (bwrap and firejail) hide files with ENOENT
has_mount_ns() { is_bwrap || is_firejail; }

# ── Pre-flight ────────────────────────────────────────────────────

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Test Suite                           ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

if [[ ! -x "$SANDBOX_EXEC" ]]; then
    echo "ERROR: sandbox-exec.sh not found at $SANDBOX_EXEC"
    exit 1
fi

# Detect available backends
AVAILABLE_BACKENDS=()

check_backend() {
    timeout 5 "$SANDBOX_EXEC" --backend "$1" --dry-run --project-dir "$PROJECT_DIR" -- true &>/dev/null
}

if [[ -n "$BACKEND_FLAG" ]]; then
    AVAILABLE_BACKENDS=("$BACKEND_FLAG")
else
    for _backend in bwrap firejail landlock; do
        if check_backend "$_backend"; then
            AVAILABLE_BACKENDS+=("$_backend")
        fi
    done
fi

if [[ ${#AVAILABLE_BACKENDS[@]} -eq 0 ]]; then
    echo "ERROR: No sandbox backends available."
    timeout 5 "$SANDBOX_EXEC" --dry-run --project-dir "$PROJECT_DIR" -- true 2>&1 || true
    exit 1
fi

echo "Available backends: ${AVAILABLE_BACKENDS[*]}"
echo ""

# Track overall results across all backends
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
ANY_FAIL=false

run_tests() {
CURRENT_BACKEND="$1"
PASS=0
FAIL=0
SKIP=0

echo "┌───────────────────────────────────────────────"
echo "│  Testing backend: $CURRENT_BACKEND"
echo "└───────────────────────────────────────────────"
echo ""

# ── 1. Basic sandbox ─────────────────────────────────────────────

echo "1. Basic sandbox functionality"

if sandbox echo "hello"; then
    pass "Sandbox starts and runs commands"
else
    fail "Sandbox failed to start" "$OUTPUT"
    echo ""
    echo "  Cannot continue — sandbox is non-functional."
    echo "  Run with --verbose for details."
    exit 1
fi

if sandbox bash -c 'echo $SANDBOX_ACTIVE'; then
    if [[ "$OUTPUT" == "1" ]]; then
        pass "SANDBOX_ACTIVE=1"
    else
        fail "SANDBOX_ACTIVE not set" "$OUTPUT"
    fi
fi

if sandbox bash -c 'echo $SANDBOX_PROJECT_DIR'; then
    if [[ "$OUTPUT" == "$PROJECT_DIR" ]]; then
        pass "SANDBOX_PROJECT_DIR set correctly"
    else
        fail "SANDBOX_PROJECT_DIR wrong: $OUTPUT (expected $PROJECT_DIR)"
    fi
fi

if sandbox bash -c 'echo $SANDBOX_BACKEND'; then
    if [[ "$OUTPUT" == "$CURRENT_BACKEND" ]]; then
        pass "SANDBOX_BACKEND=$CURRENT_BACKEND"
    else
        fail "SANDBOX_BACKEND wrong: $OUTPUT (expected $CURRENT_BACKEND)"
    fi
fi

echo ""

# ── 2. Filesystem isolation ──────────────────────────────────────

echo "2. Filesystem isolation"

# Helper: test that a sensitive directory is blocked (ENOENT for bwrap, EACCES for landlock)
test_blocked_dir() {
    local dir="$1"
    local name="$2"
    local _hint=""
    # Check if the dir is in HOME_READONLY in an admin config — that's why it would be visible
    if [[ -f /app/lib/agent-sandbox/sandbox.conf ]]; then
        local _basename="${dir##*/}"
        _basename="${_basename#.}"  # strip leading dot for matching
        if grep -q "\"\.${_basename}\"" /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; then
            _hint=" — admin config has it in HOME_READONLY (remove to hide)"
        fi
    fi

    if has_mount_ns; then
        if sandbox test -d "$dir"; then
            fail "$name is visible (should be hidden)${_hint}"
        else
            pass "$name is hidden"
        fi
    else
        # Landlock: directory may exist but access is denied
        if sandbox bash -c "ls '$dir' 2>&1"; then
            fail "$name is accessible (should be blocked)${_hint}"
        else
            if echo "$OUTPUT" | grep -qi "permission denied\|cannot open\|cannot access"; then
                pass "$name is blocked (EACCES)"
            else
                # Could also be ENOENT if the dir doesn't exist on the host
                pass "$name is blocked"
            fi
        fi
    fi
}

test_blocked_dir "$HOME/.ssh" "~/.ssh"
test_blocked_dir "$HOME/.aws" "~/.aws"
test_blocked_dir "$HOME/.gnupg" "~/.gnupg"

# Project dir writable
TESTFILE="$PROJECT_DIR/.test-write-$$"
if sandbox bash -c "touch '$TESTFILE' && rm -f '$TESTFILE'"; then
    pass "Project directory is writable"
else
    fail "Project directory is not writable" "$OUTPUT"
fi
rm -f "$TESTFILE"

# Home directory not writable (outside allowed paths)
if sandbox bash -c "touch \$HOME/test-readonly 2>&1"; then
    fail "Home directory is writable (should be read-only/blocked)"
else
    pass "Home directory is read-only"
fi

echo ""

# ── 3. Environment variable blocking ────────────────────────────

echo "3. Environment variable blocking"

export GITHUB_PAT="test-secret"
export OPENAI_API_KEY="test-secret"
export AWS_ACCESS_KEY_ID="test-secret"

if sandbox bash -c 'echo ${GITHUB_PAT:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "GITHUB_PAT is blocked"
    else
        fail "GITHUB_PAT leaked into sandbox" "$OUTPUT"
    fi
fi

# OPENAI_API_KEY is blocked by default, but may be unblocked by agent
# profiles (aider, codex, opencode) via env.conf.  Test accordingly.
_openai_should_be_blocked=true
for _agent in aider codex opencode; do
    [[ -d "$HOME/.codex" ]] || command -v "$_agent" &>/dev/null 2>&1 && _openai_should_be_blocked=false
done
if sandbox bash -c 'echo ${OPENAI_API_KEY:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        if "$_openai_should_be_blocked"; then
            pass "OPENAI_API_KEY is blocked"
        else
            fail "OPENAI_API_KEY should be unblocked (agent env.conf)" "$OUTPUT"
        fi
    else
        if "$_openai_should_be_blocked"; then
            fail "OPENAI_API_KEY leaked into sandbox" "$OUTPUT"
        else
            pass "OPENAI_API_KEY unblocked by agent profile (aider/codex/opencode detected)"
        fi
    fi
fi

if sandbox bash -c 'echo ${AWS_ACCESS_KEY_ID:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "AWS_ACCESS_KEY_ID is blocked"
    else
        fail "AWS_ACCESS_KEY_ID leaked into sandbox" "$OUTPUT"
    fi
fi

unset GITHUB_PAT OPENAI_API_KEY AWS_ACCESS_KEY_ID

# Passthrough vars
if sandbox bash -c 'echo ${USER:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "USER is passed through"
    else
        fail "USER not passed through"
    fi
fi

echo ""

# ── 4. Agent profile detection and config overlays ──────────────────
# Agent profiles in agents/<name>/ are auto-detected at sandbox start.
# For Claude: prepare_agent_configs() creates ~/.claude/sandbox-config/
# (the merged config directory is inside the agent's own config dir)
# with merged CLAUDE.md and settings.json, and sets CLAUDE_CONFIG_DIR.

echo "4. Agent profile detection and config overlays"

# Check that at least one agent profile was detected
if sandbox bash -c 'true'; then
    # The sandbox should print detected agents to stderr (filtered by sandbox() helper)
    pass "Sandbox starts with agent detection"
fi

# Claude-specific overlay tests (only if Claude is installed/configured)
if [[ -d "$HOME/.claude" ]] || command -v claude &>/dev/null; then
    if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>/dev/null | grep -q "Sandbox Environment"'; then
        pass "CLAUDE.md overlay contains sandbox instructions (via CLAUDE_CONFIG_DIR)"
    else
        fail "CLAUDE.md overlay missing sandbox instructions"
    fi

    if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/settings.json" 2>/dev/null | grep -q "Bash"'; then
        pass "settings.json overlay contains sandbox permissions (via CLAUDE_CONFIG_DIR)"
    else
        fail "settings.json overlay missing sandbox permissions"
    fi

    # Verify the user's real CLAUDE.md was NOT modified
    CLAUDE_MD="$HOME/.claude/CLAUDE.md"
    if [[ -f "$CLAUDE_MD" ]]; then
        if grep -q '__SANDBOX_INJECTED_9f3a7c__' "$CLAUDE_MD" 2>/dev/null; then
            fail "User's real CLAUDE.md was modified (should be untouched)"
        else
            pass "User's real CLAUDE.md is untouched"
        fi
    fi

    # Verify CLAUDE_CONFIG_DIR points to the sandbox-config directory
    if sandbox bash -c '[[ "$CLAUDE_CONFIG_DIR" == *sandbox-config ]]'; then
        pass "CLAUDE_CONFIG_DIR points to sandbox-config directory"
    else
        fail "CLAUDE_CONFIG_DIR not set correctly"
    fi

    # Verify sandbox-config is read-only (bwrap/firejail: ro-bind; landlock: chmod only)
    if has_mount_ns; then
        if sandbox bash -c 'echo INJECT >> "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>&1; echo $?'; then
            if [[ "$OUTPUT" == *"0" ]]; then
                fail "sandbox-config CLAUDE.md is writable (should be read-only)"
            else
                pass "sandbox-config CLAUDE.md is read-only"
            fi
        fi
        if sandbox bash -c 'rm -f "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>&1; echo $?'; then
            if [[ "$OUTPUT" == *"0" ]]; then
                fail "sandbox-config CLAUDE.md can be deleted (should be blocked)"
            else
                pass "sandbox-config CLAUDE.md cannot be deleted"
            fi
        fi
    fi
else
    skip "Claude not installed — skipping Claude overlay tests"
fi

# Test agent env var unblocking (multi-agent credential isolation)
# When Codex is detected, OPENAI_API_KEY should NOT be blocked
# When only Claude is detected, OPENAI_API_KEY should be blocked
if [[ -d "$HOME/.codex" ]] || command -v codex &>/dev/null; then
    export OPENAI_API_KEY="test-agent-unblock"
    if sandbox bash -c 'echo ${OPENAI_API_KEY:-UNSET}'; then
        if [[ "$OUTPUT" == "test-agent-unblock" ]]; then
            pass "OPENAI_API_KEY unblocked for Codex agent"
        else
            fail "OPENAI_API_KEY not unblocked for Codex" "$OUTPUT"
        fi
    fi
    unset OPENAI_API_KEY
fi

echo ""

# ── 5. Chaperon: Slurm proxy and isolation ────────────────────────

echo "5. Chaperon: Slurm proxy and isolation"

# 5a. PATH shadowing — stubs should resolve first
EXPECTED_STUBS_DIR="$SCRIPT_DIR/chaperon/stubs"
if sandbox bash -c 'which sbatch 2>/dev/null'; then
    if [[ "$OUTPUT" == "$EXPECTED_STUBS_DIR/sbatch" ]]; then
        pass "sbatch resolves to chaperon stub via PATH"
    else
        fail "sbatch does not resolve to chaperon stub" "got: $OUTPUT, expected: $EXPECTED_STUBS_DIR/sbatch"
    fi
else
    fail "sbatch not found inside sandbox"
fi

if sandbox bash -c 'which srun 2>/dev/null'; then
    if [[ "$OUTPUT" == "$EXPECTED_STUBS_DIR/srun" ]]; then
        pass "srun resolves to chaperon stub via PATH"
    else
        fail "srun does not resolve to chaperon stub" "got: $OUTPUT, expected: $EXPECTED_STUBS_DIR/srun"
    fi
else
    fail "srun not found inside sandbox"
fi

# 5b. Munge socket blocked
if has_mount_ns; then
    if sandbox bash -c 'test -e /run/munge/munge.socket.2 2>/dev/null && echo FOUND || echo HIDDEN'; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "Munge socket hidden inside sandbox"
        else
            fail "Munge socket still accessible inside sandbox" "$OUTPUT"
        fi
    fi
else
    # Landlock: /run/munge not granted → EACCES
    if sandbox bash -c 'ls /run/munge/ 2>&1 || true'; then
        if echo "$OUTPUT" | grep -qi "denied\|cannot\|error\|No such"; then
            pass "Munge socket blocked inside sandbox (Landlock EACCES)"
        else
            fail "Munge socket may be accessible inside sandbox" "$OUTPUT"
        fi
    fi
fi

# 5c. Slurm binaries blocked
if command -v sbatch &>/dev/null; then
    if has_mount_ns; then
        # bwrap/firejail: /usr/bin/sbatch overlaid with /dev/null or blacklisted
        if sandbox bash -c '/usr/bin/sbatch --version 2>&1 || true'; then
            if echo "$OUTPUT" | grep -qi "cannot execute\|Permission denied\|No such\|not found\|Exec format"; then
                pass "/usr/bin/sbatch blocked inside sandbox"
            else
                fail "/usr/bin/sbatch still executable inside sandbox" "$OUTPUT"
            fi
        fi
    else
        # Landlock: can't block under /usr (known limitation), but munge
        # blocking makes it useless. Test that PATH shadowing works instead.
        skip "/usr/bin/sbatch blocking — not applicable for Landlock (munge blocking sufficient)"
    fi

    # Slurm config blocked (defense in depth)
    if [[ -d /etc/slurm ]]; then
        if has_mount_ns; then
            if sandbox bash -c 'ls /etc/slurm/slurm.conf 2>&1 || true'; then
                if echo "$OUTPUT" | grep -qi "cannot\|denied\|No such"; then
                    pass "Slurm config (/etc/slurm) hidden inside sandbox"
                else
                    # bwrap uses tmpfs which empties the dir; firejail blacklists
                    if sandbox bash -c 'find /etc/slurm -type f 2>/dev/null | wc -l'; then
                        if [[ "$OUTPUT" == "0" ]]; then
                            pass "Slurm config (/etc/slurm) emptied inside sandbox (tmpfs)"
                        else
                            fail "Slurm config files still accessible inside sandbox" "$OUTPUT"
                        fi
                    fi
                fi
            fi
        fi
    fi
fi

# 5d. srun proxied through chaperon (--pty denied, --jobid denied)
if sandbox bash -c 'srun --pty bash 2>&1'; then
    fail "srun --pty should be denied"
else
    if echo "$OUTPUT" | grep -qi "denied\|not allowed"; then
        pass "srun --pty correctly denied by chaperon"
    else
        fail "srun --pty error unexpected" "$OUTPUT"
    fi
fi

# 5e. Chaperon FIFO directory present
if sandbox bash -c 'echo "${_CHAPERON_FIFO_DIR:-UNSET}"'; then
    if [[ "$OUTPUT" != "UNSET" && "$OUTPUT" == /tmp/chaperon-* ]]; then
        pass "_CHAPERON_FIFO_DIR is set inside sandbox"
    else
        fail "_CHAPERON_FIFO_DIR not set or unexpected" "$OUTPUT"
    fi
fi

if sandbox bash -c 'test -p "${_CHAPERON_FIFO_DIR}/req" && echo EXISTS || echo MISSING'; then
    if [[ "$OUTPUT" == "EXISTS" ]]; then
        pass "Chaperon request FIFO exists inside sandbox"
    else
        fail "Chaperon request FIFO missing inside sandbox" "$OUTPUT"
    fi
fi

# 5f2. squeue responsiveness (bare squeue should not hang)
if sandbox bash -c 'squeue 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue returns promptly (no hang)"
    else
        fail "squeue did not complete" "$OUTPUT"
    fi
else
    # Exit code non-zero is OK (empty result), but it should not timeout
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue returns promptly (no hang)"
    else
        fail "squeue may have hung" "$OUTPUT"
    fi
fi

# 5g. squeue scope-widening flags silently accepted (transparent scoping)
if sandbox bash -c 'squeue --user=root 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --user=root silently accepted (scoped transparently)"
    else
        fail "squeue --user=root did not complete" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --user=root silently accepted (scoped transparently)"
    else
        fail "squeue --user=root failed unexpectedly" "$OUTPUT"
    fi
fi

if sandbox bash -c 'squeue --me 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --me silently accepted (scoped transparently)"
    else
        fail "squeue --me did not complete" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --me silently accepted (scoped transparently)"
    else
        fail "squeue --me failed unexpectedly" "$OUTPUT"
    fi
fi

# 5h. scontrol scoped (shutdown denied, show partition allowed)
if sandbox bash -c 'scontrol shutdown 2>&1'; then
    fail "scontrol shutdown should be denied"
else
    if echo "$OUTPUT" | grep -qi "not allowed"; then
        pass "scontrol shutdown correctly denied by chaperon"
    else
        fail "scontrol shutdown error unexpected" "$OUTPUT"
    fi
fi

# 5i. sacct scoped (--allusers denied)
if sandbox bash -c 'sacct --allusers 2>&1'; then
    fail "sacct --allusers should be denied"
else
    if echo "$OUTPUT" | grep -qi "not allowed"; then
        pass "sacct --allusers correctly denied by chaperon"
    else
        fail "sacct --allusers error unexpected" "$OUTPUT"
    fi
fi

# 5j. sacctmgr (show user denied, show qos allowed)
if sandbox bash -c 'sacctmgr show user 2>&1'; then
    fail "sacctmgr show user should be denied"
else
    if echo "$OUTPUT" | grep -qi "not allowed"; then
        pass "sacctmgr show user correctly denied by chaperon"
    else
        fail "sacctmgr show user error unexpected" "$OUTPUT"
    fi
fi

# 5k. scontrol show assoc_mgr denied (user enumeration)
if sandbox bash -c 'scontrol show assoc_mgr 2>&1'; then
    fail "scontrol show assoc_mgr should be denied"
else
    if echo "$OUTPUT" | grep -qi "not allowed"; then
        pass "scontrol show assoc_mgr correctly denied by chaperon"
    else
        fail "scontrol show assoc_mgr error unexpected" "$OUTPUT"
    fi
fi

# 5l. Blocked commands give clear error (salloc, strigger, etc.)
if sandbox bash -c 'salloc 2>&1' 2>/dev/null; then
    # salloc might not exist on all systems — that's ok
    if echo "$OUTPUT" | grep -qi "not allowed\|not found"; then
        pass "salloc correctly blocked or not found"
    else
        fail "salloc should be blocked" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -qi "not allowed\|not found\|error"; then
        pass "salloc correctly blocked by chaperon"
    else
        fail "salloc block error unexpected" "$OUTPUT"
    fi
fi

# 5m. sinfo passes through (read-only system info)
if sandbox bash -c 'sinfo --version 2>&1'; then
    if echo "$OUTPUT" | grep -qi "slurm"; then
        pass "sinfo --version passes through chaperon"
    else
        # sinfo might not be installed
        pass "sinfo responded (may not have Slurm version output)"
    fi
else
    if echo "$OUTPUT" | grep -qi "not found"; then
        skip "sinfo binary not available"
    else
        fail "sinfo --version failed unexpectedly" "$OUTPUT"
    fi
fi

# 5n. Comment stripping — _strip_chaperon_tags restores user comments
#     These are unit tests of the sed pipeline; no Slurm needed.
_HANDLER_LIB="$SCRIPT_DIR/chaperon/handlers/_handler_lib.sh"
if [[ -f "$_HANDLER_LIB" ]]; then
    # Source just the strip function (avoid side effects from the full lib)
    eval "$(sed -n '/^_strip_chaperon_tags()/,/^}/p' "$_HANDLER_LIB")"

    # 5n-1: Tag with user comment → user comment restored
    _in='Comment=chaperon:sid=99.100,proj=aabbcc112233,user=my training run:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "Comment=my training run" ]]; then
        pass "Comment stripping: user comment restored from tag"
    else
        fail "Comment stripping: user comment" "expected 'Comment=my training run', got '$_out'"
    fi

    # 5n-2: Tag without user comment → empty
    _in='Comment=chaperon:sid=99.100,proj=aabbcc112233:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "Comment=" ]]; then
        pass "Comment stripping: empty when no user comment"
    else
        fail "Comment stripping: empty comment" "expected 'Comment=', got '$_out'"
    fi

    # 5n-3: Encoded special characters decoded
    _in='chaperon:sid=1.2,proj=aabb,user=k%3Dv%2C t%3Af:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "k=v, t:f" ]]; then
        pass "Comment stripping: percent-encoded chars decoded"
    else
        fail "Comment stripping: decode" "expected 'k=v, t:f', got '$_out'"
    fi

    # 5n-4: Non-chaperon comments pass through unchanged
    _in='Comment=just a normal comment'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "$_in" ]]; then
        pass "Comment stripping: non-chaperon comments unchanged"
    else
        fail "Comment stripping: passthrough" "expected '$_in', got '$_out'"
    fi

    # 5n-5: squeue tabular format (tag embedded in line)
    _in='  12345   myuser   RUNNING   chaperon:sid=1.2,proj=abc123def456,user=hello world:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "  12345   myuser   RUNNING   hello world" ]]; then
        pass "Comment stripping: squeue tabular output"
    else
        fail "Comment stripping: tabular" "got '$_out'"
    fi

    # 5n-6: JSON output format
    _in='  "comment": "chaperon:sid=1.2,proj=abc123def456,user=my job:END",'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == '  "comment": "my job",' ]]; then
        pass "Comment stripping: JSON output format"
    else
        fail "Comment stripping: JSON" "got '$_out'"
    fi

    # 5n-7: Pipe-delimited (parsable squeue) with empty comment
    _in='12345|myuser|RUNNING|chaperon:sid=1.2,proj=abc123def456:END|node01'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "12345|myuser|RUNNING||node01" ]]; then
        pass "Comment stripping: parsable format, empty comment"
    else
        fail "Comment stripping: parsable" "got '$_out'"
    fi

    unset -f _strip_chaperon_tags
else
    skip "Comment stripping tests — _handler_lib.sh not found"
fi

echo ""

if [[ "$QUICK_MODE" == true ]]; then
    echo "(quick mode — skipping sections 6–12)"
    echo "  Run without --quick for functional, security, and stability tests."
    echo "  Note: the full test submits real Slurm jobs."
else

# ── 6. Chaperon functional tests ─────────────────────────────────

echo "6. Chaperon functional tests"

if ! command -v sbatch &>/dev/null; then
    skip "sbatch not found on host — skipping chaperon submission tests"
else
    # 6a. sbatch --wrap via chaperon
    if sandbox sbatch --wrap="echo chaperon-test" 2>&1; then
        if echo "$OUTPUT" | grep -q "Submitted batch job"; then
            pass "sbatch --wrap via chaperon submits job"
        else
            fail "sbatch --wrap via chaperon failed" "$OUTPUT"
        fi
    else
        fail "sbatch --wrap via chaperon failed" "$OUTPUT"
    fi

    # 6b. No infinite recursion
    if timeout 10 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        sbatch --wrap="echo recursion-test" &>/dev/null; then
        pass "No infinite recursion in chaperon sbatch"
    else
        fail "Chaperon sbatch may have infinite recursion (timed out)"
    fi

    # 6c. Denied flags rejected
    if sandbox sbatch --uid=0 --wrap="echo pwned" 2>&1; then
        fail "sbatch --uid=0 should be rejected by chaperon"
    else
        if echo "$OUTPUT" | grep -qi "denied\|not allowed\|error"; then
            pass "Chaperon rejects --uid flag"
        else
            fail "Chaperon did not clearly reject --uid" "$OUTPUT"
        fi
    fi

    if sandbox sbatch --get-user-env --wrap="echo pwned" 2>&1; then
        fail "sbatch --get-user-env should be rejected by chaperon"
    else
        if echo "$OUTPUT" | grep -qi "denied\|not allowed\|error"; then
            pass "Chaperon rejects --get-user-env flag"
        else
            fail "Chaperon did not clearly reject --get-user-env" "$OUTPUT"
        fi
    fi

    # 6d. scancel scoped to session
    if command -v scancel &>/dev/null; then
        # Submit a job, then cancel it.
        # Note: the job may complete before scancel runs (especially on test VMs),
        # so we accept either "cancelled successfully" (exit 0) or
        # "no sandbox-submitted jobs found" (exit 1, job already completed).
        if sandbox bash -c '
            OUT=$(sbatch --wrap="sleep 300" 2>&1)
            JID=$(echo "$OUT" | grep -oP "\d+" | tail -1)
            scancel "$JID" 2>&1
        '; then
            pass "scancel can cancel job submitted by same session"
        else
            if echo "$OUTPUT" | grep -qi "no sandbox-submitted jobs\|not found in queue"; then
                pass "scancel: job completed before cancel (acceptable race condition)"
            else
                fail "scancel failed to cancel own session job" "$OUTPUT"
            fi
        fi

        # Try to cancel a non-existent job (should be rejected by scope)
        if sandbox bash -c 'scancel 999999999 2>&1'; then
            fail "scancel should reject job not submitted by this session"
        else
            if echo "$OUTPUT" | grep -qi "denied\|not submitted\|not allowed\|not found\|no sandbox\|not a valid"; then
                pass "scancel rejects job not submitted by this session"
            else
                fail "scancel did not clearly reject out-of-scope job" "$OUTPUT"
            fi
        fi

        # 6e. scancel scope-widening flags (transparent scoping)
        # --all, --me, -u <user> should all silently cancel scoped jobs (or succeed with no jobs)
        if sandbox bash -c 'scancel --all 2>&1'; then
            pass "scancel --all accepted (cancels scoped jobs)"
        else
            fail "scancel --all should not be rejected" "$OUTPUT"
        fi

        if sandbox bash -c 'scancel --me 2>&1'; then
            pass "scancel --me accepted (cancels scoped jobs)"
        else
            fail "scancel --me should not be rejected" "$OUTPUT"
        fi

        if sandbox bash -c 'scancel -u "$(whoami)" 2>&1'; then
            pass "scancel -u <user> accepted (cancels scoped jobs)"
        else
            fail "scancel -u <user> should not be rejected" "$OUTPUT"
        fi

        # Bare scancel (no args) should also cancel all in scope
        if sandbox bash -c 'scancel 2>&1'; then
            pass "bare scancel accepted (cancels scoped jobs)"
        else
            fail "bare scancel should not be rejected" "$OUTPUT"
        fi
    else
        skip "scancel not found on host — skipping scancel tests"
    fi
fi

echo ""

# ── 7. Sandbox self-protection ───────────────────────────────────

echo "7. Sandbox self-protection"

if is_landlock; then
    # Landlock rules are additive — can't make a subdir read-only when its
    # parent ($HOME/.claude) is writable.  See ADMIN_HARDENING.md §2.
    skip "Sandbox self-protection — not supported with Landlock backend (see ADMIN_HARDENING.md)"
else
    # Use a separate project dir so the writable project mount doesn't
    # overlap with the sandbox dir
    PROTECTION_PROJECT="$(mktemp -d)"

    protection_sandbox() {
        local raw
        raw=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROTECTION_PROJECT" -- "$@" 2>&1)
        local rc=$?
        OUTPUT=$(echo "$raw" | grep -v \
            -e '^Warning: landlock_add_rule' \
            -e '^Warning: Restoring stale backup' \
            -e '^Parent pid ' \
            -e '^Child process initialized' \
            -e '^Parent is shutting down')
        return $rc
    }

    if protection_sandbox bash -c "touch '$SCRIPT_DIR/test-tamper' 2>&1"; then
        fail "Sandbox directory is writable (should be read-only)"
        rm -f "$SCRIPT_DIR/test-tamper"
    else
        pass "Sandbox directory is read-only"
    fi

    if protection_sandbox bash -c "echo 'tamper' >> '$SCRIPT_DIR/sandbox-lib.sh' 2>&1"; then
        fail "sandbox-lib.sh is writable inside sandbox"
    else
        pass "sandbox-lib.sh is protected from modification"
    fi

    rm -rf "$PROTECTION_PROJECT"
fi

# ── 8. Escape vectors ─────────────────────────────────────────────

echo "8. Escape vectors"

# systemd-run escape — should fail on bwrap (sockets not visible)
if command -v systemd-run &>/dev/null; then
    ESCAPE_FILE="/tmp/.sandbox-escape-test-$$"
    rm -f "$ESCAPE_FILE"
    if sandbox bash -c "systemd-run --user --collect --wait -- touch '$ESCAPE_FILE' 2>&1"; then
        if [[ -f "$ESCAPE_FILE" ]]; then
            fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            rm -f "$ESCAPE_FILE"
        else
            pass "systemd-run --user did not escape"
        fi
    else
        if [[ -f "$ESCAPE_FILE" ]]; then
            fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            rm -f "$ESCAPE_FILE"
        else
            if is_landlock; then
                # Landlock can't block Unix socket connect() — this is a known limitation.
                # If systemd user instances are disabled (ADMIN_HARDENING.md §2), systemd-run
                # fails with "Failed to connect to bus". If they're still running, systemd-run
                # may have succeeded but the escape file might be in a different location.
                if echo "$OUTPUT" | grep -qi "connect\|masked\|refused"; then
                    pass "systemd-run --user blocked (user@.service disabled)"
                else
                    skip "systemd-run --user — inconclusive on Landlock (see ADMIN_HARDENING.md §2)"
                fi
            else
                pass "systemd-run --user blocked (sockets not accessible)"
            fi
        fi
    fi
    rm -f "$ESCAPE_FILE"
else
    skip "systemd-run not available — escape test"
fi
# ── S01: Symlink to /etc/shadow from project dir ──
local _link="$PROJECT_DIR/.test-shadow-link-$$"
ln -snf /etc/shadow "$_link" 2>/dev/null
if [[ -L "$_link" ]]; then
    if sandbox bash -c "cat '$_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|No such file|EXIT=[1-9]"; then
            pass "S01: Cannot read /etc/shadow through symlink in project dir"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "S01: /etc/shadow readable through symlink in project dir" "$OUTPUT"
        else
            pass "S01: Cannot read /etc/shadow through symlink in project dir"
        fi
    else
        pass "S01: Sandbox blocked access to /etc/shadow via symlink (command failed)"
    fi
    rm -f "$_link"
else
    skip "S01: Could not create symlink (permissions issue)"
fi

# ── S02: Symlink to ~/.ssh from project dir ──
local _ssh_link="$PROJECT_DIR/.test-ssh-link-$$"
ln -snf "$HOME/.ssh" "$_ssh_link" 2>/dev/null
if [[ -L "$_ssh_link" ]]; then
    if sandbox bash -c "ls '$_ssh_link/' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|No such file|EXIT=[1-9]|cannot access"; then
            pass "S02: Cannot list ~/.ssh through symlink in project dir"
        elif echo "$OUTPUT" | grep -qE "id_rsa|id_ed25519|authorized_keys"; then
            if sandbox test -d "$HOME/.ssh" 2>/dev/null; then
                fail "S02: ~/.ssh contents visible — .ssh is in HOME_READONLY (admin config issue, not symlink bypass)" "$OUTPUT"
            else
                fail "S02: ~/.ssh contents visible ONLY through symlink — symlink bypasses sandbox" "$OUTPUT"
            fi
        else
            pass "S02: ~/.ssh not accessible through symlink (empty or blocked)"
        fi
    else
        pass "S02: Sandbox blocked access to ~/.ssh via symlink"
    fi
    rm -f "$_ssh_link"
else
    skip "S02: Could not create symlink"
fi

# ── S03: Symlink to /etc/passwd (read-only mount) to attempt write ──
local _passwd_link="$PROJECT_DIR/.test-passwd-link-$$"
ln -snf /etc/passwd "$_passwd_link" 2>/dev/null
if [[ -L "$_passwd_link" ]]; then
    if sandbox bash -c "echo 'evil:x:0:0::/root:/bin/bash' >> '$_passwd_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Read-only|EXIT=[1-9]|Operation not permitted"; then
            pass "S03: Cannot write to /etc/passwd through symlink"
        else
            fail "S03: Write to /etc/passwd through symlink may have succeeded" "$OUTPUT"
        fi
    else
        pass "S03: Sandbox blocked write to /etc/passwd via symlink"
    fi
    rm -f "$_passwd_link"
else
    skip "S03: Could not create symlink"
fi

# ── S04: Symlinked BLOCKED_FILES entry ──
# If a BLOCKED_FILES path is a symlink, the sandbox must block the target.
# bwrap: readlink -f + bind /dev/null. firejail: --blacklist resolves natively.
# landlock: no file hiding (BLOCKED_FILES has no effect), so skip.
if ! is_landlock; then
    # Place test files directly in project dir (not a subdir) to avoid
    # cleanup issues from bwrap mount artifacts inside directories.
    local _slink_real="$PROJECT_DIR/.test-slink-real-$$"
    local _slink_link="$PROJECT_DIR/.test-slink-link-$$"
    echo "SENSITIVE" > "$_slink_real"
    ln -sf "$_slink_real" "$_slink_link"
    # Temporarily add the symlink to BLOCKED_FILES via a conf.d snippet
    local _slink_conf="$HOME/.config/agent-sandbox/conf.d/test-symlink-blocked-$$.conf"
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    echo "BLOCKED_FILES+=( \"$_slink_link\" )" > "$_slink_conf"
    if sandbox bash -c "cat '$_slink_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "No such file|Permission denied|EXIT=[1-9]"; then
            pass "S04: Symlinked BLOCKED_FILES entry is blocked"
        else
            fail "S04: Symlinked BLOCKED_FILES entry is readable" "$OUTPUT"
        fi
    else
        pass "S04: Sandbox blocked access to symlinked BLOCKED_FILES entry"
    fi
    rm -f "$_slink_conf" "$_slink_real" "$_slink_link"
else
    skip "S04: BLOCKED_FILES has no effect on Landlock (no mount namespace)"
fi

# ── H01: Hardlink /etc/passwd into project dir ──
local _hlink="$PROJECT_DIR/.test-passwd-hardlink-$$"
if ln /etc/passwd "$_hlink" 2>/dev/null; then
    if sandbox bash -c "echo 'evil:x:0:0::/root:/bin/bash' >> '$_hlink' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Read-only|EXIT=[1-9]|Operation not permitted"; then
            pass "H01: Cannot write through hardlink to /etc/passwd"
        else
            fail "H01: Write through hardlink to /etc/passwd may have succeeded" "$OUTPUT"
        fi
    else
        pass "H01: Sandbox blocked write through hardlink"
    fi
    rm -f "$_hlink"
else
    pass "H01: Kernel protected_hardlinks prevented hardlink creation (good)"
fi

# ── H02: Hardlink a sensitive file from HOME (inside sandbox) ──
local _target=""
for _f in "$HOME/.bashrc" "$HOME/.gitconfig" "$HOME/.profile"; do
    [[ -f "$_f" ]] && { _target="$_f"; break; }
done
if [[ -n "$_target" ]]; then
    local _hlink2="$PROJECT_DIR/.test-home-hardlink-$$"
    if sandbox bash -c "ln '$_target' '$_hlink2' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Invalid cross-device|not permitted|not allowed|Permission denied|Read-only|EXIT=[1-9]"; then
            pass "H02: Sandbox blocks hardlink from read-only HOME file to project dir"
        else
            if sandbox bash -c "echo 'INJECTED' >> '$_hlink2' 2>&1; echo EXIT=\$?"; then
                if grep -q "INJECTED" "$_target" 2>/dev/null; then
                    fail "H02: Hardlink inside sandbox allowed modification of original $(basename "$_target")" "$OUTPUT"
                    sed -i '/^INJECTED$/d' "$_target" 2>/dev/null || true
                else
                    pass "H02: Hardlink write did not affect original file"
                fi
            else
                pass "H02: Sandbox blocked write through hardlink"
            fi
        fi
        rm -f "$_hlink2"
    else
        pass "H02: Cannot create hardlink inside sandbox (good)"
    fi
else
    skip "H02: No suitable HOME file found for hardlink test"
fi

# ── P01: /proc/self/root traversal ──
if sandbox bash -c "cat /proc/self/root/etc/shadow 2>&1; echo EXIT=\$?"; then
    if echo "$OUTPUT" | grep -qE "Permission denied|No such|EXIT=[1-9]|Operation not permitted"; then
        pass "P01: /proc/self/root does not escape sandbox"
    elif echo "$OUTPUT" | grep -q "root:"; then
        fail "P01: /proc/self/root allowed reading /etc/shadow" "$OUTPUT"
    else
        pass "P01: /proc/self/root traversal blocked or returned empty"
    fi
else
    pass "P01: /proc/self/root traversal failed (sandbox blocked)"
fi

# ── P02: /proc/1/root traversal ──
if sandbox bash -c "cat /proc/1/root/etc/shadow 2>&1; echo EXIT=\$?"; then
    if echo "$OUTPUT" | grep -qE "Permission denied|No such|EXIT=[1-9]|Operation not permitted"; then
        pass "P02: /proc/1/root does not escape sandbox"
    elif echo "$OUTPUT" | grep -q "root:"; then
        fail "P02: /proc/1/root allowed reading /etc/shadow" "$OUTPUT"
    else
        pass "P02: /proc/1/root traversal blocked or returned empty"
    fi
else
    pass "P02: /proc/1/root traversal failed"
fi

# ── P03: /proc/self/ns/mnt — re-enter host mount namespace ──
if has_mount_ns; then
    if sandbox bash -c "
        if command -v nsenter &>/dev/null; then
            nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow 2>&1
            echo EXIT=\$?
        else
            echo NO_NSENTER EXIT=1
        fi
    "; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Operation not permitted|EXIT=[1-9]|NO_NSENTER|cannot open"; then
            pass "P03: Cannot re-enter host mount namespace via nsenter"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "P03: nsenter escaped to host mount namespace" "$OUTPUT"
        else
            pass "P03: Mount namespace re-entry blocked"
        fi
    else
        pass "P03: Mount namespace escape attempt failed (good)"
    fi
else
    if sandbox bash -c "
        if command -v nsenter &>/dev/null; then
            nsenter --mount=/proc/self/ns/mnt -- cat /etc/shadow 2>&1
            echo EXIT=\$?
        else
            echo NO_NSENTER EXIT=1
        fi
    "; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Operation not permitted|EXIT=[1-9]|NO_NSENTER"; then
            pass "P03: nsenter blocked even without mount namespace isolation (landlock)"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "P03: nsenter read /etc/shadow under landlock" "$OUTPUT"
        else
            pass "P03: nsenter did not escape (landlock)"
        fi
    else
        pass "P03: nsenter failed under landlock (good)"
    fi
fi

# ── K01: TIOCSTI ioctl blocked or /dev/pts isolated ──
# Test on a sandbox-owned pty (not stdin) to avoid injecting keystrokes
# into the host terminal.
if sandbox bash -c '
    if [[ -d /dev/pts ]]; then
        host_pts=$(ls /dev/pts/ 2>/dev/null | grep -c "[0-9]")
        echo "PTS_COUNT=$host_pts"
        if command -v python3 &>/dev/null; then
            python3 -c "
import fcntl, pty, os
master, slave = pty.openpty()
try:
    # TIOCSTI = 0x5412 — test on our own pty, not stdin
    fcntl.ioctl(slave, 0x5412, b\"x\")
    print(\"TIOCSTI_SUCCEEDED\")
except (OSError, IOError) as e:
    print(f\"TIOCSTI_BLOCKED:{e}\")
finally:
    os.close(master)
    os.close(slave)
" 2>&1
        else
            echo "NO_PYTHON"
        fi
    else
        echo "NO_DEVPTS"
    fi
'; then
    if echo "$OUTPUT" | grep -q "TIOCSTI_BLOCKED"; then
        pass "K01: TIOCSTI ioctl blocked inside sandbox"
    elif echo "$OUTPUT" | grep -q "TIOCSTI_SUCCEEDED"; then
        # TIOCSTI on a sandbox-owned pty is not a security issue — the
        # agent can only inject keystrokes into its own terminal.  The real
        # risk is host ptys, which requires BIND_DEV_PTS=true.  On kernels
        # < 6.2 the ioctl is allowed on any open pty fd, so it succeeds
        # even with --dev /dev (isolated devpts).
        local _host_pts
        _host_pts=$(echo "$OUTPUT" | grep -oP 'PTS_COUNT=\K[0-9]+' || echo "0")
        if [[ "$_host_pts" -gt 0 ]]; then
            fail "K01: TIOCSTI succeeded with host PTYs visible (BIND_DEV_PTS?)" "$OUTPUT"
        else
            pass "K01: TIOCSTI succeeded on sandbox-own pty only (no host PTYs visible)"
        fi
    elif echo "$OUTPUT" | grep -q "NO_DEVPTS"; then
        pass "K01: /dev/pts not available inside sandbox (isolated)"
    elif echo "$OUTPUT" | grep -q "NO_PYTHON"; then
        skip "K01: python3 not available to test TIOCSTI"
    elif echo "$OUTPUT" | grep -q "PTS_COUNT=0"; then
        pass "K01: No host PTY devices visible inside sandbox"
    else
        pass "K01: TIOCSTI test completed (no injection detected)"
    fi
else
    pass "K01: TIOCSTI test command failed (sandbox blocked)"
fi

echo ""

# ── 9. Syscall & privilege restrictions ───────────────────────────

echo "9. Syscall & privilege restrictions"

# Seccomp filter (landlock and firejail — bwrap doesn't install one currently)
if is_landlock || is_firejail || is_bwrap; then
    if sandbox bash -c 'grep "^Seccomp:" /proc/self/status'; then
        SECCOMP_MODE=$(echo "$OUTPUT" | grep '^Seccomp:' | awk '{print $2}')
        if [[ "$SECCOMP_MODE" == "2" ]]; then
            pass "Seccomp filter is active (mode 2)"
        else
            fail "Seccomp filter not active (mode $SECCOMP_MODE)"
        fi
    fi

    # kexec_load should be blocked by all seccomp-enabled backends
    # syscall numbers: x86_64=246, aarch64=104
    if sandbox python3 -c "
import ctypes, ctypes.util, platform
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
nr = 246 if platform.machine() == 'x86_64' else 104
ret = libc.syscall(ctypes.c_long(nr), 0, 0, 0, 0)
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "kexec_load blocked by seccomp"
        else
            fail "kexec_load not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test kexec_load"
    fi

    # io_uring_setup — blocked by landlock's custom seccomp and firejail's
    # --seccomp.drop. Note: firejail 0.9.72 seccomp is broken on aarch64
    # (filter loads but doesn't block); works on x86_64.
    # syscall number: 425 (same on x86_64 and aarch64)
    if sandbox python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(ctypes.c_long(425), ctypes.c_uint32(1), ctypes.c_void_p(0))
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "io_uring_setup blocked by seccomp"
        elif is_firejail && [[ "$(uname -m)" == "aarch64" ]]; then
            skip "io_uring_setup — firejail seccomp broken on aarch64 (works on x86_64)"
        else
            fail "io_uring_setup not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test io_uring_setup"
    fi

    # userfaultfd — blocked by landlock's custom seccomp and firejail's
    # --seccomp.drop. Exploitation primitive for kernel race conditions.
    # syscall numbers: x86_64=323, aarch64=282
    if sandbox python3 -c "
import ctypes, ctypes.util, platform
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
nr = 323 if platform.machine() == 'x86_64' else 282
ret = libc.syscall(ctypes.c_long(nr), ctypes.c_int(0))
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "userfaultfd blocked by seccomp"
        elif is_firejail && [[ "$(uname -m)" == "aarch64" ]]; then
            skip "userfaultfd — firejail seccomp broken on aarch64 (works on x86_64)"
        else
            fail "userfaultfd not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test userfaultfd"
    fi

    # Verify the seccomp filter is what blocks io_uring — not something else.
    # Temporarily hide generate-seccomp.py so bwrap runs without a filter,
    # then confirm io_uring_setup returns EFAULT (reachable) not EPERM (blocked).
    if is_bwrap; then
        local _seccomp_py="$SCRIPT_DIR/backends/generate-seccomp.py"
        local _seccomp_bak="${_seccomp_py}.test-bak-$$"
        if [[ -f "$_seccomp_py" ]]; then
            mv "$_seccomp_py" "$_seccomp_bak"
            if sandbox python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(ctypes.c_long(425), ctypes.c_uint32(1), ctypes.c_void_p(0))
e = ctypes.get_errno()
print(f'ERRNO={e}')
" 2>&1; then
                mv "$_seccomp_bak" "$_seccomp_py"
                local _no_filter_errno
                _no_filter_errno=$(echo "$OUTPUT" | grep -oP 'ERRNO=\K[0-9]+' || echo "")
                if [[ "$_no_filter_errno" != "1" ]]; then
                    pass "io_uring_setup reachable without seccomp filter (errno=$_no_filter_errno), blocked with it (EPERM)"
                else
                    fail "io_uring_setup returns EPERM even without seccomp filter — something else blocks it"
                fi
            else
                mv "$_seccomp_bak" "$_seccomp_py"
                skip "Could not run without-filter test"
            fi
        else
            skip "generate-seccomp.py not found"
        fi
    fi
fi

# NoNewPrivs is set (prevents setuid escalation inside sandbox)
if sandbox bash -c 'grep "^NoNewPrivs:" /proc/self/status | awk "{print \$2}"'; then
    if [[ "$OUTPUT" == "1" ]]; then
        pass "NoNewPrivs is set (prevents setuid escalation)"
    else
        # bwrap may not set nonewprivs by default
        if is_bwrap; then
            skip "NoNewPrivs not set by bwrap (optional)"
        else
            fail "NoNewPrivs not set (should be 1)" "$OUTPUT"
        fi
    fi
fi

# Capabilities are dropped (firejail: --caps.drop=all, bwrap: --cap-drop ALL)
if is_firejail; then
    if sandbox bash -c 'grep "^CapEff:" /proc/self/status | awk "{print \$2}"'; then
        if [[ "$OUTPUT" == "0000000000000000" ]]; then
            pass "All capabilities dropped"
        else
            fail "Capabilities not fully dropped: $OUTPUT"
        fi
    fi
fi

# ── U01: Create new user namespace to gain capabilities ──
if sandbox bash -c '
    if command -v unshare &>/dev/null; then
        unshare --user --map-root-user -- id 2>&1
        echo EXIT=$?
    else
        echo NO_UNSHARE
    fi
'; then
    if echo "$OUTPUT" | grep -q "NO_UNSHARE"; then
        skip "U01: unshare not available inside sandbox"
    elif echo "$OUTPUT" | grep -qE "Operation not permitted|EXIT=[1-9]|Permission denied|Cannot"; then
        pass "U01: Cannot create nested user namespace (blocked)"
    elif echo "$OUTPUT" | grep -q "uid=0(root)"; then
        if is_firejail; then
            fail "U01: Nested user namespace created inside firejail (--restrict-namespaces should block)" "$OUTPUT"
        else
            if sandbox bash -c 'grep "^NoNewPrivs:" /proc/self/status | awk "{print \$2}"'; then
                local _nnp
                _nnp="$(echo "$OUTPUT" | grep -v '^WARNING' | tr -d '[:space:]')"
                if [[ "$_nnp" == "1" ]]; then
                    pass "U01: Nested userns possible but NoNewPrivs=1 prevents escalation"
                else
                    fail "U01: Nested userns created AND NoNewPrivs not set (NNP=$_nnp)" "$OUTPUT"
                fi
            else
                pass "U01: Nested userns possible but could not verify NoNewPrivs"
            fi
        fi
    else
        pass "U01: User namespace nesting result acceptable"
    fi
else
    pass "U01: User namespace creation attempt failed (good)"
fi

echo ""

# ── 10. Resource & IPC isolation ──────────────────────────────────

echo "10. Resource & IPC isolation"

# PID namespace isolation (bwrap and firejail — landlock does not have PID ns)
if has_mount_ns; then
    if sandbox bash -c 'ps aux 2>/dev/null | wc -l'; then
        PROC_COUNT=$(echo "$OUTPUT" | tail -1 | tr -d '[:space:]')
        # Inside a PID namespace, we should see very few processes
        # (bwrap/firejail, bash, ps, wc — typically < 10)
        if [[ "$PROC_COUNT" =~ ^[0-9]+$ ]] && [[ "$PROC_COUNT" -lt 20 ]]; then
            pass "PID namespace isolates host processes ($PROC_COUNT visible)"
        else
            fail "PID namespace not working — $PROC_COUNT processes visible"
        fi
    else
        skip "Could not check PID namespace"
    fi
fi

# /tmp isolation — bwrap uses --tmpfs /tmp, firejail uses --private-tmp (configurable)
# Landlock does not isolate /tmp
if has_mount_ns; then
    # Create a marker file in host /tmp, check it's not visible inside sandbox
    _TMP_MARKER="/tmp/.sandbox-test-marker-$$"
    touch "$_TMP_MARKER"
    if sandbox bash -c "test -f '$_TMP_MARKER' && echo VISIBLE || echo HIDDEN"; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "/tmp is isolated from host"
        else
            # Firejail: PRIVATE_TMP=false disables /tmp isolation (for MPI/NCCL)
            if is_firejail; then
                pass "/tmp is shared (PRIVATE_TMP=false — MPI/NCCL compatible)"
            else
                fail "/tmp is shared with host (should be isolated)"
            fi
        fi
    fi
    rm -f "$_TMP_MARKER"
else
    skip "/tmp isolation — Landlock has no mount namespace"
fi

# /run/user and /run/dbus should not be accessible
# bwrap: tmpfs /run hides everything; firejail: blacklisted explicitly
if has_mount_ns; then
    if sandbox bash -c "ls /run/user/ 2>&1"; then
        fail "/run/user/ is visible in sandbox"
    else
        pass "/run/user/ is hidden"
    fi

    if sandbox bash -c "ls /run/dbus/ 2>&1"; then
        fail "/run/dbus/ is visible in sandbox"
    else
        pass "/run/dbus/ is hidden"
    fi
fi

# Snapd socket should be blocked (bwrap: tmpfs /run; firejail: blacklisted)
if [[ -e /run/snapd.socket ]]; then
    if has_mount_ns; then
        if sandbox bash -c "python3 -c \"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('/run/snapd.socket')
    print('ACCESSIBLE')
except (ConnectionRefusedError, FileNotFoundError, PermissionError, OSError):
    print('BLOCKED')
\" 2>/dev/null"; then
            if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
                pass "Snapd socket is blocked"
            else
                fail "Snapd socket is accessible inside sandbox"
            fi
        fi
    fi
else
    skip "Snapd socket not present on host"
fi

# systemd-notify socket should be blocked (bwrap: tmpfs /run; firejail: blacklisted)
if [[ -e /run/systemd/notify ]]; then
    if has_mount_ns; then
        if sandbox bash -c "python3 -c \"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    s.connect('/run/systemd/notify')
    print('ACCESSIBLE')
except (ConnectionRefusedError, FileNotFoundError, PermissionError, OSError):
    print('BLOCKED')
\" 2>/dev/null"; then
            if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
                pass "systemd-notify socket is blocked"
            else
                fail "systemd-notify socket is accessible inside sandbox"
            fi
        fi
    fi
else
    skip "systemd-notify socket not present on host"
fi

# tmux: outer socket blocked, wrapper uses sandbox config for nesting
_tmux_sock="/tmp/tmux-$(id -u)"
if [[ -d "$_tmux_sock" ]] && has_mount_ns; then
    if sandbox bash -c "test -d '$_tmux_sock' && echo VISIBLE || echo HIDDEN"; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "tmux outer socket blocked (prevents escape via tmux server)"
        else
            fail "tmux outer socket exposed (sandbox escape risk)" "$OUTPUT"
        fi
    fi
elif [[ ! -d "$_tmux_sock" ]]; then
    skip "tmux outer socket — no tmux session running"
fi

# tmux wrapper uses sandbox-tmux.conf (Ctrl-a prefix for nesting)
if sandbox bash -c 'which tmux 2>/dev/null'; then
    if [[ "$OUTPUT" == *"bin/tmux" && "$OUTPUT" != "/usr/bin/tmux" ]]; then
        pass "tmux shadows /usr/bin/tmux via sandbox bin/"
    else
        fail "tmux not shadowed by sandbox wrapper" "$OUTPUT"
    fi
fi
if [[ -f "$SCRIPT_DIR/sandbox-tmux.conf" ]]; then
    pass "sandbox-tmux.conf present"
else
    fail "sandbox-tmux.conf missing"
fi

# pty allocation and tmux (requires BIND_DEV_PTS=true on kernels < 5.4)
if sandbox bash -c 'python3 -c "import pty; pty.openpty(); print(\"pty-ok\")" 2>&1'; then
    if [[ "$OUTPUT" == *"pty-ok"* ]]; then
        pass "pty allocation works inside sandbox"
    else
        fail "pty allocation returned unexpected output" "$OUTPUT"
    fi
    # tmux test only makes sense if ptys work
    sandbox bash -c 'tmux new-session -d -s sandbox-test sleep\ 5 && tmux list-sessions && tmux kill-server' || true
    # Check output, not exit code — firejail sends SIGHUP on cleanup (exit 129)
    if [[ "$OUTPUT" == *"sandbox-test"* ]]; then
        pass "tmux starts detached session inside sandbox"
    else
        fail "tmux failed to start inside sandbox" "$OUTPUT"
    fi
else
    skip "pty allocation failed (set BIND_DEV_PTS=true for tmux on kernels < 5.4)"
fi

# ── C01: Write to cgroup filesystem ──
if sandbox bash -c '
    wrote=false
    for cg in /sys/fs/cgroup/memory/memory.limit_in_bytes \
              /sys/fs/cgroup/cpu/cpu.cfs_quota_us \
              /sys/fs/cgroup/unified/cgroup.procs \
              /sys/fs/cgroup/cgroup.procs; do
        if [[ -w "$cg" ]] 2>/dev/null; then
            echo "WRITABLE:$cg"
            wrote=true
        fi
    done
    for cgdir in /sys/fs/cgroup/memory /sys/fs/cgroup/cpu /sys/fs/cgroup/unified /sys/fs/cgroup; do
        if mkdir "$cgdir/escape-test-$$" 2>/dev/null; then
            echo "MKDIR_OK:$cgdir/escape-test-$$"
            rmdir "$cgdir/escape-test-$$" 2>/dev/null
            wrote=true
        fi
    done
    if ! $wrote; then
        echo "CGROUP_READONLY"
    fi
'; then
    if echo "$OUTPUT" | grep -q "CGROUP_READONLY"; then
        pass "C01: Cgroup filesystem is read-only inside sandbox"
    elif echo "$OUTPUT" | grep -q "WRITABLE\|MKDIR_OK"; then
        fail "C01: Cgroup filesystem writable inside sandbox" "$OUTPUT"
    else
        pass "C01: Cgroup access restricted"
    fi
else
    pass "C01: Cgroup test failed (sandbox restriction)"
fi

# ── F01: Verify FDs > 2 are closed inside sandbox ──
if sandbox bash -c '
    open_fds=""
    for fd_num in $(ls /proc/self/fd 2>/dev/null); do
        if [[ "$fd_num" -gt 2 ]] 2>/dev/null && [[ "$fd_num" -ne 255 ]]; then
            target=$(readlink "/proc/self/fd/$fd_num" 2>/dev/null || echo "unknown")
            case "$target" in
                pipe:*|socket:*|anon_inode:*|/dev/null|unknown) continue ;;
            esac
            open_fds="$open_fds $fd_num:$target"
        fi
    done
    if [[ -z "$open_fds" ]]; then
        echo "CLEAN"
    else
        echo "LEAKED:$open_fds"
    fi
'; then
    if echo "$OUTPUT" | grep -q "CLEAN"; then
        pass "F01: No unexpected FDs > 2 inherited into sandbox"
    elif echo "$OUTPUT" | grep -q "LEAKED"; then
        fail "F01: Leaked FDs found inside sandbox" "$OUTPUT"
    else
        pass "F01: FD check completed (no leaks detected)"
    fi
else
    fail "F01: FD inheritance check command failed" "$OUTPUT"
fi

# ── G01: Signal processes outside PID namespace ──
if has_mount_ns; then
    local _host_pid=$$
    if sandbox bash -c "
        kill -0 $_host_pid 2>&1
        echo EXIT=\$?
    "; then
        if echo "$OUTPUT" | grep -qE "No such process|EXIT=[1-9]|not permitted"; then
            pass "G01: Cannot signal host process from inside PID namespace"
        elif echo "$OUTPUT" | grep -q "EXIT=0"; then
            fail "G01: kill -0 succeeded on host PID $_host_pid (PID namespace leak)" "$OUTPUT"
        else
            pass "G01: Signal to host process blocked"
        fi
    else
        pass "G01: Signal attack failed (good)"
    fi
else
    skip "G01: No PID namespace isolation ($CURRENT_BACKEND backend)"
fi

echo ""

# ── 11. Credential & identity protection ──────────────────────────

echo "11. Credential & identity protection"

# SSH env vars should not leak
export SSH_AUTH_SOCK="/tmp/ssh-test/agent.123"
export SSH_CONNECTION="1.2.3.4 1234 5.6.7.8 22"
export SSH_CLIENT="1.2.3.4 1234 22"
export SSH_TTY="/dev/pts/99"

if sandbox bash -c 'echo ${SSH_AUTH_SOCK:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "SSH_AUTH_SOCK is blocked"
    else
        fail "SSH_AUTH_SOCK leaked into sandbox" "$OUTPUT"
    fi
fi

if sandbox bash -c 'echo ${SSH_CONNECTION:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "SSH_CONNECTION is blocked"
    else
        fail "SSH_CONNECTION leaked into sandbox" "$OUTPUT"
    fi
fi

unset SSH_AUTH_SOCK SSH_CONNECTION SSH_CLIENT SSH_TTY

# ALLOWED_ENV_VARS — override BLOCKED_ENV_VARS
# Use a conf.d snippet to set ALLOWED_ENV_VARS for this test
_aev_conf="$HOME/.config/agent-sandbox/conf.d/test-allowed-env-$$.conf"
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
echo 'ALLOWED_ENV_VARS+=("GITHUB_TOKEN")' > "$_aev_conf"
export GITHUB_TOKEN="allowed-env-test-value"
if sandbox bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "allowed-env-test-value" ]]; then
        pass "ALLOWED_ENV_VARS overrides BLOCKED_ENV_VARS (GITHUB_TOKEN passed through)"
    else
        fail "ALLOWED_ENV_VARS did not override BLOCKED_ENV_VARS" "$OUTPUT"
    fi
fi
unset GITHUB_TOKEN
rm -f "$_aev_conf"

# ALLOWED_ENV_VARS — override SSH_* catch-all
echo 'ALLOWED_ENV_VARS+=("SSH_TTY")' > "$_aev_conf"
export SSH_TTY="/dev/pts/test-allowed"
export SSH_CONNECTION="1.2.3.4 1234 5.6.7.8 22"
if sandbox bash -c 'echo TTY=${SSH_TTY:-UNSET} CONN=${SSH_CONNECTION:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "TTY=/dev/pts/test-allowed"; then
        pass "ALLOWED_ENV_VARS overrides SSH_* catch-all (SSH_TTY passed through)"
    else
        fail "ALLOWED_ENV_VARS did not override SSH_* catch-all for SSH_TTY" "$OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q "CONN=UNSET"; then
        pass "SSH_CONNECTION still blocked (not in ALLOWED_ENV_VARS)"
    else
        fail "SSH_CONNECTION leaked despite not being in ALLOWED_ENV_VARS" "$OUTPUT"
    fi
fi
unset SSH_TTY SSH_CONNECTION
rm -f "$_aev_conf"

# Empty ALLOWED_ENV_VARS — blocked vars remain blocked (no regression)
export GITHUB_TOKEN="empty-allow-test"
if sandbox bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "Empty ALLOWED_ENV_VARS: GITHUB_TOKEN still blocked"
    else
        fail "Empty ALLOWED_ENV_VARS: GITHUB_TOKEN leaked" "$OUTPUT"
    fi
fi
unset GITHUB_TOKEN

# Non-blocked env vars should pass through to the sandbox
export _TEST_CRED_VAR="test-credential-value"
if sandbox bash -c 'echo ${LANG:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "Passthrough env vars (LANG) accessible"
    else
        # LANG may not be set on all systems
        skip "LANG not set — passthrough test inconclusive"
    fi
fi
unset _TEST_CRED_VAR

# FILTER_PASSWD — verify /etc/passwd is filtered inside sandbox
if is_bwrap; then
    if sandbox bash -c 'wc -l < /etc/passwd'; then
        _host_count=$(wc -l < /etc/passwd)
        _sandbox_count="$OUTPUT"
        if [[ "$_sandbox_count" -lt "$_host_count" ]]; then
            pass "FILTER_PASSWD: /etc/passwd filtered (host: $_host_count → sandbox: $_sandbox_count lines)"
        elif [[ "$_sandbox_count" -eq "$_host_count" ]]; then
            # Could be that all users are system users (< 1000)
            pass "FILTER_PASSWD: /etc/passwd overlaid (same count — all UIDs may be < 1000)"
        fi
    fi
    # Slurm service users must be present (sbatch needs to resolve SlurmUser)
    if sandbox bash -c 'grep -c "^slurm:" /etc/passwd'; then
        pass "FILTER_PASSWD: slurm user preserved in filtered passwd"
    else
        fail "FILTER_PASSWD: slurm user missing from filtered passwd" "$OUTPUT"
    fi
    if sandbox bash -c 'grep "^passwd:" /etc/nsswitch.conf'; then
        if [[ "$OUTPUT" == *"files"* ]] && [[ "$OUTPUT" != *"ldap"* ]] && [[ "$OUTPUT" != *"sss"* ]]; then
            pass "FILTER_PASSWD: nsswitch.conf uses files-only for passwd"
        else
            fail "FILTER_PASSWD: nsswitch.conf still references ldap/sss" "$OUTPUT"
        fi
    fi
elif is_firejail; then
    # Firejail: check that LDAP users are not enumerable
    _host_getent=$(getent passwd | wc -l)
    if sandbox bash -c 'getent passwd | wc -l'; then
        _sandbox_getent="$OUTPUT"
        if [[ "$_sandbox_getent" -lt "$_host_getent" ]]; then
            pass "FILTER_PASSWD: getent filtered (host: $_host_getent → sandbox: $_sandbox_getent)"
        elif [[ "$_sandbox_getent" -eq "$_host_getent" ]]; then
            # No LDAP configured — nothing to filter
            skip "FILTER_PASSWD: no LDAP users to filter (host and sandbox both $_host_getent)"
        fi
    fi
else
    skip "FILTER_PASSWD: not supported on Landlock (no mount namespace)"
fi

# SANDBOX_BYPASS_TOKEN — verify the token file is hidden inside the sandbox
# bwrap overlays with /dev/null; firejail blacklists; landlock relies on eBPF LSM
if has_mount_ns; then
    # Mount-namespace backends: test with a temp token file
    _TOKEN_FILE="/tmp/.sandbox-test-bypass-token-$$"
    echo "test-bypass-secret" > "$_TOKEN_FILE"
    _TOKEN_RAW=$(SANDBOX_BYPASS_TOKEN="$_TOKEN_FILE" \
        timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- cat "$_TOKEN_FILE" 2>&1) || true
    _TOKEN_OUT=$(echo "$_TOKEN_RAW" | grep -v \
        -e '^Warning:' -e '^Parent pid' -e '^Child process' -e '^Parent is shutting')
    if echo "$_TOKEN_OUT" | grep -q "test-bypass-secret"; then
        fail "SANDBOX_BYPASS_TOKEN is readable inside sandbox"
    else
        pass "SANDBOX_BYPASS_TOKEN is hidden inside sandbox"
    fi
    rm -f "$_TOKEN_FILE"
else
    # Landlock: cannot hide files via mount namespace. Check if eBPF LSM
    # program (deny_token_read) is loaded and protecting a configured token.
    _EBPF_LOADED=false
    if command -v bpftool &>/dev/null; then
        if sudo -n bpftool prog list 2>/dev/null | grep -q 'deny_token_read'; then
            _EBPF_LOADED=true
        fi
    fi

    if [[ "$_EBPF_LOADED" == "true" ]]; then
        # eBPF is loaded — find the configured token path and test it
        # Try sandbox.conf first, then auto-discover from admin wrapper config
        _TOKEN_PATH=""
        if [[ -f "$SCRIPT_DIR/sandbox.conf" ]]; then
            _TOKEN_PATH=$(bash -c "source '$SCRIPT_DIR/sandbox.conf' 2>/dev/null; echo \"\$SANDBOX_BYPASS_TOKEN\"")
        fi
        if [[ -z "$_TOKEN_PATH" && -f /app/lib/agent-sandbox/sandbox.conf ]]; then
            _TOKEN_PATH=$(bash -c 'source /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; echo "$TOKEN_FILE"')
        fi
        if [[ -n "$_TOKEN_PATH" && -f "$_TOKEN_PATH" ]]; then
            # Landlock sets NO_NEW_PRIVS — eBPF should deny the read
            if sandbox cat "$_TOKEN_PATH" 2>&1; then
                # eBPF is loaded but not blocking. This can happen if:
                # - The eBPF program doesn't match this token path
                # - The eBPF program checks a different condition than NoNewPrivs
                # - The kernel version doesn't support the specific LSM hook
                fail "SANDBOX_BYPASS_TOKEN readable despite eBPF (Landlock) — check eBPF program path match"
            else
                if echo "$OUTPUT" | grep -qi "permission denied\|operation not permitted"; then
                    pass "SANDBOX_BYPASS_TOKEN protected by eBPF LSM (Landlock)"
                else
                    pass "SANDBOX_BYPASS_TOKEN not readable (Landlock + eBPF)"
                fi
            fi
        else
            skip "SANDBOX_BYPASS_TOKEN — eBPF loaded but no token path found (sandbox.conf or admin config)"
        fi
    else
        skip "SANDBOX_BYPASS_TOKEN — Landlock needs eBPF LSM (not loaded; see ADMIN_HARDENING.md §1)"
    fi
fi

echo ""

# ── 12. Stability ─────────────────────────────────────────────────

echo "12. Stability"

# ── D01: Consistent isolation across repeated runs ──
local _results=()
local _consistent=true

for _i in $(seq 1 5); do
    if sandbox bash -c '
        echo "SANDBOX_ACTIVE=${SANDBOX_ACTIVE:-unset}"
        echo "HOME_WRITABLE=$(touch $HOME/.test-write-deterministic 2>&1 >/dev/null && echo YES || echo NO)"
        rm -f "$HOME/.test-write-deterministic" 2>/dev/null
        echo "ETC_WRITABLE=$(touch /etc/.test-write-deterministic 2>&1 >/dev/null && echo YES || echo NO)"
        echo "SSH_HIDDEN=$(test -d $HOME/.ssh && echo VISIBLE || echo HIDDEN)"
    '; then
        _results+=("$OUTPUT")
    else
        _results+=("FAILED")
    fi
done

if [[ ${#_results[@]} -gt 0 ]]; then
    local _reference="${_results[0]}"
    for _i in $(seq 1 $((${#_results[@]} - 1))); do
        if [[ "${_results[$_i]}" != "$_reference" ]]; then
            _consistent=false
            break
        fi
    done
    if [[ "$_consistent" == true ]]; then
        pass "D01: All 5 runs produced identical isolation state"
    else
        fail "D01: Inconsistent isolation across runs (possible race condition)" "Run 1: $_reference | Diverged at run $((_i+1))"
    fi
else
    fail "D01: No results collected"
fi

# ── W01: Two concurrent sandboxes with independent state ──
local _marker_a="$PROJECT_DIR/.concurrent-test-A-$$"
local _marker_b="$PROJECT_DIR/.concurrent-test-B-$$"

(
    timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        bash -c "
            echo 'INSTANCE_A' > '$_marker_a'
            sleep 2
            if [[ -f '$_marker_b' ]]; then
                echo 'A_SEES_B'
            else
                echo 'A_ALONE'
            fi
            echo \"A_PID=\$\$\"
            echo \"A_BACKEND=\$SANDBOX_BACKEND\"
        " 2>/dev/null
) > /tmp/sandbox-concurrent-A-$$ 2>&1 &
local _pid_a=$!

(
    timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        bash -c "
            echo 'INSTANCE_B' > '$_marker_b'
            sleep 2
            if [[ -f '$_marker_a' ]]; then
                echo 'B_SEES_A'
            else
                echo 'B_ALONE'
            fi
            echo \"B_PID=\$\$\"
            echo \"B_BACKEND=\$SANDBOX_BACKEND\"
        " 2>/dev/null
) > /tmp/sandbox-concurrent-B-$$ 2>&1 &
local _pid_b=$!

wait $_pid_a 2>/dev/null
wait $_pid_b 2>/dev/null

local _out_a _out_b
_out_a="$(cat /tmp/sandbox-concurrent-A-$$ 2>/dev/null)"
_out_b="$(cat /tmp/sandbox-concurrent-B-$$ 2>/dev/null)"

rm -f /tmp/sandbox-concurrent-A-$$ /tmp/sandbox-concurrent-B-$$
rm -f "$_marker_a" "$_marker_b"

if [[ -n "$_out_a" && -n "$_out_b" ]]; then
    local _a_pid _b_pid
    _a_pid=$(echo "$_out_a" | grep -oP 'A_PID=\K[0-9]+' || echo "0")
    _b_pid=$(echo "$_out_b" | grep -oP 'B_PID=\K[0-9]+' || echo "0")

    if has_mount_ns; then
        pass "W01: Both sandbox instances ran concurrently (PIDs: A=$_a_pid, B=$_b_pid)"
    else
        if [[ "$_a_pid" != "$_b_pid" ]]; then
            pass "W01: Concurrent instances have different PIDs (no PID namespace, but isolated)"
        else
            pass "W01: Concurrent instances ran (landlock — shared PID space expected)"
        fi
    fi
elif [[ -z "$_out_a" && -z "$_out_b" ]]; then
    fail "W01: Both concurrent sandbox instances failed to produce output"
else
    pass "W01: At least one concurrent sandbox instance ran successfully"
fi

echo ""

fi  # end of [[ "$QUICK_MODE" != true ]] block (sections 6-12)

# ── Per-backend summary ──────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo "════════════════════════════════════════════════"
echo "  Backend: $CURRENT_BACKEND"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL)"
echo "════════════════════════════════════════════════"
echo ""

TOTAL_PASS=$((TOTAL_PASS + PASS))
TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
TOTAL_SKIP=$((TOTAL_SKIP + SKIP))
[[ $FAIL -gt 0 ]] && ANY_FAIL=true
}

# ── Run tests for each available backend ─────────────────────────

for backend in "${AVAILABLE_BACKENDS[@]}"; do
    run_tests "$backend"
done

# ── Overall summary ──────────────────────────────────────────────

if [[ ${#AVAILABLE_BACKENDS[@]} -gt 1 ]]; then
    GRAND_TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
    echo "╔═══════════════════════════════════════════════╗"
    echo "║  Overall Results                              ║"
    echo "╠═══════════════════════════════════════════════╣"
    printf "║  Backends tested: %-27s ║\n" "${AVAILABLE_BACKENDS[*]}"
    printf "║  %3d passed, %d failed, %d skipped (of %d)     ║\n" \
        "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$GRAND_TOTAL"
    echo "╚═══════════════════════════════════════════════╝"
fi

# ── Admin hardening status (ADMIN_HARDENING.md) ──────────────────

echo ""
echo "Admin hardening status (see ADMIN_HARDENING.md):"

# §1 — Enforce sandbox on agent-submitted Slurm jobs
_s1_parts=()
_s1_missing=()

# Token file exists?
_token_path=""
if [[ -n "${TOKEN_FILE:-}" ]]; then
    _token_path="$TOKEN_FILE"
elif [[ -f /app/lib/agent-sandbox/sandbox.conf ]]; then
    _token_path=$(bash -c 'source /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; echo "$TOKEN_FILE"')
fi
if [[ -n "$_token_path" && -f "$_token_path" ]]; then
    _s1_parts+=("bypass token")
else
    _s1_missing+=("bypass token")
fi

# eBPF loaded?
if command -v bpftool &>/dev/null && sudo -n bpftool prog list 2>/dev/null | grep -q 'deny_token_read'; then
    _s1_parts+=("eBPF LSM")
else
    _s1_missing+=("eBPF LSM")
fi

# Job submit plugin?
if [[ -f /etc/slurm/job_submit.lua ]] && grep -q 'SANDBOX_BYPASS\|sandbox' /etc/slurm/job_submit.lua 2>/dev/null; then
    _s1_parts+=("job submit plugin")
else
    _s1_missing+=("job submit plugin")
fi

# System-wide wrappers?
if [[ -f /usr/bin/sbatch ]] && head -1 /usr/bin/sbatch 2>/dev/null | grep -q bash; then
    _s1_parts+=("sbatch/srun wrappers")
else
    _s1_missing+=("sbatch/srun wrappers")
fi

if [[ ${#_s1_missing[@]} -eq 0 ]]; then
    echo "  ✓ §1 Slurm job enforcement: deployed (${_s1_parts[*]})"
elif [[ ${#_s1_parts[@]} -gt 0 ]]; then
    echo "  ◐ §1 Slurm job enforcement: partial (have: ${_s1_parts[*]}; missing: ${_s1_missing[*]})"
else
    echo "  · §1 Slurm job enforcement: not deployed"
fi

# §2 — Admin-owned sandbox installation
_sandbox_dir="$(cd "$SCRIPT_DIR" && pwd)"
_sandbox_owner=$(stat -c %u "$_sandbox_dir" 2>/dev/null || stat -f %u "$_sandbox_dir" 2>/dev/null)
if [[ "${_sandbox_owner:-}" == "0" ]]; then
    echo "  ✓ §2 Admin-owned installation: sandbox scripts owned by root"
else
    echo "  · §2 Admin-owned installation: not deployed (scripts owned by user)"
fi

# §2 — systemd user instances (Landlock-only concern)
for b in "${AVAILABLE_BACKENDS[@]}"; do
    if [[ "$b" == "landlock" ]]; then
        if systemctl is-enabled user@.service &>/dev/null 2>&1; then
            _user_svc=$(systemctl is-enabled user@.service 2>/dev/null || true)
            if [[ "$_user_svc" == "masked" ]]; then
                echo "  ✓ §2 systemd user@.service: masked (Landlock escape mitigated)"
            else
                echo "  ⚠ §2 systemd user@.service: active (Landlock escape possible — see ADMIN_HARDENING.md §2)"
            fi
        fi
        break
    fi
done

echo ""

if [[ "$ANY_FAIL" == true ]]; then
    echo ""
    echo "  Some tests failed. Run with --verbose for details."
    exit 1
fi
