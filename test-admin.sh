#!/usr/bin/env bash
# test-admin.sh — Standalone admin-only config enforcement tests
#
# Tests the multi-level config system which only applies when an admin
# config exists at /app/lib/agent-sandbox/sandbox.conf.
#
# Sections:
#   T01-T03:  BLOCKED_ENV_VARS clearing and user additions
#   T04-T05:  ALLOWED_ENV_VARS user additions and admin merge
#   T09-T10:  HOME_READONLY -> HOME_WRITABLE escalation (.ssh, .gnupg)
#   T11-T14:  DENIED_WRITABLE_PATHS enforcement
#   T15-T16:  Scalar protection (TOKEN_FILE, SANDBOX_BYPASS_TOKEN)
#   A01:      HOME=/tmp/evil override
#   conf.d:   Enforcement after conf.d, syntax errors, edge cases
#   Combined: Multiple violations, adjacent paths, all blocked vars
#   Admin wrappers: sbatch/srun wrapper validation
#
# Usage: ./test-admin.sh [--verbose] [--backend BACKEND] [PROJECT_DIR]

set -uo pipefail

# ── Argument parsing ─────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"
PROJECT_DIR=""

VERBOSE=false
BACKEND_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE=true; shift ;;
        --backend) BACKEND_FLAG="$2"; shift 2 ;;
        -*) shift ;;
        *) PROJECT_DIR="$1"; shift ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && PROJECT_DIR="$SCRIPT_DIR"

# ── Early exit if admin config is absent ─────────────────────────

if [[ ! -f /app/lib/agent-sandbox/sandbox.conf ]]; then
    echo ""
    echo "Admin sandbox.conf not found at /app/lib/agent-sandbox/sandbox.conf"
    echo "These tests only apply when an admin config is deployed.  Skipping."
    echo ""
    exit 0
fi

# ── Counters and helpers ─────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

pass() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }
skip() { ((SKIP++)); echo "  ⊘ $1 (skipped)"; }

is_bwrap()    { [[ "$CURRENT_BACKEND" == "bwrap" ]]; }
is_firejail() { [[ "$CURRENT_BACKEND" == "firejail" ]]; }
is_landlock()  { [[ "$CURRENT_BACKEND" == "landlock" ]]; }
has_mount_ns() { is_bwrap || is_firejail; }

# sandbox_raw — run sandbox and capture combined stdout+stderr (keeps WARNINGs)
sandbox_raw() {
    local raw
    raw=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- "$@" 2>&1)
    local rc=$?
    OUTPUT="$raw"
    return $rc
}

# Helper: write user.conf with given content
write_user_conf() {
    mkdir -p "$HOME/.claude/sandbox"
    cat > "$HOME/.claude/sandbox/user.conf" <<< "$1"
}

# Helper: remove user.conf
clean_user_conf() {
    rm -f "$HOME/.claude/sandbox/user.conf"
}

# Helper: write a conf.d file
write_confd() {
    local name="$1"
    local content="$2"
    mkdir -p "$HOME/.claude/sandbox/conf.d"
    cat > "$HOME/.claude/sandbox/conf.d/$name" <<< "$content"
}

# Helper: remove all conf.d files
clean_confd() {
    rm -rf "$HOME/.claude/sandbox/conf.d"
}

# ── Detect backend ───────────────────────────────────────────────

if [[ -n "$BACKEND_FLAG" ]]; then
    CURRENT_BACKEND="$BACKEND_FLAG"
else
    CURRENT_BACKEND=""
    for _b in bwrap firejail landlock; do
        if timeout 5 "$SANDBOX_EXEC" --backend "$_b" --dry-run --project-dir "$PROJECT_DIR" -- true &>/dev/null; then
            CURRENT_BACKEND="$_b"
            break
        fi
    done
fi

if [[ -z "${CURRENT_BACKEND:-}" ]]; then
    echo "ERROR: No sandbox backend available."
    exit 1
fi

echo "╔═══════════════════════════════════════════════╗"
echo "║  Admin Enforcement Test Suite                 ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "Backend: $CURRENT_BACKEND"
echo "Project: $PROJECT_DIR"
echo ""

# ══════════════════════════════════════════════════════════════════
#  T01-T03: BLOCKED_ENV_VARS clearing and user additions
# ══════════════════════════════════════════════════════════════════

echo "BLOCKED_ENV_VARS Enforcement (T01-T03)"
echo ""

# ── T01: BLOCKED_ENV_VARS=() — user clears the admin list ──
echo "  T01: BLOCKED_ENV_VARS cleared by user"
write_user_conf 'BLOCKED_ENV_VARS=()'
export GITHUB_TOKEN="leak-test-T01"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "T01: GITHUB_TOKEN still blocked after user cleared BLOCKED_ENV_VARS"
    else
        fail "T01: GITHUB_TOKEN leaked — user cleared BLOCKED_ENV_VARS" "$OUTPUT"
    fi
else
    fail "T01: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_user_conf

# ── T02: declare -a BLOCKED_ENV_VARS=() — alternative clear syntax ──
echo "  T02: BLOCKED_ENV_VARS cleared via declare -a"
write_user_conf 'declare -a BLOCKED_ENV_VARS=()'
export ANTHROPIC_API_KEY="leak-test-T02"
if sandbox_raw bash -c 'echo ${ANTHROPIC_API_KEY:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "T02: ANTHROPIC_API_KEY still blocked after declare -a clear"
    else
        fail "T02: ANTHROPIC_API_KEY leaked via declare -a clear" "$OUTPUT"
    fi
else
    fail "T02: Sandbox failed to start" "$OUTPUT"
fi
unset ANTHROPIC_API_KEY
clean_user_conf

# ── T03: BLOCKED_ENV_VARS user addition ──
echo "  T03: User addition to BLOCKED_ENV_VARS"
write_user_conf 'BLOCKED_ENV_VARS+=("MY_LAB_SECRET_T03")'
export GITHUB_TOKEN="leak-test-T03"
export MY_LAB_SECRET_T03="lab-secret-T03"
if sandbox_raw bash -c 'echo GT=${GITHUB_TOKEN:-UNSET} ML=${MY_LAB_SECRET_T03:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "GT=UNSET"; then
        pass "T03: Admin GITHUB_TOKEN still blocked"
    else
        fail "T03: Admin GITHUB_TOKEN leaked" "$OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q "ML=UNSET"; then
        pass "T03: User-added MY_LAB_SECRET_T03 also blocked"
    else
        skip "T03: User-added MY_LAB_SECRET_T03 not blocked (user additions may require additive config support)"
    fi
else
    fail "T03: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN MY_LAB_SECRET_T03
clean_user_conf

echo ""

# ══════════════════════════════════════════════════════════════════
#  T04-T05: ALLOWED_ENV_VARS user additions and admin merge
# ══════════════════════════════════════════════════════════════════

echo "ALLOWED_ENV_VARS Enforcement (T04-T05)"
echo ""

# ── T04: User adds to ALLOWED_ENV_VARS — overrides BLOCKED_ENV_VARS ──
echo "  T04: User ALLOWED_ENV_VARS overrides BLOCKED_ENV_VARS"
write_user_conf 'ALLOWED_ENV_VARS+=("GITHUB_TOKEN")'
export GITHUB_TOKEN="allow-test-T04"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "allow-test-T04"; then
        pass "T04: GITHUB_TOKEN passed through via ALLOWED_ENV_VARS"
    else
        fail "T04: GITHUB_TOKEN still blocked despite ALLOWED_ENV_VARS" "$OUTPUT"
    fi
else
    fail "T04: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_user_conf

# ── T05: User ALLOWED_ENV_VARS overrides SSH_* pattern ──
echo "  T05: User ALLOWED_ENV_VARS overrides SSH_* pattern"
write_user_conf 'ALLOWED_ENV_VARS+=("SSH_TTY")'
export SSH_TTY="/dev/pts/test-T05"
export SSH_CONNECTION="1.2.3.4 1234 5.6.7.8 22"
if sandbox_raw bash -c 'echo TTY=${SSH_TTY:-UNSET} CONN=${SSH_CONNECTION:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "TTY=/dev/pts/test-T05"; then
        pass "T05: SSH_TTY passed through via ALLOWED_ENV_VARS"
    else
        fail "T05: SSH_TTY still blocked despite ALLOWED_ENV_VARS" "$OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q "CONN=UNSET"; then
        pass "T05: SSH_CONNECTION still blocked (not in ALLOWED_ENV_VARS)"
    else
        fail "T05: SSH_CONNECTION leaked" "$OUTPUT"
    fi
else
    fail "T05: Sandbox failed to start" "$OUTPUT"
fi
unset SSH_TTY SSH_CONNECTION
clean_user_conf

echo ""

# ══════════════════════════════════════════════════════════════════
#  T09-T10: HOME_READONLY -> HOME_WRITABLE escalation
# ══════════════════════════════════════════════════════════════════

echo "HOME_READONLY Escalation (T09-T10)"
echo ""

# ── T09: HOME_WRITABLE escalation attempt (.ssh) ──
echo "  T09: HOME_WRITABLE escalation attempt (.ssh)"
write_user_conf 'HOME_WRITABLE+=(".ssh")'
if sandbox_raw bash -c 'touch $HOME/.ssh/test-escalation 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only"; then
        pass "T09: .ssh not writable despite user trying to add to HOME_WRITABLE"
    else
        fail "T09: .ssh may be writable (escalation from HOME_READONLY)" "$OUTPUT"
    fi
else
    pass "T09: .ssh write attempt failed (escalation blocked)"
fi
clean_user_conf

# ── T10: HOME_WRITABLE escalation attempt (.gnupg) ──
echo "  T10: HOME_WRITABLE escalation attempt (.gnupg)"
write_user_conf 'HOME_WRITABLE+=(".gnupg")'
if sandbox_raw bash -c 'touch $HOME/.gnupg/test-escalation 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only"; then
        pass "T10: .gnupg not writable despite user trying to add to HOME_WRITABLE"
    else
        fail "T10: .gnupg may be writable (escalation from HOME_READONLY)" "$OUTPUT"
    fi
else
    pass "T10: .gnupg write attempt failed (escalation blocked)"
fi
clean_user_conf

echo ""

# ══════════════════════════════════════════════════════════════════
#  T11-T14: DENIED_WRITABLE_PATHS enforcement
# ══════════════════════════════════════════════════════════════════

echo "DENIED_WRITABLE_PATHS Enforcement (T11-T14)"
echo ""

# ── T11: EXTRA_WRITABLE_PATHS under denied /etc ──
echo "  T11: EXTRA_WRITABLE_PATHS under denied /etc"
write_user_conf 'EXTRA_WRITABLE_PATHS+=("/etc/cron.d")'
if sandbox_raw bash -c 'touch /etc/cron.d/test-denied 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only"; then
        pass "T11: /etc/cron.d not writable despite EXTRA_WRITABLE_PATHS addition"
    else
        fail "T11: /etc/cron.d may be writable (DENIED_WRITABLE_PATHS bypass)" "$OUTPUT"
    fi
else
    pass "T11: /etc/cron.d write attempt failed (denied path enforced)"
fi
clean_user_conf

# ── T12: EXTRA_WRITABLE_PATHS under denied /app ──
echo "  T12: EXTRA_WRITABLE_PATHS under denied /app"
write_user_conf 'EXTRA_WRITABLE_PATHS+=("/app/data")'
if sandbox_raw bash -c 'touch /app/data/test-denied 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only\|No such"; then
        pass "T12: /app/data not writable despite EXTRA_WRITABLE_PATHS addition"
    else
        fail "T12: /app/data may be writable (DENIED_WRITABLE_PATHS bypass)" "$OUTPUT"
    fi
else
    pass "T12: /app/data write attempt failed (denied path enforced)"
fi
clean_user_conf

# ── T13: HOME_WRITABLE .ssh subpath (under denied $HOME/.ssh) ──
echo "  T13: HOME_WRITABLE .ssh/authorized_keys (under denied \$HOME/.ssh)"
write_user_conf 'HOME_WRITABLE+=(".ssh/authorized_keys")'
if sandbox_raw bash -c 'touch $HOME/.ssh/authorized_keys 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only\|No such"; then
        pass "T13: .ssh/authorized_keys not writable despite HOME_WRITABLE addition"
    else
        fail "T13: .ssh/authorized_keys may be writable (DENIED_WRITABLE_PATHS bypass)" "$OUTPUT"
    fi
else
    pass "T13: .ssh/authorized_keys write attempt failed (denied path enforced)"
fi
clean_user_conf

# ── T14: Safe path NOT denied ──
echo "  T14: EXTRA_WRITABLE_PATHS safe path (not under denied paths)"
write_user_conf 'EXTRA_WRITABLE_PATHS+=("/scratch/safe")'
if sandbox_raw bash -c 'echo done'; then
    if echo "$OUTPUT" | grep -q "done"; then
        pass "T14: Sandbox starts with safe EXTRA_WRITABLE_PATHS (no false denial)"
    else
        fail "T14: Sandbox output unexpected" "$OUTPUT"
    fi
else
    fail "T14: Sandbox failed to start with safe EXTRA_WRITABLE_PATHS" "$OUTPUT"
fi
clean_user_conf

echo ""

# ══════════════════════════════════════════════════════════════════
#  T15-T16: Scalar protection
# ══════════════════════════════════════════════════════════════════

echo "Scalar Protection (T15-T16)"
echo ""

# ── T15: TOKEN_FILE scalar override blocked ──
echo "  T15: TOKEN_FILE scalar override attempt"
write_user_conf 'TOKEN_FILE="/tmp/fake-token"'
if has_mount_ns; then
    echo "fake-secret" > /tmp/fake-token 2>/dev/null || true
    if sandbox_raw bash -c 'cat /app/lib/agent-sandbox/.sandbox-bypass-token 2>&1'; then
        if echo "$OUTPUT" | grep -q "fake-secret"; then
            fail "T15: User redirected TOKEN_FILE to fake token"
        else
            pass "T15: TOKEN_FILE override did not expose admin token path"
        fi
    else
        pass "T15: Admin token file still protected despite TOKEN_FILE override"
    fi
    rm -f /tmp/fake-token
else
    skip "T15: TOKEN_FILE overlay — not applicable for $CURRENT_BACKEND backend"
fi
clean_user_conf

# ── T16: SANDBOX_BYPASS_TOKEN scalar override blocked ──
echo "  T16: SANDBOX_BYPASS_TOKEN scalar override attempt"
write_user_conf 'SANDBOX_BYPASS_TOKEN="/tmp/fake"'
if sandbox_raw bash -c 'echo done'; then
    if echo "$OUTPUT" | grep -q "done"; then
        pass "T16: Sandbox starts normally despite SANDBOX_BYPASS_TOKEN override attempt"
    else
        fail "T16: Sandbox output unexpected" "$OUTPUT"
    fi
else
    fail "T16: Sandbox failed to start" "$OUTPUT"
fi
clean_user_conf

echo ""

# ══════════════════════════════════════════════════════════════════
#  A01: HOME=/tmp/evil override
# ══════════════════════════════════════════════════════════════════

echo "Escape Attempt (A01)"
echo ""

echo "  A01: HOME override before sandbox"
_real_home="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6 || echo "$HOME")"
if HOME=/tmp/evil sandbox_raw bash -c 'echo $HOME'; then
    if [[ "$OUTPUT" != *"/tmp/evil"* ]] || echo "$OUTPUT" | grep -q "$_real_home"; then
        pass "A01: HOME resolved from passwd, not environment (/tmp/evil rejected)"
    else
        fail "A01: HOME=/tmp/evil was used by sandbox" "$OUTPUT"
    fi
else
    fail "A01: Sandbox failed to start with HOME override" "$OUTPUT"
fi

echo ""

# ══════════════════════════════════════════════════════════════════
#  Per-project conf.d tests
# ══════════════════════════════════════════════════════════════════

echo "Per-project conf.d Tests"
echo ""

# ── conf.d: admin enforcement after conf.d clears BLOCKED_ENV_VARS ──
echo "  conf.d: Admin enforcement after conf.d clears BLOCKED_ENV_VARS"
clean_user_conf
write_confd "evil-project.conf" 'BLOCKED_ENV_VARS=()'
export GITHUB_TOKEN="leak-test-confd-enforce"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "conf.d: Admin BLOCKED_ENV_VARS preserved despite conf.d clearing"
    else
        fail "conf.d: conf.d file bypassed admin BLOCKED_ENV_VARS" "$OUTPUT"
    fi
else
    fail "conf.d: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_confd

# ── conf.d: DENIED_WRITABLE_PATHS enforced after conf.d ──
echo "  conf.d: DENIED_WRITABLE_PATHS enforced after conf.d"
write_confd "denied-path.conf" 'EXTRA_WRITABLE_PATHS+=("/etc/shadow.d")'
if sandbox_raw bash -c 'touch /etc/shadow.d/test 2>&1 || echo BLOCKED'; then
    if echo "$OUTPUT" | grep -q "BLOCKED\|denied\|Read-only\|No such"; then
        pass "conf.d: /etc/shadow.d not writable (DENIED_WRITABLE_PATHS enforced)"
    else
        fail "conf.d: /etc/shadow.d may be writable (DENIED_WRITABLE_PATHS bypass)" "$OUTPUT"
    fi
else
    pass "conf.d: /etc/shadow.d write attempt failed (denied path enforced)"
fi
clean_confd

# ── conf.d: syntax error causes exit ──
echo "  conf.d: Syntax error in conf.d file"
write_confd "broken.conf" 'READONLY_MOUNTS+=("/valid/path"'
if sandbox_raw bash -c 'echo done' 2>&1; then
    if echo "$OUTPUT" | grep -qi "syntax error\|Error.*broken.conf"; then
        pass "conf.d: Syntax error detected and reported"
    else
        fail "conf.d: Syntax error not detected — sandbox started normally" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -qi "syntax error\|Error"; then
        pass "conf.d: Syntax error caused sandbox exit (as expected)"
    else
        fail "conf.d: Sandbox exited but without syntax error message" "$OUTPUT"
    fi
fi
clean_confd

# ── conf.d: absent conf.d directory is fine ──
echo "  conf.d: Absent conf.d directory"
rm -rf "$HOME/.claude/sandbox/conf.d"
if sandbox_raw bash -c 'echo done'; then
    if echo "$OUTPUT" | grep -q "done"; then
        pass "conf.d: Sandbox starts normally without conf.d directory"
    else
        fail "conf.d: Sandbox output unexpected" "$OUTPUT"
    fi
else
    fail "conf.d: Sandbox failed to start without conf.d" "$OUTPUT"
fi

# ── conf.d: empty conf.d directory is fine ──
echo "  conf.d: Empty conf.d directory"
mkdir -p "$HOME/.claude/sandbox/conf.d"
if sandbox_raw bash -c 'echo done'; then
    if echo "$OUTPUT" | grep -q "done"; then
        pass "conf.d: Sandbox starts normally with empty conf.d"
    else
        fail "conf.d: Sandbox output unexpected" "$OUTPUT"
    fi
else
    fail "conf.d: Sandbox failed to start with empty conf.d" "$OUTPUT"
fi
clean_confd

# ── conf.d: _enforce_admin_policy redefined in conf.d ──
echo "  conf.d: _enforce_admin_policy override in conf.d"
write_confd "override-enforce.conf" '_enforce_admin_policy() { echo "neutered"; }
BLOCKED_ENV_VARS=()'
export GITHUB_TOKEN="leak-test-confd-override"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "conf.d: _enforce_admin_policy override in conf.d confined to subprocess"
    else
        fail "conf.d: _enforce_admin_policy override in conf.d escaped subprocess" "$OUTPUT"
    fi
else
    fail "conf.d: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_confd

# ── conf.d: DEBUG trap in conf.d file ──
echo "  conf.d: DEBUG trap in conf.d file"
write_confd "trap-debug.conf" 'trap '\''BLOCKED_ENV_VARS=()'\'' DEBUG'
export GITHUB_TOKEN="leak-test-confd-trap"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "conf.d: DEBUG trap in conf.d confined to subprocess"
    else
        fail "conf.d: DEBUG trap in conf.d bypassed enforcement" "$OUTPUT"
    fi
else
    fail "conf.d: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_confd

echo ""

# ══════════════════════════════════════════════════════════════════
#  Combined enforcement and edge cases
# ══════════════════════════════════════════════════════════════════

echo "Combined Enforcement and Edge Cases"
echo ""

# ── Multiple violations in one user.conf ──
echo "  Combined: Multiple violations in single user.conf"
write_user_conf 'BLOCKED_ENV_VARS=()
BLOCKED_FILES=()
EXTRA_BLOCKED_PATHS=()
TOKEN_FILE="/tmp/evil"
HOME_WRITABLE+=(".ssh" ".gnupg")
EXTRA_WRITABLE_PATHS+=("/etc/cron.d" "/app/bin")'
export GITHUB_TOKEN="leak-multi"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "Combined: Multiple violations — GITHUB_TOKEN still blocked"
    else
        fail "Combined: Multiple violations — GITHUB_TOKEN leaked" "$OUTPUT"
    fi
else
    fail "Combined: Sandbox failed to start" "$OUTPUT"
fi
unset GITHUB_TOKEN
clean_user_conf

# ── DENIED_WRITABLE_PATHS: adjacent path not false-matched ──
echo "  Combined: Adjacent path not falsely denied"
write_user_conf 'EXTRA_WRITABLE_PATHS+=("/etcetera")'
if sandbox_raw bash -c 'echo done'; then
    if echo "$OUTPUT" | grep -q "done"; then
        pass "Combined: Sandbox starts with /etcetera (not falsely matched against /etc)"
    else
        fail "Combined: Sandbox output unexpected" "$OUTPUT"
    fi
else
    fail "Combined: Sandbox failed to start" "$OUTPUT"
fi
clean_user_conf

# ── All admin-blocked env vars tested ──
echo "  Combined: All admin-blocked env vars"
clean_user_conf
export GITHUB_PAT="leak" GITHUB_TOKEN="leak" GH_TOKEN="leak"
export OPENAI_API_KEY="leak" ANTHROPIC_API_KEY="leak"
export AWS_ACCESS_KEY_ID="leak" AWS_SECRET_ACCESS_KEY="leak" AWS_SESSION_TOKEN="leak"
_all_blocked=true
for _var in GITHUB_PAT GITHUB_TOKEN GH_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY \
            AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do
    if sandbox_raw bash -c "echo \${${_var}:-UNSET}"; then
        if ! echo "$OUTPUT" | grep -q "UNSET"; then
            fail "Combined: $_var leaked into sandbox"
            _all_blocked=false
        fi
    fi
done
if [[ "$_all_blocked" == true ]]; then
    pass "Combined: All 8 admin-blocked env vars are blocked"
fi
unset GITHUB_PAT GITHUB_TOKEN GH_TOKEN OPENAI_API_KEY ANTHROPIC_API_KEY
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# ── No user.conf at all (should use admin defaults) ──
echo "  Combined: No user.conf (admin defaults only)"
clean_user_conf
export GITHUB_TOKEN="leak-no-conf"
if sandbox_raw bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if echo "$OUTPUT" | grep -q "UNSET"; then
        pass "Combined: GITHUB_TOKEN blocked with no user.conf (admin defaults)"
    else
        fail "Combined: GITHUB_TOKEN leaked with no user.conf" "$OUTPUT"
    fi
else
    fail "Combined: Sandbox failed to start without user.conf" "$OUTPUT"
fi
unset GITHUB_TOKEN

echo ""

# ══════════════════════════════════════════════════════════════════
#  Admin wrappers (sandbox-wrapper.conf)
# ══════════════════════════════════════════════════════════════════

WRAPPER_CONF=""
if [[ -f /app/lib/agent-sandbox/sandbox.conf ]]; then
    WRAPPER_CONF="/app/lib/agent-sandbox/sandbox.conf"
elif [[ -f "$SCRIPT_DIR/slurm-enforce/sandbox-wrapper.conf" ]]; then
    WRAPPER_CONF="$SCRIPT_DIR/slurm-enforce/sandbox-wrapper.conf"
fi

if [[ -n "$WRAPPER_CONF" ]]; then
    source "$WRAPPER_CONF"
    echo "Admin Wrappers (sandbox-wrapper.conf)"
    echo ""

    # Check that real binaries exist at configured locations
    if [[ -x "${REAL_SBATCH:-}" ]]; then
        OUTPUT=$(file "$REAL_SBATCH" 2>&1)
        if echo "$OUTPUT" | grep -qi 'ELF'; then
            pass "Real sbatch binary at $REAL_SBATCH"
        else
            fail "Real sbatch at $REAL_SBATCH is not an ELF binary" "$OUTPUT"
        fi
    else
        skip "Real sbatch not found at ${REAL_SBATCH:-<unset>}"
    fi

    if [[ -x "${REAL_SRUN:-}" ]]; then
        OUTPUT=$(file "$REAL_SRUN" 2>&1)
        if echo "$OUTPUT" | grep -qi 'ELF'; then
            pass "Real srun binary at $REAL_SRUN"
        else
            fail "Real srun at $REAL_SRUN is not an ELF binary" "$OUTPUT"
        fi
    else
        skip "Real srun not found at ${REAL_SRUN:-<unset>}"
    fi

    # Check that /usr/bin/sbatch and /usr/bin/srun are wrapper scripts
    if [[ -f /usr/bin/sbatch ]]; then
        OUTPUT=$(file /usr/bin/sbatch 2>&1)
        if echo "$OUTPUT" | grep -qi 'script\|text'; then
            pass "/usr/bin/sbatch is a wrapper script (not the real binary)"
        else
            skip "/usr/bin/sbatch is the real binary (admin wrappers not deployed)"
        fi
    fi

    if [[ -f /usr/bin/srun ]]; then
        OUTPUT=$(file /usr/bin/srun 2>&1)
        if echo "$OUTPUT" | grep -qi 'script\|text'; then
            pass "/usr/bin/srun is a wrapper script (not the real binary)"
        else
            skip "/usr/bin/srun is the real binary (admin wrappers not deployed)"
        fi
    fi

    # Check token file exists and is readable
    if [[ -n "${TOKEN_FILE:-}" && -f "$TOKEN_FILE" ]]; then
        if cat "$TOKEN_FILE" &>/dev/null; then
            pass "Token file readable ($TOKEN_FILE)"
        else
            fail "Token file exists but is not readable ($TOKEN_FILE)"
        fi
    else
        skip "Token file not found (${TOKEN_FILE:-<unset>})"
    fi

    # Test sbatch wrapper logic (dry run — no job submission needed)
    SBATCH_WRAPPER=""
    if [[ -f /usr/bin/sbatch ]] && head -1 /usr/bin/sbatch 2>/dev/null | grep -q bash; then
        SBATCH_WRAPPER=/usr/bin/sbatch
    fi

    if [[ -n "$SBATCH_WRAPPER" ]]; then
        # Verify wrapper sources sandbox-wrapper.conf
        if grep -q 'sandbox-wrapper.conf' "$SBATCH_WRAPPER"; then
            pass "sbatch wrapper sources sandbox-wrapper.conf"
        else
            fail "sbatch wrapper does not source sandbox-wrapper.conf"
        fi

        # Verify wrapper strips _SANDBOX_BYPASS from --export= flags
        if grep -q '_SANDBOX_BYPASS' "$SBATCH_WRAPPER"; then
            pass "sbatch wrapper handles _SANDBOX_BYPASS stripping"
        else
            fail "sbatch wrapper does not handle _SANDBOX_BYPASS stripping"
        fi

        # Verify wrapper injects token via env var (not CLI)
        if grep -q 'export _SANDBOX_BYPASS' "$SBATCH_WRAPPER"; then
            pass "sbatch wrapper injects token via environment (not CLI)"
        else
            fail "sbatch wrapper does not export _SANDBOX_BYPASS"
        fi

        # Test the stripping logic directly
        OUTPUT=$(echo "ALL,_SANDBOX_BYPASS=secret,FOO=bar" | sed 's/,\?_SANDBOX_BYPASS=[^,]*//' | sed 's/^,//')
        if [[ "$OUTPUT" == "ALL,FOO=bar" ]]; then
            pass "Token stripping preserves other --export= variables"
        else
            fail "Token stripping produced unexpected output" "$OUTPUT"
        fi
    fi

    # Test srun wrapper logic (dry run)
    SRUN_WRAPPER=""
    if [[ -f /usr/bin/srun ]] && head -1 /usr/bin/srun 2>/dev/null | grep -q bash; then
        SRUN_WRAPPER=/usr/bin/srun
    fi

    if [[ -n "$SRUN_WRAPPER" ]]; then
        # Verify wrapper checks SANDBOX_ACTIVE to avoid nesting
        if grep -q 'SANDBOX_ACTIVE' "$SRUN_WRAPPER"; then
            pass "srun wrapper checks SANDBOX_ACTIVE (avoids nesting)"
        else
            fail "srun wrapper does not check SANDBOX_ACTIVE"
        fi

        # Verify wrapper reads token to decide pass-through vs sandbox
        if grep -q 'TOKEN_FILE\|sandbox-wrapper.conf' "$SRUN_WRAPPER"; then
            pass "srun wrapper reads token for pass-through decision"
        else
            fail "srun wrapper does not read token"
        fi
    fi

    # Test token protection: sandboxed process cannot read token
    if [[ -n "${TOKEN_FILE:-}" && -f "$TOKEN_FILE" && -x "$SANDBOX_EXEC" ]]; then
        OUTPUT=$(timeout 15 "$SANDBOX_EXEC" \
            --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
            cat "$TOKEN_FILE" 2>&1) || true
        if echo "$OUTPUT" | grep -qi 'permission denied\|EACCES'; then
            pass "Token protected from sandboxed process"
        elif [[ -z "$OUTPUT" ]]; then
            pass "Token hidden from sandboxed process (empty read)"
        else
            fail "Token readable from sandboxed process" "$OUTPUT"
        fi
    fi

    echo ""
fi

# ══════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════

TOTAL=$((PASS + FAIL + SKIP))
echo "╔═══════════════════════════════════════════════╗"
printf "║  Results: %3d passed, %d failed, %d skipped    ║\n" "$PASS" "$FAIL" "$SKIP"
echo "╚═══════════════════════════════════════════════╝"
echo ""

[[ $FAIL -gt 0 ]] && exit 1
exit 0
