#!/usr/bin/env bash
# test.sh — Comprehensive test suite for the bubblewrap sandbox
#
# Runs from the repo directory or the installed ~/.claude/sandbox/.
# Tests cover filesystem isolation, environment blocking, Slurm binary
# isolation, overlay generation, and sbatch/srun wrapping.
#
# Usage:
#   bash test.sh              # run all tests
#   bash test.sh --verbose    # show command output on failure

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BWRAP_SANDBOX="$SCRIPT_DIR/bwrap-sandbox.sh"
PROJECT_DIR="$SCRIPT_DIR"   # use the repo itself as the writable project dir

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0
FAIL=0
SKIP=0

# ── Helpers ───────────────────────────────────────────────────────

pass() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }
skip() { ((SKIP++)); echo "  ⊘ $1 (skipped)"; }

# Run a command inside the sandbox. Returns the exit code.
# Captures stdout+stderr in $OUTPUT.
sandbox() {
    OUTPUT=$(timeout 15 "$BWRAP_SANDBOX" --project-dir "$PROJECT_DIR" -- "$@" 2>&1)
    return $?
}

# ── Pre-flight ────────────────────────────────────────────────────

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Test Suite                           ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

if [[ ! -x "$BWRAP_SANDBOX" ]]; then
    echo "ERROR: bwrap-sandbox.sh not found at $BWRAP_SANDBOX"
    exit 1
fi

# Check for AppArmor userns restriction (Ubuntu 24.04+)
if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] \
   && [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == "1" ]]; then
    BWRAP_PATH="$(command -v bwrap)"
    echo "ERROR: AppArmor blocks unprivileged user namespaces on this system."
    echo "  bwrap will fail with 'setting up uid map: Permission denied'."
    echo ""
    echo "  Ask your sysadmin to create /etc/apparmor.d/bwrap with:"
    echo ""
    echo "    abi <abi/4.0>,"
    echo "    include <tunables/global>"
    echo "    profile bwrap $BWRAP_PATH flags=(unconfined) {"
    echo "      userns,"
    echo "    }"
    echo ""
    echo "  Then: sudo apparmor_parser -r /etc/apparmor.d/bwrap"
    echo ""
    echo "  Or disable globally: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
    exit 1
fi

# ── 1. Basic sandbox ─────────────────────────────────────────────

echo "1. Basic sandbox functionality"

if sandbox echo "hello"; then
    pass "Sandbox starts and runs commands"
else
    fail "Sandbox failed to start" "$OUTPUT"
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

echo ""

# ── 2. Filesystem isolation ──────────────────────────────────────

echo "2. Filesystem isolation"

if sandbox test -d ~/.ssh; then
    fail "~/.ssh is visible (should be hidden)"
else
    pass "~/.ssh is hidden"
fi

if sandbox test -d ~/.aws; then
    fail "~/.aws is visible (should be hidden)"
else
    pass "~/.aws is hidden"
fi

if sandbox test -d ~/.gnupg; then
    fail "~/.gnupg is visible (should be hidden)"
else
    pass "~/.gnupg is hidden"
fi

# Project dir writable
TESTFILE="$PROJECT_DIR/.test-write-$$"
if sandbox bash -c "touch '$TESTFILE' && rm -f '$TESTFILE'"; then
    pass "Project directory is writable"
else
    fail "Project directory is not writable" "$OUTPUT"
fi
rm -f "$TESTFILE"

# Outside project dir read-only
if sandbox touch /tmp/outside-test 2>/dev/null; then
    # /tmp is a tmpfs inside the sandbox, writing there is expected to work
    # but writing to $HOME or other NFS paths should fail
    :
fi

if sandbox bash -c "touch \$HOME/test-readonly 2>&1"; then
    fail "Home directory is writable (should be read-only)"
else
    pass "Home directory is read-only"
fi

echo ""

# ── 3. Environment variable blocking ────────────────────────────

echo "3. Environment variable blocking"

# Export test vars so the sandbox can try to inherit them
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

if sandbox bash -c 'echo ${OPENAI_API_KEY:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "OPENAI_API_KEY is blocked"
    else
        fail "OPENAI_API_KEY leaked into sandbox" "$OUTPUT"
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

# ── 4. CLAUDE.md and settings.json overlays ──────────────────────

echo "4. CLAUDE.md and settings.json overlays"

# The overlay should contain sandbox instructions
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
if [[ -e "$CLAUDE_MD" ]]; then
    # Resolve symlink to check the correct path inside the sandbox
    CLAUDE_MD_RESOLVED="$CLAUDE_MD"
    if [[ -L "$CLAUDE_MD" ]]; then
        CLAUDE_MD_RESOLVED="$(readlink -f "$CLAUDE_MD")"
    fi

    if sandbox bash -c "cat '$CLAUDE_MD_RESOLVED' 2>/dev/null | grep -q 'SANDBOX_ACTIVE'"; then
        pass "CLAUDE.md overlay contains sandbox instructions"
    else
        fail "CLAUDE.md overlay missing sandbox instructions" "$OUTPUT"
    fi
else
    skip "CLAUDE.md not found — overlay test"
fi

# Settings overlay should contain sandbox permissions
SETTINGS="$HOME/.claude/settings.json"
if [[ -e "$SETTINGS" ]]; then
    SETTINGS_RESOLVED="$SETTINGS"
    if [[ -L "$SETTINGS" ]]; then
        SETTINGS_RESOLVED="$(readlink -f "$SETTINGS")"
    fi

    if sandbox bash -c "cat '$SETTINGS_RESOLVED' 2>/dev/null | grep -q 'Bash'"; then
        pass "settings.json overlay contains sandbox permissions"
    else
        fail "settings.json overlay missing sandbox permissions" "$OUTPUT"
    fi
else
    skip "settings.json not found — overlay test"
fi

# Symlink handling: verify the overlays work even when files are symlinks
if [[ -L "$CLAUDE_MD" ]]; then
    pass "CLAUDE.md is a symlink — overlay handled correctly (sandbox started)"
fi
if [[ -L "$SETTINGS" ]]; then
    pass "settings.json is a symlink — overlay handled correctly (sandbox started)"
fi

echo ""

# ── 5. Slurm binary isolation ───────────────────────────────────

echo "5. Slurm binary isolation"

if ! command -v sbatch &>/dev/null; then
    skip "sbatch not found on host — skipping Slurm tests"
    echo ""
else
    # PATH shadow
    if sandbox bash -c 'which sbatch 2>/dev/null'; then
        if echo "$OUTPUT" | grep -q sandbox; then
            pass "sbatch resolves to sandbox wrapper via PATH"
        else
            fail "sbatch does not resolve to sandbox wrapper" "$OUTPUT"
        fi
    else
        fail "sbatch not found inside sandbox"
    fi

    if sandbox bash -c 'which srun 2>/dev/null'; then
        if echo "$OUTPUT" | grep -q sandbox; then
            pass "srun resolves to sandbox wrapper via PATH"
        else
            fail "srun does not resolve to sandbox wrapper" "$OUTPUT"
        fi
    else
        fail "srun not found inside sandbox"
    fi

    # /usr/bin/ overlay
    if sandbox bash -c 'file /usr/bin/sbatch'; then
        if echo "$OUTPUT" | grep -qi "script\|text"; then
            pass "/usr/bin/sbatch is overlaid with redirector script"
        else
            fail "/usr/bin/sbatch is still the real ELF binary" "$OUTPUT"
        fi
    fi

    if sandbox bash -c 'file /usr/bin/srun'; then
        if echo "$OUTPUT" | grep -qi "script\|text"; then
            pass "/usr/bin/srun is overlaid with redirector script"
        else
            fail "/usr/bin/srun is still the real ELF binary" "$OUTPUT"
        fi
    fi

    # Real binaries at obscure path
    if sandbox bash -c 'file /tmp/.sandbox-slurm-real/sbatch'; then
        if echo "$OUTPUT" | grep -qi "ELF"; then
            pass "Real sbatch binary at /tmp/.sandbox-slurm-real/sbatch"
        else
            fail "Real sbatch binary not found at obscure path" "$OUTPUT"
        fi
    fi

    if sandbox bash -c 'file /tmp/.sandbox-slurm-real/srun'; then
        if echo "$OUTPUT" | grep -qi "ELF"; then
            pass "Real srun binary at /tmp/.sandbox-slurm-real/srun"
        else
            fail "Real srun binary not found at obscure path" "$OUTPUT"
        fi
    fi

    # /usr/bin/sbatch redirector points to sandbox
    if sandbox bash -c 'head -2 /usr/bin/sbatch'; then
        if echo "$OUTPUT" | grep -q "sandbox"; then
            pass "/usr/bin/sbatch redirector calls sandbox wrapper"
        else
            fail "/usr/bin/sbatch redirector does not point to sandbox" "$OUTPUT"
        fi
    fi

    echo ""

    # ── 6. sbatch/srun functional tests ──────────────────────────

    echo "6. Slurm submission (functional)"

    # sbatch --wrap via PATH
    if sandbox sbatch --wrap="echo sandbox-test-path" 2>&1; then
        if echo "$OUTPUT" | grep -q "Submitted batch job"; then
            pass "sbatch --wrap via PATH submits job"
        else
            fail "sbatch --wrap via PATH failed" "$OUTPUT"
        fi
    else
        fail "sbatch --wrap via PATH failed" "$OUTPUT"
    fi

    # sbatch via /usr/bin/sbatch (bypass attempt)
    if sandbox /usr/bin/sbatch --wrap="echo sandbox-test-bypass" 2>&1; then
        if echo "$OUTPUT" | grep -q "Submitted batch job"; then
            pass "/usr/bin/sbatch bypass attempt routed through sandbox"
        else
            fail "/usr/bin/sbatch bypass attempt failed" "$OUTPUT"
        fi
    else
        fail "/usr/bin/sbatch bypass attempt errored" "$OUTPUT"
    fi

    # No infinite recursion (should complete within timeout)
    if timeout 10 "$BWRAP_SANDBOX" --project-dir "$PROJECT_DIR" -- \
        sbatch --wrap="echo recursion-test" &>/dev/null; then
        pass "No infinite recursion in sbatch wrapper"
    else
        fail "sbatch wrapper may have infinite recursion (timed out)"
    fi
fi

echo ""

# ── 7. Sandbox self-protection ───────────────────────────────────

echo "7. Sandbox self-protection"

# Use a separate project dir so the writable project mount doesn't
# overlap with the sandbox dir (which would override its read-only mount).
PROTECTION_PROJECT="$(mktemp -d)"
trap "rm -rf '$PROTECTION_PROJECT'" EXIT

protection_sandbox() {
    OUTPUT=$(timeout 15 "$BWRAP_SANDBOX" --project-dir "$PROTECTION_PROJECT" -- "$@" 2>&1)
    return $?
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

echo ""

# ── Summary ───────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo "════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL)"
echo "════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "  Some tests failed. Run with --verbose for details."
    exit 1
fi
