#! /bin/bash --
# tests/test_landlock_abi_probe.sh — regression for the Landlock ABI
# hard-requirement probe.
#
# Drives backends/landlock-sandbox.py with LANDLOCK_FAKE_ABI to simulate
# stale-kernel scenarios on any host (including ones with no Landlock at
# all). Asserts:
#
#   1. ABI < required, hard=true       → exit non-zero, error names
#                                        the missing capability.
#   2. ABI < required, hard=false      → exit 0, warning names the
#                                        missing capability.
#   3. ABI >= required                 → exit 0, no diagnostic.
#   4. --required-abi N can be lowered → ABI v1 + required=1 → quiet pass.
#
# Run:  bash tests/test_landlock_abi_probe.sh
#
# Also used by test.sh as part of the Landlock backend section.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HELPER="$REPO_DIR/backends/landlock-sandbox.py"

# Pick the newest python3 available — the helper uses ctypes which is
# in stdlib, so 3.6+ works, but argparse REMAINDER + capture_output in
# subprocess want 3.7+. Prefer brew's 3.11 if installed.
PYTHON3=python3
for cand in python3.12 python3.11 python3.10; do
    if command -v "$cand" >/dev/null 2>&1; then
        PYTHON3="$cand"
        break
    fi
done

PASS=0
FAIL=0

_run() {
    # _run NAME EXPECTED_EXIT "PAT1|PAT2|..." ENV_VARS... -- HELPER_ARGS...
    # Each PAT is checked independently so they can match on separate
    # lines of multi-line output.
    local name="$1" expected_exit="$2" expected_patterns="$3"
    shift 3
    local env_pairs=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do
        env_pairs+=("$1")
        shift
    done
    [[ "$1" == "--" ]] && shift

    local out
    out=$(env "${env_pairs[@]}" "$PYTHON3" "$HELPER" "$@" 2>&1)
    local rc=$?

    local ok=true
    if [[ "$rc" != "$expected_exit" ]]; then
        ok=false
        echo "FAIL [$name]: exit=$rc expected=$expected_exit"
    fi
    if [[ -n "$expected_patterns" ]]; then
        local pat
        local IFS=$'\n'
        for pat in $expected_patterns; do
            if ! grep -qE "$pat" <<<"$out"; then
                ok=false
                echo "FAIL [$name]: output did not match /$pat/"
            fi
        done
    fi
    if $ok; then
        echo "PASS [$name]"
        PASS=$((PASS+1))
    else
        echo "--- output ---"
        echo "$out"
        echo "--- end ---"
        FAIL=$((FAIL+1))
    fi
}

# 1. Hard mode + ABI 1 < required 3  →  exit 1, error names TRUNCATE.
_run "hard/abi-too-old" 1 \
    "^Error:.*configured policy requires v3
FS_TRUNCATE" \
    LANDLOCK_FAKE_ABI=1 \
    -- --check --required-abi 3 --hard-requirement

# 2. Soft mode + ABI 1 < required 3  →  exit 0, warning still names it.
_run "soft/abi-too-old" 0 \
    "^WARNING: Landlock ABI v1
FS_TRUNCATE
continuing with reduced isolation" \
    LANDLOCK_FAKE_ABI=1 \
    -- --check --required-abi 3 --no-hard-requirement

# 3. ABI 4 >= required 3  →  exit 0, no error/warning header.
out=$(LANDLOCK_FAKE_ABI=4 "$PYTHON3" "$HELPER" \
        --check --required-abi 3 --hard-requirement 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && ! grep -qE 'Error|WARNING' <<<"$out"; then
    echo "PASS [ok/abi-meets-floor]"
    PASS=$((PASS+1))
else
    echo "FAIL [ok/abi-meets-floor]: rc=$rc out=$out"
    FAIL=$((FAIL+1))
fi

# 4. ABI 1 + lowered required 1  →  exit 0, no diagnostic.
out=$(LANDLOCK_FAKE_ABI=1 "$PYTHON3" "$HELPER" \
        --check --required-abi 1 --hard-requirement 2>&1)
rc=$?
if [[ $rc -eq 0 ]] && ! grep -qE 'Error|WARNING' <<<"$out"; then
    echo "PASS [ok/lowered-floor]"
    PASS=$((PASS+1))
else
    echo "FAIL [ok/lowered-floor]: rc=$rc out=$out"
    FAIL=$((FAIL+1))
fi

# 5. ABI 0 (no Landlock)  →  hard mode names policy floor.
_run "hard/abi-zero" 1 \
    "Landlock is not available
configured policy requires ABI v3" \
    LANDLOCK_FAKE_ABI=0 \
    -- --check --required-abi 3 --hard-requirement

# 6. Default (no flags) — DEFAULT_REQUIRED_ABI is 3, hard=true by default.
_run "default/abi-1-rejected" 1 \
    'configured policy requires v3' \
    LANDLOCK_FAKE_ABI=1 \
    -- --check

echo
echo "$PASS passed, $FAIL failed"
exit $FAIL
