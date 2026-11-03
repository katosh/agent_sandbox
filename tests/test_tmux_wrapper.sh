#! /bin/bash --
# tests/test_tmux_wrapper.sh — regression for bin/tmux's per-call logic.
#
# Runs a copy of the wrapper (outside any sandbox) against fake tmux
# binaries, a fake infocmp and a fake `id`, so it needs no tmux server
# and works on any host. Asserts:
#
#   TERM fallback
#     1. A known TERM is passed through, with the config path.
#     2. An unknown TERM falls back to xterm-256color.
#   Binary selection
#     3. SANDBOX_TMUX_BIN wins and /usr/bin/tmux is not probed.
#     4. With no candidate, /usr/bin/tmux runs and is not probed.
#     5. The newest of several candidates wins; an older candidate loses
#        to /usr/bin/tmux; a candidate whose -V fails is skipped; a
#        candidate that is the wrapper itself is skipped.
#
# Run:  bash tests/test_tmux_wrapper.sh [WRAPPER]
#       (WRAPPER defaults to bin/tmux; pass a copy to test a mutant.)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WRAPPER="${1:-$REPO_DIR/bin/tmux}"

PASS=0
FAIL=0
SKIP=0

T="$(mktemp -d "${TMPDIR:-/tmp}/tmux-wrapper-test.XXXXXX")" || exit 1
# The wrapper derives its socket directory from `id -u`; the fake id
# below makes that a throwaway /tmp/tmux-<name> owned by this test.
FAKE_UID="agent-sandbox-test-$$"
SOCKDIR="/tmp/tmux-$FAKE_UID"
cleanup() { rm -rf "$T" "$SOCKDIR"; }
trap cleanup EXIT

# Install layout the wrapper expects: <dir>/bin/tmux + <dir>/sandbox-tmux.conf
mkdir -p "$T/inst/bin" "$T/fakebin" "$T/home" "$T/hb/bin" "$T/home2"
cp "$WRAPPER" "$T/inst/bin/tmux"
chmod +x "$T/inst/bin/tmux"
: > "$T/inst/sandbox-tmux.conf"
W="$T/inst/bin/tmux"
LOG="$T/log"
: > "$LOG"

cat > "$T/fakebin/id" <<EOF
#! /bin/bash
echo "$FAKE_UID"
EOF
cat > "$T/fakebin/infocmp" <<EOF
#! /bin/bash
echo "infocmp \$1" >> "$LOG"
grep -qxF -- "\$1" "$T/terminfo.ok"
EOF
printf '%s\n' known-term xterm-256color > "$T/terminfo.ok"
chmod +x "$T/fakebin/id" "$T/fakebin/infocmp"

# make_fake PATH NAME VERSION — VERSION "fail" makes -V fail.
make_fake() {
    cat > "$1" <<EOF
#! /bin/bash
if [[ "\$*" == "-V" ]]; then
    echo "probe $2" >> "$LOG"
    [[ "$3" == fail ]] && exit 1
    echo "tmux $3"
    exit 0
fi
echo "exec $2 TERM=\$TERM args=\$*" >> "$LOG"
EOF
    chmod +x "$1"
}
make_fake "$T/pinned" pinned 1.0

FAKE_PATH="$T/fakebin:/usr/bin:/bin"

# run [VAR=VAL ...] — one wrapper call with a controlled environment.
# Defaults: no candidates (HOME and HOMEBREW_PREFIX point at empty dirs),
# the pinned fake as SANDBOX_TMUX_BIN, TERM=known-term.
run() {
    : > "$LOG"
    timeout 10 env -i PATH="$FAKE_PATH" HOME="$T/home" \
        HOMEBREW_PREFIX="$T/hb" SANDBOX_TMUX_BIN="$T/pinned" \
        TERM=known-term "$@" /bin/bash "$W" list-sessions \
        >"$T/out" 2>"$T/err"
}
# trace [VAR=VAL ...] — like run, under xtrace, so probes are visible.
trace() {
    : > "$LOG"
    timeout 10 env -i PATH="$FAKE_PATH" HOME="$T/home" \
        HOMEBREW_PREFIX="$T/hb" TERM=known-term "$@" \
        /bin/bash -x "$W" -V >"$T/out" 2>"$T/err"
}
n_infocmp() { grep -c '^infocmp ' "$LOG"; }
exec_line() { grep '^exec ' "$LOG"; }

check() {  # check NAME CONDITION-RESULT(0/1) DETAIL
    if [[ "$2" == 0 ]]; then
        echo "PASS [$1]"; PASS=$((PASS+1))
    else
        echo "FAIL [$1]: $3"; FAIL=$((FAIL+1))
        echo "  log: $(tr '\n' '|' < "$LOG")"
        echo "  err: $(tail -3 "$T/err" | tr '\n' '|')"
    fi
}
skip() { echo "SKIP [$1]: $2"; SKIP=$((SKIP+1)); }
is() { [[ "$1" == "$2" ]]; echo $?; }
has() { [[ "$1" == *"$2"* ]]; echo $?; }
lacks() { [[ "$1" != *"$2"* ]]; echo $?; }
# ── 1–2. TERM fallback ─────────────────────────────────────────────
run
check "term/known-passed-through" "$(has "$(exec_line)" "TERM=known-term ")" "$(exec_line)"
CONF="$(readlink -f "$T/inst")/bin/../sandbox-tmux.conf"
check "conf/path-passed" "$(has "$(exec_line)" "args=-f $CONF list-sessions")" "$(exec_line)"
check "term/known-runs-infocmp" "$(is "$(n_infocmp)" 1)" "infocmp ran $(n_infocmp)x"
run TERM=unknown-term
check "term/unknown-falls-back" "$(has "$(exec_line)" "TERM=xterm-256color ")" "$(exec_line)"

# ── 3–5. binary selection ─────────────────────────────────────────
host_cands=()
for c in /home/linuxbrew/.linuxbrew/bin/tmux /opt/homebrew/bin/tmux /usr/local/bin/tmux; do
    [[ -x "$c" ]] && host_cands+=("$c")
done
# xtrace prints the version probe inside $( $( ) ) as "++… /usr/bin/tmux -V"
# and the final exec as "+ exec …", which this does not count.
sys_probed() { grep -cE '^\+{2,} /usr/bin/tmux -V$' "$T/err"; }
probes_of() { grep -c "^probe $1\$" "$LOG"; }

trace SANDBOX_TMUX_BIN="$T/pinned"
check "bin/override-wins" "$(has "$(exec_line)" "exec pinned ")" "$(exec_line)"
check "bin/override-no-system-probe" "$(is "$(sys_probed)" 0)" "probed $(sys_probed)x"

if (( ${#host_cands[@]} )); then
    skip "bin/no-candidate-*" "host has candidate(s): ${host_cands[*]}"
else
    trace
    check "bin/no-candidate-no-system-probe" "$(is "$(sys_probed)" 0)" "probed $(sys_probed)x"
    check "bin/no-candidate-execs-system" \
        "$( [[ -z "$(exec_line)" && "$(cat "$T/out")" == "tmux "* ]]; echo $?)" "$(exec_line)"
fi

make_fake "$T/hb/bin/tmux" hb-new 99.9
mkdir -p "$T/home/.linuxbrew/bin"
make_fake "$T/home/.linuxbrew/bin/tmux" home-old 98.1
trace
check "bin/newest-of-two-wins" "$(has "$(exec_line)" "exec hb-new ")" "$(exec_line)"
check "bin/system-probed-at-most-once" "$( [[ "$(sys_probed)" -le 1 ]]; echo $?)" "probed $(sys_probed)x"
check "bin/each-candidate-probed-once" \
    "$( [[ "$(probes_of hb-new)" == 1 && "$(probes_of home-old)" == 1 ]]; echo $?)" \
    "hb-new $(probes_of hb-new)x, home-old $(probes_of home-old)x"
make_fake "$T/hb/bin/tmux" hb-old 98.1
make_fake "$T/home/.linuxbrew/bin/tmux" home-new 99.9
trace
check "bin/later-newer-candidate-wins" "$(has "$(exec_line)" "exec home-new ")" "$(exec_line)"
make_fake "$T/hb/bin/tmux" hb-broken fail
trace
check "bin/failing-V-skipped" "$(has "$(exec_line)" "exec home-new ")" "$(exec_line)"
rm -f "$T/home/.linuxbrew/bin/tmux"
if [[ -x /usr/bin/tmux ]] && /usr/bin/tmux -V 2>/dev/null | grep -q '^tmux [1-9]'; then
    make_fake "$T/hb/bin/tmux" hb-ancient 0.1
    trace
    check "bin/older-candidate-loses-to-system" "$(is "$(exec_line)" "")" "$(exec_line)"
    check "bin/system-probed-when-compared" "$(is "$(sys_probed)" 1)" "probed $(sys_probed)x"
else
    skip "bin/older-candidate-loses-to-system" "no versioned /usr/bin/tmux"
fi
rm -f "$T/hb/bin/tmux"
ln -s "$W" "$T/hb/bin/tmux"
trace SANDBOX_TMUX_BIN=
rc=$?
check "bin/self-candidate-skipped" "$( [[ $rc != 124 ]]; echo $?)" "rc=$rc (recursion?)"

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
exit $FAIL
