#!/usr/bin/env bash
# test-lab.sh — end-to-end tests for the `lab` CLI's kernel discovery,
# execution, and notebook-editing capabilities.
#
# Spins up a real JupyterLab instance, spawns a kernel via the Sessions
# API, and exercises the full lab CLI surface.
#
# Requirements: uv on PATH.  Run from the repo root:
#     ./test-lab.sh
# Or with verbose output:
#     VERBOSE=1 ./test-lab.sh

set -euo pipefail

: "${VERBOSE:=0}"

# ── Paths ──────────────────────────────────────────────────────────────────

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$REPO_DIR/bin/lab"
HELPER="$REPO_DIR/bin/_lab_kernel.py"

WORK_DIR="$(mktemp -d -t lab-test-XXXXXX)"
VENV_DIR="$WORK_DIR/.venv"
JUPYTER_CONFIG_DIR="$WORK_DIR/.jupyter"
JUPYTER_DATA_DIR="$WORK_DIR/.jupyter/share/jupyter"
RUNTIME_DIR="$JUPYTER_DATA_DIR/runtime"

export JUPYTER_CONFIG_DIR JUPYTER_DATA_DIR

# Pick a random port to avoid collisions with other users on the same box.
PORT=$((20000 + RANDOM % 40000))
TOKEN="testtoken_$(openssl rand -hex 4 2>/dev/null || echo lab)"

pass=0
fail=0
total=0

# ── Helpers ────────────────────────────────────────────────────────────────

cleanup() {
    # Kill any processes we launched.
    if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    # Belt-and-suspenders: kill anything still listening on our port.
    pkill -f "jupyter-lab.*--port $PORT" 2>/dev/null || true
    pkill -f "ipykernel_launcher.*$RUNTIME_DIR" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() { echo "  $*"; }
vlog() { [ "$VERBOSE" = "1" ] && echo "  [v] $*" || true; }

run_test() {
    local name="$1"; shift
    total=$((total + 1))
    if [ "$VERBOSE" = "1" ]; then echo "── $name"; fi
    if "$@"; then
        pass=$((pass + 1))
        echo "  ✓ $name"
    else
        fail=$((fail + 1))
        echo "  ✗ $name"
    fi
}

lab_py() {
    # Run the Python helper directly (faster than going through bin/lab's
    # dependency-ensure path which was already run during setup).
    cd "$WORK_DIR" && "$VENV_DIR/bin/python" "$HELPER" "$@"
}

wait_for_server() {
    local max_wait="${1:-15}"
    local i
    for i in $(seq 1 "$max_wait"); do
        if compgen -G "$RUNTIME_DIR/jpserver-*.json" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_kernel() {
    # Wait until at least one ipykernel_launcher process exists whose
    # connection file is under our RUNTIME_DIR.
    local max_wait="${1:-15}"
    local i
    for i in $(seq 1 "$max_wait"); do
        if lab_py kernel ps 2>/dev/null | grep -q 'hello.ipynb'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ── Setup ──────────────────────────────────────────────────────────────────

echo "test-lab: setting up in $WORK_DIR (port $PORT)"

command -v uv >/dev/null 2>&1 || { echo "SKIP: uv not found"; exit 0; }

mkdir -p "$JUPYTER_CONFIG_DIR" "$JUPYTER_DATA_DIR" "$RUNTIME_DIR"

# Create venv with all needed packages.
uv venv "$VENV_DIR" >/dev/null 2>&1
uv pip install --python "$VENV_DIR/bin/python" \
    jupyterlab ipykernel psutil nbformat 2>&1 | tail -1

# Create a test notebook.
cat > "$WORK_DIR/hello.ipynb" <<'NB'
{
 "cells": [
  {"cell_type": "code", "id": "seed", "execution_count": null,
   "metadata": {}, "outputs": [],
   "source": "x = 42\nprint('seeded')"}
 ],
 "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
 "nbformat": 4, "nbformat_minor": 5
}
NB

# Start JupyterLab in the background.
cd "$WORK_DIR"
"$VENV_DIR/bin/jupyter" lab \
    --port "$PORT" --ip 127.0.0.1 --no-browser \
    --IdentityProvider.token="$TOKEN" \
    --ServerApp.password='' \
    > "$WORK_DIR/jupyter.log" 2>&1 &
SERVER_PID=$!
vlog "server pid $SERVER_PID"

echo "test-lab: waiting for server..."
if ! wait_for_server 15; then
    echo "FAIL: jupyter-lab did not start within 15 s"
    cat "$WORK_DIR/jupyter.log"
    exit 1
fi
vlog "server ready"

# Create a kernel session for hello.ipynb via the Sessions API.
curl -sf "http://127.0.0.1:$PORT/api/sessions" \
    -H "Authorization: token $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"kernel":{"name":"python3"},"name":"hello.ipynb","path":"hello.ipynb","type":"notebook"}' \
    > /dev/null

echo "test-lab: waiting for kernel..."
if ! wait_for_kernel 15; then
    echo "FAIL: kernel did not appear within 15 s"
    exit 1
fi
vlog "kernel ready"

# ── Tests ──────────────────────────────────────────────────────────────────

echo
echo "test-lab: running tests"

# --- kernel ps ---

test_kernel_ps() {
    local out
    out="$(lab_py kernel ps 2>&1)"
    echo "$out" | grep -q "hello.ipynb"
}
run_test "kernel ps shows hello.ipynb" test_kernel_ps

test_kernel_ps_columns() {
    local out
    out="$(lab_py kernel ps 2>&1)"
    echo "$out" | head -1 | grep -q "PID" && echo "$out" | head -1 | grep -q "NOTEBOOK"
}
run_test "kernel ps output has PID and NOTEBOOK columns" test_kernel_ps_columns

# --- kernel find ---

test_kernel_find_exact() {
    lab_py kernel find hello.ipynb 2>&1 | grep -q "hello.ipynb"
}
run_test "kernel find hello.ipynb" test_kernel_find_exact

test_kernel_find_substring() {
    lab_py kernel find hello 2>&1 | grep -q "hello.ipynb"
}
run_test "kernel find by substring" test_kernel_find_substring

test_kernel_find_miss() {
    ! lab_py kernel find nonexistent 2>&1
}
run_test "kernel find miss exits non-zero" test_kernel_find_miss

# --- kernel exec ---

test_exec_simple() {
    local out
    out="$(lab_py kernel exec -n hello.ipynb "print('hi')" 2>&1)"
    echo "$out" | grep -q "hi"
}
run_test "kernel exec simple print" test_exec_simple

test_exec_state_persistence() {
    # Set a variable then read it in a separate call.
    lab_py kernel exec -n hello.ipynb "lab_test_var = 1234" >/dev/null 2>&1
    local out
    out="$(lab_py kernel exec -n hello.ipynb "print(lab_test_var)" 2>&1)"
    echo "$out" | grep -q "1234"
}
run_test "kernel exec state persists across calls" test_exec_state_persistence

test_exec_error_exit_code() {
    ! lab_py kernel exec -n hello.ipynb "1/0" 2>/dev/null
}
run_test "kernel exec error returns non-zero" test_exec_error_exit_code

test_exec_error_traceback() {
    local err
    err="$(lab_py kernel exec -n hello.ipynb "1/0" 2>&1 || true)"
    echo "$err" | grep -q "ZeroDivisionError"
}
run_test "kernel exec error includes traceback" test_exec_error_traceback

test_exec_stdin() {
    local out
    out="$(echo 'print("from_stdin")' | lab_py kernel exec -n hello.ipynb -f - 2>&1)"
    echo "$out" | grep -q "from_stdin"
}
run_test "kernel exec from stdin via -f -" test_exec_stdin

test_exec_auto_select() {
    # With a single running kernel, -n/-k should not be required.
    local out
    out="$(lab_py kernel exec "print('auto')" 2>&1)"
    echo "$out" | grep -q "auto"
}
run_test "kernel exec auto-selects single kernel" test_exec_auto_select

# --- kernel inspect ---

test_inspect() {
    lab_py kernel exec -n hello.ipynb "inspect_var = [1,2,3]" >/dev/null 2>&1
    local out
    out="$(lab_py kernel inspect -n hello.ipynb 2>&1)"
    echo "$out" | grep -q "inspect_var"
}
run_test "kernel inspect shows defined variable" test_inspect

test_inspect_filter() {
    local out
    out="$(lab_py kernel inspect -n hello.ipynb inspect_var 2>&1)"
    echo "$out" | grep -q "inspect_var" && ! echo "$out" | grep -q "lab_test_var"
}
run_test "kernel inspect pattern filter" test_inspect_filter

# --- status ---

test_status() {
    local out
    out="$(lab_py status 2>&1)"
    echo "$out" | grep -q "servers:" && echo "$out" | grep -q "kernels:"
}
run_test "status shows servers and kernels sections" test_status

# --- notebook cells ---

test_nb_cells() {
    local out
    out="$(lab_py notebook cells -n "$WORK_DIR/hello.ipynb" 2>&1)"
    echo "$out" | grep -q "x = 42"  # first line of the seed cell
}
run_test "notebook cells lists seed cell" test_nb_cells

# --- notebook show ---

test_nb_show() {
    local out
    out="$(lab_py notebook show -n "$WORK_DIR/hello.ipynb" 0 2>&1)"
    echo "$out" | grep -q "x = 42"
}
run_test "notebook show prints cell source" test_nb_show

# --- notebook append ---

test_nb_append() {
    lab_py notebook append -n "$WORK_DIR/hello.ipynb" "y = x * 2" 2>&1
    local cells
    cells="$(lab_py notebook cells -n "$WORK_DIR/hello.ipynb" 2>&1)"
    echo "$cells" | grep -q "y = x"
}
run_test "notebook append adds a code cell" test_nb_append

test_nb_append_execute() {
    lab_py notebook append --execute -n "$WORK_DIR/hello.ipynb" "print('appended_exec')" 2>&1
    # The cell should be written with outputs.
    local disk
    disk="$(python3 -c "import json,sys; nb=json.load(open('$WORK_DIR/hello.ipynb')); last=nb['cells'][-1]; print(json.dumps(last.get('outputs',[])))")"
    echo "$disk" | grep -q "appended_exec"
}
run_test "notebook append --execute persists output" test_nb_append_execute

test_nb_append_markdown() {
    lab_py notebook append --markdown -n "$WORK_DIR/hello.ipynb" "# A heading" 2>&1
    local cells
    cells="$(lab_py notebook cells -n "$WORK_DIR/hello.ipynb" 2>&1)"
    echo "$cells" | grep -q "# A heading"
}
run_test "notebook append --markdown adds markdown cell" test_nb_append_markdown

# --- notebook replace ---

test_nb_replace() {
    lab_py notebook replace -n "$WORK_DIR/hello.ipynb" 0 "x = 999; print('replaced')" 2>&1
    local out
    out="$(lab_py notebook show -n "$WORK_DIR/hello.ipynb" 0 2>&1)"
    echo "$out" | grep -q "x = 999"
}
run_test "notebook replace rewrites cell" test_nb_replace

# ── Summary ────────────────────────────────────────────────────────────────

echo
echo "test-lab: $pass/$total passed, $fail failed"
if [ "$fail" -gt 0 ]; then
    exit 1
fi
