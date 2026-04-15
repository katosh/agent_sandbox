#!/usr/bin/env python3
"""
_lab_kernel.py — backend for `lab` subcommands that discover, attach to, and
drive running Jupyter kernels without going through the REST API for code
execution.

This file is invoked by bin/lab. It is intentionally a single file with no
non-stdlib dependencies beyond psutil, jupyter_client, and nbformat — all of
which are ensured in ./.venv by bin/lab before dispatching here.

Discovery strategy (borrowed from settylab/jupyter_kernel_inspector):
  * Kernels are scanned via psutil, matching cmdlines that contain
    `-m ipykernel_launcher -f <connection-file>`. The connection file is read
    directly from the path on the cmdline, so this works in any sandbox
    regardless of JUPYTER_RUNTIME_DIR.
  * Modern jupyter_server writes the absolute notebook path into the
    connection file as `jupyter_session`, so we get notebook<->kernel mapping
    for free.
  * Running lab servers are discovered by walking the runtime dir's
    jpserver-<pid>.json files and verifying the pid is alive.
"""

from __future__ import annotations

import argparse
import getpass
import glob
import json
import os
import queue
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil


# ---------------------------------------------------------------------------
# Paths / environment
# ---------------------------------------------------------------------------

PROJECT_DIR = Path(os.environ.get("PWD") or os.getcwd()).resolve()
JUPYTER_CONFIG_DIR = Path(
    os.environ.get("JUPYTER_CONFIG_DIR") or (PROJECT_DIR / ".jupyter")
)
JUPYTER_DATA_DIR = Path(
    os.environ.get("JUPYTER_DATA_DIR") or (JUPYTER_CONFIG_DIR / "share" / "jupyter")
)
JUPYTER_RUNTIME_DIR = JUPYTER_DATA_DIR / "runtime"


def eprint(*args: Any, **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Kernel discovery
# ---------------------------------------------------------------------------


@dataclass
class Kernel:
    pid: int
    username: str
    connection_file: Path
    short_id: str
    kernelspec: str | None
    notebook_path: Path | None  # absolute, as reported by jupyter_session
    connection: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> dict[str, str]:
        return {
            "PID": str(self.pid),
            "ID": self.short_id,
            "KERNEL": self.kernelspec or "-",
            "NOTEBOOK": (
                str(self.notebook_path) if self.notebook_path else "<unknown>"
            ),
        }


def _is_ipykernel(proc_info: dict[str, Any]) -> bool:
    cmdline = proc_info.get("cmdline") or []
    return (
        len(cmdline) > 2
        and "-m" in cmdline
        and "ipykernel_launcher" in cmdline
        and "-f" in cmdline
    )


def discover_kernels(current_user_only: bool = True) -> list[Kernel]:
    """Scan processes for running ipykernel_launcher instances.

    We identify the connection file from the `-f` flag and read it directly.
    `jupyter_session` (added by jupyter_server) maps the kernel to its
    notebook; when absent (classic notebook, bare `jupyter console`, etc.)
    the kernel is still returned with notebook_path=None.
    """
    current_user = getpass.getuser() if current_user_only else None
    seen: set[tuple[str, ...]] = set()
    out: list[Kernel] = []

    for proc in psutil.process_iter(attrs=["pid", "cmdline", "username"]):
        info = proc.info
        if not _is_ipykernel(info):
            continue
        cmdline = tuple(info.get("cmdline") or ())
        if cmdline in seen:
            continue
        seen.add(cmdline)

        username = info.get("username") or ""
        if current_user and username != current_user:
            continue

        try:
            idx = cmdline.index("-f")
        except ValueError:
            continue
        if idx + 1 >= len(cmdline):
            continue

        cf = Path(cmdline[idx + 1])
        try:
            conn = json.loads(cf.read_text())
        except (FileNotFoundError, PermissionError, json.JSONDecodeError):
            conn = {}

        # short id: the uuid fragment of `kernel-<uuid>.json`
        stem_parts = cf.stem.split("-")
        short_id = stem_parts[1] if len(stem_parts) > 1 else cf.stem
        short_id = short_id[:8]

        nb_raw = conn.get("jupyter_session")
        nb_path = Path(nb_raw).resolve() if nb_raw else None

        out.append(
            Kernel(
                pid=info["pid"],
                username=username,
                connection_file=cf,
                short_id=short_id,
                kernelspec=conn.get("kernel_name"),
                notebook_path=nb_path,
                connection=conn,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Server discovery
# ---------------------------------------------------------------------------


@dataclass
class LabServer:
    pid: int
    url: str
    token: str
    root_dir: Path
    secure: bool
    port: int
    runtime_file: Path

    @property
    def api_base(self) -> str:
        return self.url.rstrip("/")


def discover_servers() -> list[LabServer]:
    """Find running jupyter servers by walking the runtime dir.

    Each running server writes a `jpserver-<pid>.json` file containing url,
    token, and root_dir. We keep only those whose pid is still live in this
    PID namespace (sandbox-safe: orphaned files from a previous run are
    ignored).
    """
    out: list[LabServer] = []
    if not JUPYTER_RUNTIME_DIR.is_dir():
        return out
    for jf in sorted(JUPYTER_RUNTIME_DIR.glob("jpserver-*.json")):
        try:
            data = json.loads(jf.read_text())
        except (json.JSONDecodeError, PermissionError, FileNotFoundError):
            continue
        pid = data.get("pid")
        if not isinstance(pid, int):
            continue
        if not psutil.pid_exists(pid):
            continue
        try:
            proc = psutil.Process(pid)
            cmdline = proc.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        # Sanity: ensure this really is a jupyter process. This guards against
        # PID reuse after the server died without cleaning up its json.
        if not any("jupyter" in part for part in cmdline):
            continue
        out.append(
            LabServer(
                pid=pid,
                url=data.get("url", ""),
                token=data.get("token") or "",
                root_dir=Path(data.get("root_dir") or PROJECT_DIR),
                secure=bool(data.get("secure")),
                port=int(data.get("port") or 0),
                runtime_file=jf,
            )
        )
    return out


def server_for_path(servers: list[LabServer], path: Path) -> LabServer | None:
    """Return the server whose root_dir contains `path`. Prefers the longest
    matching root (most-specific server) so nested projects work."""
    path = path.resolve()
    best: LabServer | None = None
    best_len = -1
    for s in servers:
        try:
            root = s.root_dir.resolve()
        except OSError:
            continue
        try:
            path.relative_to(root)
        except ValueError:
            continue
        if len(str(root)) > best_len:
            best = s
            best_len = len(str(root))
    return best


# ---------------------------------------------------------------------------
# Contents API client
# ---------------------------------------------------------------------------


class ContentsClient:
    """Minimal client for a running lab server's /api/contents endpoint.

    We use this for notebook reads/writes so the server broadcasts file-change
    events to any open frontend (avoiding the "file has been modified on
    disk" dialog that direct file writes trigger).
    """

    def __init__(self, server: LabServer) -> None:
        self.server = server
        self._ssl_ctx = None
        if server.secure and server.url.startswith("https://"):
            # Lab certs are often self-signed on HPC — trust them since we
            # only ever talk to 127.0.0.1/localhost anyway.
            self._ssl_ctx = ssl._create_unverified_context()

    def _request(
        self,
        method: str,
        rel_path: str,
        body: dict | None = None,
    ) -> dict:
        url = (
            f"{self.server.api_base}/api/contents/"
            f"{urllib.parse.quote(rel_path)}"
        )
        headers = {"Content-Type": "application/json"}
        if self.server.token:
            headers["Authorization"] = f"token {self.server.token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"lab: server {method} {rel_path} failed: "
                f"HTTP {e.code} {e.read().decode(errors='replace')}"
            ) from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"lab: cannot reach lab server at {self.server.url}: {e}"
            ) from e
        return json.loads(raw) if raw else {}

    def get_notebook(self, rel_path: str) -> dict:
        doc = self._request("GET", rel_path)
        content = doc.get("content")
        if not isinstance(content, dict):
            raise RuntimeError(f"lab: {rel_path}: not a notebook (type={doc.get('type')})")
        return content

    def put_notebook(self, rel_path: str, notebook: dict) -> dict:
        body = {"type": "notebook", "format": "json", "content": notebook}
        return self._request("PUT", rel_path, body)


def notebook_rel_path(nb_abs: Path, server: LabServer) -> str:
    """Return the notebook path relative to the server's root_dir (as the
    Contents API expects)."""
    nb_abs = nb_abs.resolve()
    root = server.root_dir.resolve()
    try:
        return str(nb_abs.relative_to(root))
    except ValueError as e:
        raise RuntimeError(
            f"lab: notebook {nb_abs} is not under lab server root {root}"
        ) from e


# ---------------------------------------------------------------------------
# Selector resolution
# ---------------------------------------------------------------------------


def _match_notebook(kernels: list[Kernel], query: str) -> list[Kernel]:
    """Resolve a notebook-like query to kernels.

    Accepted forms:
      * absolute path                         (must match an existing kernel exactly)
      * path relative to $PWD                 (absolute-matched)
      * basename (globbed under $PWD)
      * substring match against jupyter_session
    """
    if not kernels:
        return []

    query_path = Path(query)
    candidates: list[Path] = []
    if query_path.is_absolute():
        candidates.append(query_path.resolve())
    else:
        rel = (PROJECT_DIR / query_path).resolve()
        if rel.exists():
            candidates.append(rel)
        # glob on basename under project dir
        for hit in PROJECT_DIR.rglob(query_path.name):
            candidates.append(hit.resolve())

    def by_abs(abs_path: Path) -> list[Kernel]:
        return [
            k
            for k in kernels
            if k.notebook_path is not None and k.notebook_path == abs_path
        ]

    matches: list[Kernel] = []
    seen_pids: set[int] = set()
    for c in candidates:
        for k in by_abs(c):
            if k.pid not in seen_pids:
                matches.append(k)
                seen_pids.add(k.pid)
    if matches:
        return matches

    # Substring fallback against jupyter_session
    q_lower = query.lower()
    for k in kernels:
        if (
            k.notebook_path is not None
            and q_lower in str(k.notebook_path).lower()
            and k.pid not in seen_pids
        ):
            matches.append(k)
            seen_pids.add(k.pid)
    return matches


def _match_kernel(kernels: list[Kernel], query: str) -> list[Kernel]:
    """Resolve a kernel selector: PID, short id, or connection file path."""
    if query.isdigit():
        pid = int(query)
        return [k for k in kernels if k.pid == pid]
    query_path = Path(query)
    if query_path.is_absolute():
        qp = query_path.resolve()
        return [k for k in kernels if k.connection_file.resolve() == qp]
    # short id (prefix match on hex)
    q_lower = query.lower()
    return [
        k
        for k in kernels
        if k.short_id.lower().startswith(q_lower)
        or k.connection_file.stem.lower().endswith(q_lower)
    ]


def resolve_one(
    kernels: list[Kernel],
    *,
    notebook: str | None,
    kernel_sel: str | None,
    required_action: str,
) -> Kernel:
    """Resolve exactly one kernel from the selectors. Refuses to guess on
    ambiguity — that is the contract with the agent."""
    if notebook and kernel_sel:
        _die(f"{required_action}: pass either -n NOTEBOOK or -k KERNEL, not both")
    matches: list[Kernel]
    if notebook is not None:
        matches = _match_notebook(kernels, notebook)
        if not matches:
            _die(
                f"{required_action}: no running kernel matches notebook "
                f"'{notebook}'. `lab kernel ps` to list live kernels, or "
                f"`lab notebook attach <path>` to spawn one."
            )
    elif kernel_sel is not None:
        matches = _match_kernel(kernels, kernel_sel)
        if not matches:
            _die(f"{required_action}: no running kernel matches '{kernel_sel}'")
    else:
        if len(kernels) == 1:
            return kernels[0]
        if not kernels:
            _die(
                f"{required_action}: no running kernels. Start lab "
                f"(`lab` or `lab start`) and attach a notebook."
            )
        _die_with_candidates(
            f"{required_action}: multiple kernels running; pass -n NOTEBOOK or -k PID/ID",
            kernels,
        )
    if len(matches) > 1:
        _die_with_candidates(
            f"{required_action}: ambiguous selector matched {len(matches)} kernels",
            matches,
        )
    return matches[0]


# ---------------------------------------------------------------------------
# Kernel execution
# ---------------------------------------------------------------------------


def execute_in_kernel(
    kernel: Kernel,
    code: str,
    *,
    timeout: float | None,
    capture: bool,
) -> tuple[int, str, str, list[dict], int | None]:
    """Execute `code` in the given kernel.

    If `capture` is False, stdout/stderr/result/display all stream directly to
    the parent process's stdout/stderr. If True, everything is accumulated
    and returned along with a list of nbformat-shaped output dicts (used by
    `notebook append --execute`).

    Returns (exit_code, captured_stdout, captured_stderr, outputs, execution_count).
    """
    from jupyter_client import BlockingKernelClient  # type: ignore

    kc = BlockingKernelClient(connection_file=str(kernel.connection_file))
    kc.load_connection_file()
    kc.start_channels()
    try:
        try:
            kc.wait_for_ready(timeout=10)
        except RuntimeError as e:
            raise RuntimeError(
                f"lab: kernel {kernel.short_id} is not responding: {e}"
            ) from e

        msg_id = kc.execute(code, store_history=False, allow_stdin=False)
        had_error = False
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        outputs: list[dict] = []
        execution_count: int | None = None
        per_msg_timeout = 5.0 if timeout is None else min(5.0, timeout)
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            if deadline is not None and time.monotonic() > deadline:
                return 124, "".join(stdout_parts), "".join(stderr_parts), outputs, execution_count
            try:
                msg = kc.get_iopub_msg(timeout=per_msg_timeout)
            except queue.Empty:
                continue
            if msg["parent_header"].get("msg_id") != msg_id:
                continue
            msg_type = msg["msg_type"]
            content = msg["content"]

            if msg_type == "stream":
                text = content.get("text", "")
                if content["name"] == "stdout":
                    if capture:
                        stdout_parts.append(text)
                    else:
                        sys.stdout.write(text)
                        sys.stdout.flush()
                    outputs.append(
                        {"output_type": "stream", "name": "stdout", "text": text}
                    )
                else:
                    if capture:
                        stderr_parts.append(text)
                    else:
                        sys.stderr.write(text)
                        sys.stderr.flush()
                    outputs.append(
                        {"output_type": "stream", "name": "stderr", "text": text}
                    )
            elif msg_type in ("execute_result", "display_data"):
                data = content.get("data") or {}
                text = data.get("text/plain", "")
                if text:
                    if capture:
                        stdout_parts.append(text + "\n")
                    else:
                        sys.stdout.write(text + "\n")
                        sys.stdout.flush()
                metadata = content.get("metadata") or {}
                if msg_type == "execute_result":
                    execution_count = content.get("execution_count")
                    outputs.append(
                        {
                            "output_type": "execute_result",
                            "execution_count": execution_count,
                            "data": data,
                            "metadata": metadata,
                        }
                    )
                else:
                    outputs.append(
                        {
                            "output_type": "display_data",
                            "data": data,
                            "metadata": metadata,
                        }
                    )
            elif msg_type == "error":
                had_error = True
                tb = "\n".join(content.get("traceback", []))
                if capture:
                    stderr_parts.append(tb + "\n")
                else:
                    sys.stderr.write(tb + "\n")
                    sys.stderr.flush()
                outputs.append(
                    {
                        "output_type": "error",
                        "ename": content.get("ename", ""),
                        "evalue": content.get("evalue", ""),
                        "traceback": content.get("traceback", []),
                    }
                )
            elif msg_type == "status" and content.get("execution_state") == "idle":
                break

        # Drain the shell reply for the execution_count in the no-result case.
        try:
            reply = kc.get_shell_msg(timeout=5)
            if execution_count is None:
                execution_count = reply["content"].get("execution_count")
        except queue.Empty:
            pass

        return (
            1 if had_error else 0,
            "".join(stdout_parts),
            "".join(stderr_parts),
            outputs,
            execution_count,
        )
    finally:
        kc.stop_channels()


# ---------------------------------------------------------------------------
# CLI: helpers
# ---------------------------------------------------------------------------


def _die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    eprint(msg)
    sys.exit(code)


def _die_with_candidates(msg: str, kernels: list[Kernel]) -> "NoReturn":  # type: ignore[name-defined]
    eprint(msg)
    eprint()
    _print_table([k.as_row() for k in kernels], stream=sys.stderr)
    sys.exit(2)


def _print_table(rows: list[dict[str, str]], *, stream=sys.stdout) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(r[c]) for r in rows)) for c in cols}
    stream.write("  ".join(c.ljust(widths[c]) for c in cols) + "\n")
    for r in rows:
        stream.write("  ".join(r[c].ljust(widths[c]) for c in cols) + "\n")


def _read_code(args: argparse.Namespace) -> str:
    if args.file:
        if args.code:
            _die("lab: pass either CODE or -f FILE, not both")
        if args.file == "-":
            return sys.stdin.read()
        return Path(args.file).read_text()
    if args.code:
        if len(args.code) == 1 and args.code[0] == "-":
            return sys.stdin.read()
        return "\n".join(args.code)
    _die("lab: no code provided (pass CODE, -f FILE, or '-' for stdin)")


def _notebook_arg(args: argparse.Namespace) -> str | None:
    return getattr(args, "notebook", None)


def _kernel_arg(args: argparse.Namespace) -> str | None:
    return getattr(args, "kernel", None)


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def cmd_kernel_ps(args: argparse.Namespace) -> int:
    kernels = discover_kernels(current_user_only=not args.all_users)
    if not kernels:
        eprint("lab: no running kernels")
        return 0
    _print_table([k.as_row() for k in kernels])
    return 0


def cmd_kernel_find(args: argparse.Namespace) -> int:
    kernels = discover_kernels()
    matches = _match_notebook(kernels, args.query)
    if not matches:
        eprint(f"lab: no running kernel matches '{args.query}'")
        return 1
    _print_table([k.as_row() for k in matches])
    return 0


def cmd_kernel_exec(args: argparse.Namespace) -> int:
    kernels = discover_kernels()
    kernel = resolve_one(
        kernels,
        notebook=_notebook_arg(args),
        kernel_sel=_kernel_arg(args),
        required_action="kernel exec",
    )
    code = _read_code(args)
    exit_code, *_ = execute_in_kernel(
        kernel, code, timeout=args.timeout, capture=False
    )
    return exit_code


def cmd_kernel_inspect(args: argparse.Namespace) -> int:
    kernels = discover_kernels()
    kernel = resolve_one(
        kernels,
        notebook=_notebook_arg(args),
        kernel_sel=_kernel_arg(args),
        required_action="kernel inspect",
    )
    pattern = args.pattern or ""
    # Produce a compact "whos" style listing of user globals.
    code = (
        "def __lab_inspect(pat=''):\n"
        "    import sys\n"
        "    g = dict(globals())\n"
        "    hide = {'In','Out','exit','quit','get_ipython'}\n"
        "    rows = []\n"
        "    for k,v in g.items():\n"
        "        if k.startswith('_') or k in hide: continue\n"
        "        if pat and pat not in k: continue\n"
        "        t = type(v).__name__\n"
        "        try: size = len(v)\n"
        "        except Exception: size = ''\n"
        "        try:\n"
        "            s = repr(v)\n"
        "            if len(s) > 60: s = s[:57] + '...'\n"
        "        except Exception: s = '<unreprable>'\n"
        "        rows.append((k,t,str(size),s))\n"
        "    rows.sort()\n"
        "    w = [max(len(r[i]) for r in rows) if rows else 0 for i in range(4)]\n"
        "    hdr = ('NAME','TYPE','LEN','VALUE')\n"
        "    w = [max(w[i], len(hdr[i])) for i in range(4)]\n"
        "    sys.stdout.write('  '.join(hdr[i].ljust(w[i]) for i in range(4)) + '\\n')\n"
        "    for r in rows:\n"
        "        sys.stdout.write('  '.join(r[i].ljust(w[i]) for i in range(4)) + '\\n')\n"
        f"__lab_inspect({pattern!r})\n"
    )
    exit_code, *_ = execute_in_kernel(kernel, code, timeout=args.timeout, capture=False)
    return exit_code


def _resolve_notebook_path(arg: str | None) -> Path:
    """Resolve the argument to an absolute notebook path.

    Resolution order when arg is given:
      1. Running kernels' jupyter_session paths (exact, basename, substring)
      2. Server root-relative path
      3. CWD-relative path
      4. Absolute path (if given as such)

    If no arg is given, fall back to the single running-kernel notebook.
    """
    if arg:
        # 1. Check running kernels first — they know where their notebooks are
        kernels = discover_kernels()
        matches = _match_notebook(kernels, arg)
        if len(matches) == 1 and matches[0].notebook_path is not None:
            return matches[0].notebook_path
        if len(matches) > 1:
            # Multiple matches — don't guess, but let caller proceed with
            # filesystem resolution (the kernel exec path will catch ambiguity
            # separately if needed)
            pass

        # 2. Server root-relative
        servers = discover_servers()
        if servers:
            for s in servers:
                candidate = (s.root_dir / arg).resolve()
                if candidate.exists():
                    return candidate

        # 3. CWD-relative
        p = Path(arg)
        if p.is_absolute():
            return p.resolve()
        cwd_rel = (PROJECT_DIR / p).resolve()
        if cwd_rel.exists():
            return cwd_rel

        # 4. Glob basename under server root or CWD
        search_dirs = [s.root_dir for s in servers] if servers else [PROJECT_DIR]
        for d in search_dirs:
            hits = list(d.rglob(p.name))
            if len(hits) == 1:
                return hits[0].resolve()

        # Fall through — return CWD-relative even if it doesn't exist yet
        # (caller will get a clear "file not found" from nbformat/server)
        return cwd_rel

    kernels = discover_kernels()
    nb_kernels = [k for k in kernels if k.notebook_path is not None]
    if len(nb_kernels) == 1:
        return nb_kernels[0].notebook_path  # type: ignore[return-value]
    if not nb_kernels:
        _die(
            "notebook: no -n NOTEBOOK given and no running kernel has an "
            "associated notebook. Pass -n explicitly."
        )
    _die_with_candidates(
        "notebook: -n NOTEBOOK is required (multiple live notebooks)",
        nb_kernels,
    )


def _load_notebook(nb_path: Path) -> tuple[dict, LabServer | None, str]:
    """Load the notebook via a running lab server if possible, else from disk.
    Returns (notebook dict, server or None, path-key for saving)."""
    nb_path = nb_path.resolve()
    server = server_for_path(discover_servers(), nb_path)
    if server is not None:
        rel = notebook_rel_path(nb_path, server)
        client = ContentsClient(server)
        return client.get_notebook(rel), server, rel
    # Fallback: read directly.
    import nbformat  # type: ignore

    nb = nbformat.read(str(nb_path), as_version=4)
    return nb, None, str(nb_path)


def _save_notebook(
    nb: dict, server: LabServer | None, key: str, nb_path: Path
) -> None:
    if server is not None:
        ContentsClient(server).put_notebook(key, nb)
        return
    import nbformat  # type: ignore

    nbformat.write(nbformat.from_dict(nb), str(nb_path))


def _cell_snippet(cell: dict) -> str:
    src = cell.get("source", "")
    if isinstance(src, list):
        src = "".join(src)
    first = src.split("\n", 1)[0]
    if len(first) > 72:
        first = first[:69] + "..."
    return first


def cmd_notebook_cells(args: argparse.Namespace) -> int:
    nb_path = _resolve_notebook_path(args.notebook)
    nb, _server, _key = _load_notebook(nb_path)
    cells = nb.get("cells", [])
    rows = [
        {
            "IDX": str(i),
            "TYPE": cell.get("cell_type", "?"),
            "EC": str(cell.get("execution_count") or ""),
            "SOURCE": _cell_snippet(cell),
        }
        for i, cell in enumerate(cells)
    ]
    if not rows:
        eprint(f"lab: {nb_path} has no cells")
        return 0
    _print_table(rows)
    return 0


def cmd_notebook_show(args: argparse.Namespace) -> int:
    nb_path = _resolve_notebook_path(args.notebook)
    nb, _server, _key = _load_notebook(nb_path)
    cells = nb.get("cells", [])
    if args.index < 0 or args.index >= len(cells):
        _die(f"notebook show: index {args.index} out of range (0..{len(cells) - 1})")
    cell = cells[args.index]
    src = cell.get("source", "")
    if isinstance(src, list):
        src = "".join(src)
    print(f"# cell {args.index} ({cell.get('cell_type', '?')})")
    print(src)
    outputs = cell.get("outputs") or []
    if outputs:
        print()
        print("# outputs")
        for out in outputs:
            ot = out.get("output_type")
            if ot == "stream":
                sys.stdout.write(out.get("text", ""))
            elif ot in ("execute_result", "display_data"):
                data = out.get("data") or {}
                text = data.get("text/plain", "")
                if text:
                    print(text)
            elif ot == "error":
                for line in out.get("traceback", []):
                    print(line)
    return 0


def _make_cell_id() -> str:
    import secrets

    return secrets.token_hex(4)


def _make_code_cell(
    source: str, outputs: list[dict] | None = None, execution_count: int | None = None
) -> dict:
    return {
        "cell_type": "code",
        "id": _make_cell_id(),
        "metadata": {},
        "execution_count": execution_count,
        "outputs": outputs or [],
        "source": source,
    }


def _make_md_cell(source: str) -> dict:
    return {
        "cell_type": "markdown",
        "id": _make_cell_id(),
        "metadata": {},
        "source": source,
    }


def cmd_notebook_append(args: argparse.Namespace) -> int:
    nb_path = _resolve_notebook_path(args.notebook)
    nb, server, key = _load_notebook(nb_path)
    cells = nb.setdefault("cells", [])
    content = _read_code(args)

    if args.markdown:
        if args.execute:
            _die("notebook append: --execute is not meaningful for markdown cells")
        cells.append(_make_md_cell(content))
        _save_notebook(nb, server, key, nb_path)
        eprint(f"lab: appended markdown cell at index {len(cells) - 1}")
        return 0

    exit_code = 0
    outputs: list[dict] = []
    execution_count: int | None = None
    if args.execute:
        kernels = discover_kernels()
        kernel = resolve_one(
            kernels,
            notebook=str(nb_path),
            kernel_sel=None,
            required_action="notebook append --execute",
        )
        exit_code, _stdout, _stderr, outputs, execution_count = execute_in_kernel(
            kernel, content, timeout=args.timeout, capture=True
        )
    cells.append(
        _make_code_cell(content, outputs=outputs, execution_count=execution_count)
    )
    _save_notebook(nb, server, key, nb_path)
    msg = f"lab: appended code cell at index {len(cells) - 1}"
    if args.execute:
        msg += f" (executed, exit={exit_code})"
    eprint(msg)
    return exit_code


def cmd_notebook_replace(args: argparse.Namespace) -> int:
    nb_path = _resolve_notebook_path(args.notebook)
    nb, server, key = _load_notebook(nb_path)
    cells = nb.setdefault("cells", [])
    if args.index < 0 or args.index >= len(cells):
        _die(f"notebook replace: index {args.index} out of range (0..{len(cells) - 1})")
    content = _read_code(args)
    old = cells[args.index]
    ct = old.get("cell_type", "code")
    exit_code = 0
    outputs: list[dict] = []
    execution_count: int | None = None
    if args.execute:
        if ct != "code":
            _die("notebook replace: --execute only applies to code cells")
        kernels = discover_kernels()
        kernel = resolve_one(
            kernels,
            notebook=str(nb_path),
            kernel_sel=None,
            required_action="notebook replace --execute",
        )
        exit_code, _stdout, _stderr, outputs, execution_count = execute_in_kernel(
            kernel, content, timeout=args.timeout, capture=True
        )
    if ct == "code":
        cells[args.index] = _make_code_cell(
            content,
            outputs=outputs or old.get("outputs") or [],
            execution_count=execution_count
            if execution_count is not None
            else old.get("execution_count"),
        )
        cells[args.index]["id"] = old.get("id") or _make_cell_id()
    else:
        cells[args.index] = _make_md_cell(content)
        cells[args.index]["id"] = old.get("id") or _make_cell_id()
    _save_notebook(nb, server, key, nb_path)
    return exit_code


def cmd_notebook_attach(args: argparse.Namespace) -> int:
    """Ensure a kernel exists for the given notebook path by asking a running
    lab server to create a Session for it. Prints the resulting kernel row."""
    nb_path = _resolve_notebook_path(args.notebook)
    servers = discover_servers()
    server = server_for_path(servers, nb_path)
    if server is None:
        _die(
            "notebook attach: no running lab server owns this notebook. "
            "Start one with `lab` (foreground) or `lab start` (background)."
        )
    rel = notebook_rel_path(nb_path, server)
    # Check if a live kernel already exists.
    kernels = discover_kernels()
    existing = [k for k in kernels if k.notebook_path == nb_path]
    if existing:
        _print_table([k.as_row() for k in existing])
        return 0
    # Create a new session via the REST API.
    url = f"{server.api_base}/api/sessions"
    body = {
        "kernel": {"name": args.kernel_name or "python3"},
        "name": nb_path.name,
        "path": rel,
        "type": "notebook",
    }
    headers = {"Content-Type": "application/json"}
    if server.token:
        headers["Authorization"] = f"token {server.token}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST", headers=headers
    )
    ctx = ssl._create_unverified_context() if server.secure else None
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        _die(
            f"notebook attach: POST /api/sessions failed: "
            f"HTTP {e.code} {e.read().decode(errors='replace')}"
        )
    except urllib.error.URLError as e:
        _die(f"notebook attach: cannot reach lab server: {e}")
    # Give the kernel a moment to start before scanning again.
    kernel_id = (data.get("kernel") or {}).get("id", "?")
    eprint(f"lab: created session for {rel} (kernel id {kernel_id})")
    for _ in range(20):
        time.sleep(0.25)
        new_kernels = discover_kernels()
        hits = [k for k in new_kernels if k.notebook_path == nb_path]
        if hits:
            _print_table([k.as_row() for k in hits])
            return 0
    eprint("lab: session created but kernel did not appear in process scan yet")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    servers = discover_servers()
    if servers:
        rows = [
            {
                "PID": str(s.pid),
                "URL": s.url,
                "ROOT": str(s.root_dir),
                "TOKEN": "(set)" if s.token else "(none)",
            }
            for s in servers
        ]
        print("servers:")
        _print_table(rows)
    else:
        print("servers: (none)")
    kernels = discover_kernels()
    if kernels:
        print()
        print("kernels:")
        _print_table([k.as_row() for k in kernels])
    else:
        print()
        print("kernels: (none)")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    servers = discover_servers()
    if not servers:
        eprint("lab: no running lab server to stop")
        return 1
    for s in servers:
        if args.all or s.root_dir.resolve() == PROJECT_DIR.resolve():
            try:
                os.kill(s.pid, signal.SIGTERM)
                eprint(f"lab: sent SIGTERM to lab server pid {s.pid}")
            except ProcessLookupError:
                eprint(f"lab: pid {s.pid} already gone")
    return 0


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def _add_selector(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-n",
        "--notebook",
        help="Select by notebook path/glob/substring (resolved against running kernels' jupyter_session)",
    )
    p.add_argument(
        "-k",
        "--kernel",
        help="Select by kernel PID, short id, or connection file path",
    )


def _add_code_inputs(p: argparse.ArgumentParser) -> None:
    p.add_argument("code", nargs="*", help="Code to execute (or '-' for stdin)")
    p.add_argument("-f", "--file", help="Read code from FILE (or '-' for stdin)")
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help="Overall execution timeout in seconds (default: none)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab", add_help=True)
    sub = parser.add_subparsers(dest="group", required=True)

    # --- kernel ----------------------------------------------------------------
    p_k = sub.add_parser("kernel", help="Runtime kernel discovery and execution")
    sk = p_k.add_subparsers(dest="cmd", required=True)

    p = sk.add_parser("ps", help="List running kernels")
    p.add_argument("--all-users", action="store_true")
    p.set_defaults(func=cmd_kernel_ps)

    p = sk.add_parser("find", help="Resolve a notebook pattern to kernel(s)")
    p.add_argument("query")
    p.set_defaults(func=cmd_kernel_find)

    p = sk.add_parser("exec", help="Execute code in a live kernel")
    _add_selector(p)
    _add_code_inputs(p)
    p.set_defaults(func=cmd_kernel_exec)

    p = sk.add_parser("inspect", help="Print a 'whos'-style summary of user globals")
    _add_selector(p)
    p.add_argument("pattern", nargs="?", default="")
    p.add_argument("-t", "--timeout", type=float, default=30.0)
    p.set_defaults(func=cmd_kernel_inspect)

    # --- notebook --------------------------------------------------------------
    p_n = sub.add_parser("notebook", help="Read and edit notebook files via the running lab server")
    sn = p_n.add_subparsers(dest="cmd", required=True)

    p = sn.add_parser("cells", help="List cells (idx, type, snippet)")
    p.add_argument("-n", "--notebook")
    p.set_defaults(func=cmd_notebook_cells)

    p = sn.add_parser("show", help="Show a single cell's source and outputs")
    p.add_argument("-n", "--notebook")
    p.add_argument("index", type=int)
    p.set_defaults(func=cmd_notebook_show)

    p = sn.add_parser("append", help="Append a cell, optionally execute it in the live kernel")
    p.add_argument("-n", "--notebook")
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--execute", action="store_true")
    _add_code_inputs(p)
    p.set_defaults(func=cmd_notebook_append)

    p = sn.add_parser("replace", help="Replace cell at IDX")
    p.add_argument("-n", "--notebook")
    p.add_argument("index", type=int)
    p.add_argument("--execute", action="store_true")
    _add_code_inputs(p)
    p.set_defaults(func=cmd_notebook_replace)

    p = sn.add_parser("attach", help="Ensure a kernel is running for the given notebook (via lab server)")
    p.add_argument("notebook", nargs="?")
    p.add_argument("--kernel-name", default=None, help="kernelspec name (default: python3)")
    p.set_defaults(func=cmd_notebook_attach)

    # --- status / stop ---------------------------------------------------------
    p = sub.add_parser("status", help="Show running lab servers and kernels")
    p.set_defaults(func=cmd_status, group="status", cmd="status")

    p = sub.add_parser("stop", help="Stop background lab server(s) owning this project")
    p.add_argument("--all", action="store_true", help="Stop every discoverable lab server, not just this project's")
    p.set_defaults(func=cmd_stop, group="stop", cmd="stop")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
