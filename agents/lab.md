# Lab: Stateful Experimentation with Jupyter Kernels

The sandbox ships a `lab` utility (on `$PATH`) that runs a project-local
JupyterLab and gives the agent CLI access to live Jupyter kernels.
Variables, dataframes, and trained models loaded in one turn stay alive
for the next, eliminating the cost of reloading expensive state.

## Two Run Modes

### 1. Agent background mode

The agent starts the server itself, then works against it:

```bash
lab kernel add            # one-time: create .venv, register kernel
lab start                 # daemonize JupyterLab; log at .jupyter/lab.bg.log
lab notebook attach foo.ipynb  # spawn a kernel for the notebook
lab kernel exec -n foo.ipynb "df = pd.read_csv('data.csv')"
lab kernel exec -n foo.ipynb "df.shape"
lab notebook append -n foo.ipynb --execute "df.head()"
```

The user may not have a browser open. That's fine — the agent
drives the kernel directly over ZMQ. Everything is headless.

### 2. User foreground mode (tmux pane)

The user starts JupyterLab in a tmux pane inside the sandbox:

```bash
lab                       # foreground; prints token URL
```

They open the notebook in a browser. The agent, in a different
pane or on a different turn, attaches to the same running kernel:

```bash
lab kernel exec -n foo.ipynb "df.describe()"
```

Both modes use the same CLI underneath.

**Port selection.** On multi-user machines, the default port (8888) will
often be taken by another user. Use `--port`:

```bash
lab --port 9012           # foreground
lab start --port 9012     # background
```

If the requested port is in use, `lab` auto-increments and tries up to 10
consecutive ports before failing.

**HTTPS access.** For remote access over HTTPS with auto-generated
self-signed certs:

```bash
lab start --https                   # binds 0.0.0.0, generates cert
lab start --https --port 9012       # custom port
lab --https --ip 127.0.0.1          # foreground, localhost-only HTTPS
```

`--https` generates a self-signed certificate under `.jupyter/ssl/` if
none exists, and defaults to binding `0.0.0.0`. Set a persistent password
with `lab password` or rely on the auto-generated token.

**Getting the URL.** Use `lab url` to print the running server's full
access URL (with token) at any time:

```bash
lab url                             # prints https://host:port/lab?token=...
```

**SSH tunneling.** For localhost-only servers, tunnel from your laptop:

```bash
ssh -L 8888:localhost:8888 user@host
```

## Quick Reference

### Server lifecycle

| Command                | What it does |
|------------------------|-------------|
| `lab`                  | Run JupyterLab in foreground (for tmux pane) |
| `lab start [--https] [--port N] [--ip ADDR]` | Daemonize, log to `.jupyter/lab.bg.log` |
| `lab stop`             | SIGTERM the lab server owning this project |
| `lab status`           | Show running servers and kernels |
| `lab url`              | Print the running server's access URL (with token) |

### Kernelspec management

| Command                 | What it does |
|-------------------------|-------------|
| `lab kernel add [NAME]` | Create `.venv`, install ipykernel, register kernelspec |
| `lab kernel list`       | List registered kernelspecs |
| `lab kernel remove N`   | Unregister a kernelspec |

### Runtime kernel operations

| Command | What it does |
|---------|-------------|
| `lab kernel ps`              | List running kernels: PID, short id, kernelspec, notebook |
| `lab kernel find QUERY`      | Resolve a notebook path/glob/substring to kernel(s) |
| `lab kernel exec [-n NB\|-k K] CODE` | Execute code in a live kernel; streams stdout/stderr |
| `lab kernel exec [-n NB\|-k K] -f FILE` | Execute code from a file (`-` for stdin) |
| `lab kernel inspect [-n NB\|-k K] [PATTERN]` | `%whos`-style listing of live variables |

### Notebook editing

| Command | What it does |
|---------|-------------|
| `lab notebook attach PATH`         | Ensure a kernel exists for this notebook (creates session via server) |
| `lab notebook cells [-n PATH]`     | List cells: index, type, first-line snippet |
| `lab notebook show [-n PATH] IDX`  | Print full source and outputs of cell IDX |
| `lab notebook append [-n PATH] [--markdown] [--execute] CODE` | Append a cell; `--execute` runs it and persists outputs |
| `lab notebook replace [-n PATH] IDX [--execute] CODE` | Replace cell source at IDX |

## Selector Semantics

`-n NOTEBOOK` matches the notebook path stored in each running kernel's
connection file (`jupyter_session` field). Accepted forms:

- Absolute path
- Path relative to `$PWD`
- Bare filename (globbed recursively under `$PWD`)
- Substring match

**Ambiguity:** if the query matches more than one running kernel, the
command prints the candidates and exits non-zero. It will not silently
pick one. Ask the user to clarify, or use `-k PID` / `-k SHORTID` for
an exact target.

When neither `-n` nor `-k` is given and exactly one kernel is running,
that kernel is auto-selected.

## How Discovery Works

Kernels are found by scanning processes for `python -m ipykernel_launcher -f <path>`. The `<path>` argument is the kernel's
connection file, which contains ZMQ ports, HMAC key, and (on modern
`jupyter_server` >= 2.0) the `jupyter_session` field that maps to the
absolute notebook path. This works inside any sandbox regardless of
`JUPYTER_RUNTIME_DIR` because the path is right there on the process
cmdline.

Running lab servers are discovered by reading `jpserver-<pid>.json`
files in the runtime directory (`.jupyter/share/jupyter/runtime/`). Each
file holds the server URL, token, and root directory. Only files whose
pid is alive in the current PID namespace are considered, so stale files
from previous sandbox sessions are ignored.

Notebook edits go through the running server's Contents API (not direct
file writes). This ensures JupyterLab's frontend picks up the change
without showing a "file modified on disk" prompt. If no server is
running, `nbformat` writes the file directly as a fallback.

## Typical Agent Workflows

### Iterate on loaded data

```bash
lab kernel exec -n analysis.ipynb "df.columns.tolist()"
lab kernel exec -n analysis.ipynb "df.groupby('condition')['value'].mean()"
lab kernel exec -n analysis.ipynb "import matplotlib.pyplot as plt; plt.figure(); df.hist(); plt.savefig('dist.png')"
```

The dataframe stays in memory between calls.

### Crystallize results into the notebook

```bash
lab notebook append -n analysis.ipynb --execute "summary = df.describe(); summary"
```

This runs the code, captures the output, and writes the cell (with
outputs) into the notebook file. If the user has the notebook open in
the browser, the change appears after a file reload.

### Inspect what's loaded

```bash
lab kernel inspect -n analysis.ipynb
```

Prints a compact table of all user-defined variables with their types,
lengths, and abbreviated repr.

### Find which notebook a user is talking about

```bash
lab kernel ps                   # lists running kernels + notebook paths
lab kernel find "alignment"     # substring match
```

If the user says "look at the alignment notebook", use `kernel find` to
resolve the ambiguity before attempting `kernel exec`.

## Requirements

`uv` on PATH. The first time `lab kernel exec` (or any runtime
subcommand) runs, `lab` ensures that `psutil`, `jupyter_client`, and
`nbformat` are installed in the project `.venv` alongside `ipykernel`.

## Troubleshooting

**"no running kernels"** — JupyterLab must be running and a notebook
must have an active kernel (either opened in the browser, or spawned via
`lab notebook attach`).

**"no running lab server"** when using `lab notebook attach` — start one
with `lab` (foreground) or `lab start` (background).

**kernel exec times out** — the code is taking longer than the timeout.
Pass `-t SECONDS` to increase it, or `None` (default) for no limit.

**"ambiguous selector"** — more than one kernel matches. Narrow the
search with a longer path or use `-k PID`.

**Port already in use** — another user (or your previous session) is
using the same port. Use `--port N` to pick a different one, or let `lab`
auto-increment: `lab start --port 9012`.
