# tools/mail-block/ — mailer-stub layer for NETWORK_MAIL_BLOCK

`mail-block-stub.sh` is the single universal stub bound over every
canonical mailer binary inside the sandbox when `NETWORK_MAIL_BLOCK`
is active. Defense-in-depth above `NETWORK_FILTER_MODE`'s port-level
SMTP block: the stub catches the syscall (`execve`) and tells the
agent — in plain text — that mail is disabled, before the network
filter quietly drops a connection on the floor.

## Two layers, one threat class

```
                  ┌──────────────────────────────┐
                  │ AGENT exec's `sendmail -t`   │
                  └────────────┬─────────────────┘
                               │
              CONFIG layer     │ stub layer (this directory)
              ──────────       │
              argv[0] resolves │ → /usr/sbin/sendmail is bind-
              to the bound      mounted to mail-block-stub.sh
              path             │ → per-launch stubs dir under
                               │   $TMPDIR (bound same-path on both
                               │   sides) is PATH-prefixed and
                               │   shadows host-PATH lookups
                               │ → stub prints deterrent message,
                               │   exits 77 (EX_NOPERM)
                               │
                               ▼ if the agent escalates to a
                                 language-level dialer instead…
              NETWORK layer
              ─────────────
              python -c 'smtplib...'   ↘
              curl smtp://relay:25     ─→ NETWORK_FILTER_MODE
              nc relay 25              ↗   blocks 25/465/587 at
                                          the namespace edge
```

The stub catches every UNIX tool that respects the sendmail interface
or has a canonical binary name on PATH; the network filter catches
the application-level remainder. Two reinforcing layers, evaluated
in CONFIG > NETWORK order (so the agent learns the policy in
human-readable terms BEFORE the kernel drops the connection).

## What the stub does

- Print a 16-line deterrent message to **stderr**, addressed to the AI
  agent that exec'd it. The message:
  1. States the rule (mail is disabled in this configuration).
  2. Forecloses the search tree explicitly ("retrying with another
     binary, another invocation, or another path will produce the
     same result").
  3. Enumerates the known-mailer set so the agent doesn't burn cycles
     hunting alternatives.
  4. Instructs explicitly: do not retry; escalate the policy to the
     user; propose an out-of-band channel.
  5. Reports the basename of `$0` and the argv count (sanitized — no
     ANSI / OSC-8 / control-byte injection surface from a hostile
     argv).
- Exit **77** (sysexits.h `EX_NOPERM` — "permission denied at a
  higher level"). `EX_CONFIG` (78) was considered and rejected: it
  reads as "operator misconfiguration, retry with a fix" which invites
  exactly the retry loop the stub is meant to break.

## Argv sanitization

Echoing `argv[1..N]` back to the agent's terminal would create a
control-byte injection surface — a crafted argument containing
`\e[2J\e[H` or OSC-8 hyperlinks can rewrite the agent's screen or
smuggle clickable URLs into log scrapers. We echo only `basename
"$0"` (passed through `LC_ALL=C tr -cd '[:graph:]'` and capped at 64
bytes) and the argv count, never the args themselves.

## Why not log to syslog as well

Considered and rejected. From inside a user-namespaced sandbox
`syslog(3)` writes either to `/dev/log` (often not bind-mounted —
fails silently) or to host journald — a write surface we don't want
to grant to a sandbox (log injection, disk-fill DoS via repeated
execs). Stderr is the right audience: the agent reads it directly,
and host-side audit (if wanted) belongs to bwrap exec tracing or to
the parent process's stderr capture, not to a sandboxed write to a
shared host log.

## POSIX sh on purpose

The stub is invoked at every mailer exec. We avoid bash startup
overhead and avoid pulling bash in as a hard runtime dependency for
the layer. The script uses only commands that coreutils-or-busybox
guarantees (`basename`, `printf`, `cat`, `tr`, `cut`).

## Canonical name list

The launcher (`backends/bwrap.sh::backend_prepare`) iterates
`_MAIL_BLOCK_TARGET_PATHS` (full absolute paths under `/usr/{bin,sbin,
lib}` and `/var/qmail/bin`) and bind-mounts the stub over every entry
that exists on the host; entries that don't exist are silently
skipped (no need to materialise phantom paths). It also creates a
symlink farm in a per-launch tempdir under `$TMPDIR` — one symlink
per name in `_MAIL_BLOCK_STUB_NAMES` pointing at the in-sandbox stub
path — `--ro-bind`'s that dir at the same path on both sides of the
sandbox boundary (mirroring the chaperon FIFO and proxy socket-dir
pattern, so the path resolves identically inside and outside), and
prepends it to PATH. PATH-prefix catches `/usr/local/bin/<name>`,
`/app/software/<pkg>/bin/<name>` (Lmod-injected paths), and any
other host-PATH-position the bind-mount loop missed.

See `sandbox-lib.sh::_MAIL_BLOCK_TARGET_PATHS` and
`_MAIL_BLOCK_STUB_NAMES` for the canonical lists, and
`docs/reference/network-filter.md#outbound-mail-policy` for the
operator-facing documentation.
