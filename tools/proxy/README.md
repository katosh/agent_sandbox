# tools/proxy/ — host-side policy proxy for NETWORK_FILTER_MODE=proxied

`agent-sandbox-proxy.py` is the single helper for the v0.10.1
`proxied` mode. Two modes:

- **`--server`** (host-side) — listens on two Unix sockets in
  `--socket-dir` (`http.sock` + `socks.sock`); speaks HTTP CONNECT
  and SOCKS5. Enforces `effective_network_blocklist` +
  `NETWORK_BLOCKLIST_EXCEPT` at connect-request time, plus a hardened
  IP floor (RFC1918, loopback, link-local, cloud metadata).
- **`--bridge`** (sandbox-side) — listens on TCP `127.0.0.1:44889` and
  `127.0.0.1:44890` inside the sandbox's empty netns; forwards bytes
  byte-for-byte to the bind-mounted Unix sockets. Then execs the agent
  argv after `--`.

Both modes are spawned by `sandbox-exec.sh` + `backends/bwrap.sh` when
the network-filter resolver picks `proxied`. Operators do not invoke
this helper directly. See `docs/reference/network-filter.md#proxied-
mode-host-side-http-connect--socks5-fallback` for the full surface.

## Why Python, not socat / tinyproxy / microsocks

- **Zero new host dependency.** Python 3 is already a transitive
  requirement (`backends/landlock-sandbox.py`, `install.sh`'s probe).
  Adding `socat` + `tinyproxy` + `microsocks` to the host requirement
  set would block every degraded-pasta host that's the main target of
  this work — those are typically locked-down HPC login nodes where
  `apt install` is not an option.
- **One auditable file.** All policy decisions live in one place.
  A single Python file (~600 LOC) is straightforward to read and
  reason about under set-uid attacker assumptions; vendoring three
  C binaries with per-arch builds + SHA-pinning is materially more
  work both at audit-time and at release-time.
- **Performance is adequate.** HTTPS API calls and `pip` wheel
  fetches dominate on RTT; localhost-to-Unix-socket overhead is
  <2ms per CONNECT and zero per reused HTTP/1.1 keep-alive
  connection.

The bridge inside the sandbox is the same script. Running Python in
two roles in the same launch costs ~50 MB RSS total. Acceptable on
HPC compute nodes; tight on cgroup-memory-capped login nodes — pin
`NETWORK_FILTER_MODE=open` for sessions that need every byte.

## Compatibility

Python 3.6+. No `asyncio.run` (3.7+), no walrus `:=` (3.8+), no
PEP-563 future annotations, no third-party imports. All from stdlib:
`ctypes`, `ipaddress`, `json`, `os`, `re`, `select`, `signal`,
`socket`, `struct`, `sys`, `threading`, `time`.

## Lifecycle

`PR_SET_PDEATHSIG(SIGTERM)` is armed as the script's FIRST executable
statement (line 47 of `agent-sandbox-proxy.py`, before any imports
beyond stdlib essentials), mirroring `chaperon/chaperon.sh:50-60`.
The host-side daemon dies cleanly when `sandbox-exec.sh` exits; the
in-sandbox bridge dies when bwrap tears its pid-namespace down.
`sandbox-exec.sh`'s cleanup trap also kills the daemon and rm -rf's
the socket dir as belt-and-suspenders for the pre-exec failure
window (Ctrl-C between daemon spawn and bwrap exec).
