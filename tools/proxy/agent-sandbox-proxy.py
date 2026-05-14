#!/usr/bin/env python3
# agent-sandbox-proxy — HTTP CONNECT + SOCKS5 proxy for NETWORK_FILTER_MODE=proxied.
#
# Two modes:
#
#   --server  (host-side)
#       Listens on two Unix sockets in --socket-dir (http.sock, socks.sock).
#       Speaks HTTP CONNECT (HTTPS via CONNECT, plain HTTP via request line
#       rewrite) on http.sock; SOCKS5 (CONNECT method) on socks.sock.
#       Enforces --blocklist-json + --except-json at connect-request time.
#       Hard IP floor: 127/8, ::1, 169.254/16, fe80::/10, RFC1918, IPv6 ULA,
#       IPv6 metadata. Resolves hostname once, checks IP, connects to literal
#       IP — no DNS-rebind window.
#
#   --bridge  (sandbox-side)
#       Listens on TCP 127.0.0.1:<http-port> + 127.0.0.1:<socks-port>; forwards
#       byte-for-byte to Unix sockets at --socket-dir/http.sock + socks.sock.
#       Then execs the agent argv after `--`. Bridge stays PID 1 inside the
#       sandbox's empty netns; agent is its child.
#
# Compat: Python 3.6+ (no asyncio.run / no walrus / no PEP-563 annotations).
# Process-death contract: prctl(PR_SET_PDEATHSIG, SIGTERM) is the first
# executable statement (mirror chaperon/chaperon.sh).
#
# The proxy is a defense-in-depth chokepoint, NOT a substitute for
# operating-system isolation. It enforces destination policy on outbound
# connections; what happens inside an allowed TLS tunnel is opaque (same
# as any HTTP CONNECT proxy).

import ctypes
import ctypes.util
import errno
import ipaddress
import json
import os
import re
import select
import signal
import socket
import struct
import sys
import threading
import time

# ─── PR_SET_PDEATHSIG must run before anything else ───────────────
# Linux prctl(2): if our parent dies, deliver SIGTERM to us. This is
# how the host-side proxy dies cleanly when sandbox-exec.sh dies and
# how the in-sandbox bridge dies when bwrap tears the netns down.
# Mirror chaperon.sh:50-60 — first action, no work done before.
_PR_SET_PDEATHSIG = 1
try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                        use_errno=True)
    _libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
except Exception:
    pass  # non-Linux or libc missing — prctl is best-effort

# ─── Hard IP floor — always blocked regardless of NETWORK_BLOCKLIST ─
# Cloud metadata endpoints, link-local, RFC1918, loopback. Lifting these
# would defeat the whole point of the proxy chokepoint. We do NOT honour
# NETWORK_BLOCKLIST_EXCEPT against the floor — admin pin can carve a hole
# via the floor list only via code change, not config (intentional).
#
# IPv4: 127/8 loopback, 169.254/16 link-local + AWS/Azure/GCP metadata,
#       RFC1918 (10/8, 172.16/12, 192.168/16), 100.64/10 carrier-NAT,
#       0.0.0.0/8 reserved.
# IPv6: ::1 loopback, fe80::/10 link-local + IPv6 cloud metadata (AWS
#       fe80::a9fe:a9fe, GCP fe80::4001), fc00::/7 ULA (covers fd00:ec2::254),
#       ::/8 unspecified.
_FLOOR_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::/8"),
]


def ip_in_floor(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _FLOOR_NETS:
        if addr.version == net.version and addr in net:
            return True
    return False


# ─── Host token validation + normalisation ────────────────────────
# Reject CR/LF/NUL/space/tab + URL-confusion characters in the host
# token. Reject IPv4-quirky forms (decimal-int, hex, octal) — they
# evade simple string match against blocklist entries. Lowercase the
# host for case-insensitive blocklist match.
_HOST_REJECT_CHARS = re.compile(r'[\x00-\x20\x7f@#?\\/]')


def normalise_host(host):
    """Return (canonical_host_or_None, error_message_or_None).

    canonical_host is lowercase, IDN-encoded, and either a dotted-quad
    IPv4 / bracketed IPv6 / DNS-name. Returns None + error on rejection.
    """
    if not host:
        return None, "empty host"
    if _HOST_REJECT_CHARS.search(host):
        return None, "host contains forbidden character"
    # Strip a single trailing dot (FQDN root) so 'example.com.' and
    # 'example.com' match the same blocklist entry.
    if host.endswith("."):
        host = host[:-1]
    # Bracketed IPv6.
    if host.startswith("[") and host.endswith("]"):
        try:
            ip = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None, "invalid bracketed IPv6"
        return "[" + ip.compressed + "]", None
    # Numeric — must be strict dotted-quad IPv4 OR un-bracketed IPv6.
    # `ipaddress.ip_address()` rejects decimal-int (2130706433), hex
    # (0x7f000001), and short forms (127.1) — by design.
    try:
        ip = ipaddress.ip_address(host)
        return ip.compressed.lower(), None
    except ValueError:
        pass
    # Hostname path: IDN-encode (turns unicode into punycode), lowercase.
    # The `idna` module is third-party; use `encode('idna')` from the
    # stdlib which covers IDNA2003. Adequate for blocklist matching; we
    # do not need IDNA2008 strictness.
    try:
        # encode/decode dance — bytes 'idna' produces ascii-compatible label.
        h = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return None, "invalid hostname (IDN)"
    # Reject host strings that look like numeric IP forms but were
    # rejected by `ipaddress.ip_address()` above. Catches:
    #   - all-digits-and-dots (e.g. '192.168.1', '127.1', '2130706433')
    #     — short-form IPv4 forms that glibc's `getaddrinfo` ACCEPTS,
    #     and would otherwise sneak past the blocklist's literal-string
    #     entries while still resolving to a floor IP.
    #   - 0x-prefixed hex / 0-prefixed octal IPv4 literals — same.
    # The IP floor catches the resolved address as defense-in-depth,
    # but rejecting at parse time keeps the contract simple.
    if re.match(r'^[0-9.]+$', h) or re.match(r'^0[xX][0-9a-fA-F]+$', h):
        return None, "invalid IPv4 literal"
    return h, None


# ─── Blocklist evaluation ─────────────────────────────────────────
#
# Mirrors `_network_rule_matches` in sandbox-lib.sh: bash-glob host
# patterns, exact host[:port], CIDR[:port], bare port. The semantic
# `EXCEPT` list carves holes via the same precedence model: an exception
# applies when a more-specific EXCEPT entry overlaps a less-specific
# BLOCK entry. We implement specificity ordering as a simple "exact-host
# > CIDR > wildcard > bare-port" length comparison, mirroring the v1.0
# precedence model.

def _parse_entry(entry):
    """Parse a blocklist entry into (host_or_None, port_or_None, cidr_or_None,
    wildcard_or_None). Bare port: (None, port, None, None). Bare host:
    (host, None, None, None). host:port: (host, port, None, None). CIDR[:port]:
    (None, port, cidr, None). Wildcard host pattern: (None, port, None, glob)."""
    # Strip optional :port.
    port = None
    h = entry
    if ":" in entry:
        # Bracketed IPv6 with port: [::1]:443
        if entry.startswith("["):
            end = entry.find("]")
            if end != -1 and end + 1 < len(entry) and entry[end + 1] == ":":
                h = entry[1:end]
                try:
                    port = int(entry[end + 2:])
                except ValueError:
                    port = None
            else:
                h = entry
        elif entry.count(":") == 1:
            # IPv4 or hostname with port.
            head, _, tail = entry.rpartition(":")
            try:
                port = int(tail)
                h = head
            except ValueError:
                h = entry  # not a port suffix; leave intact
        else:
            # Looks like an un-bracketed IPv6 literal — leave as host.
            h = entry
    # Bare integer entry → port-only block.
    try:
        only_port = int(h)
        return (None, only_port, None, None)
    except ValueError:
        pass
    # CIDR?
    if "/" in h:
        try:
            cidr = ipaddress.ip_network(h, strict=False)
            return (None, port, cidr, None)
        except ValueError:
            pass
    # Glob wildcard?
    if "*" in h or "?" in h:
        return (None, port, None, h.lower())
    # Plain host.
    return (h.lower(), port, None, None)


def _glob_match(pattern, host):
    """bash-glob match — only `*` (any chars) and `?` (single char) supported.
    Mirrors `_network_rule_matches` in sandbox-lib.sh."""
    # Convert glob → regex.
    rx = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.match("^" + rx + "$", host) is not None


def _entry_matches(parsed_entry, host_lower, host_ip, port):
    eh, ep, ecidr, eglob = parsed_entry
    # Port narrowing.
    if ep is not None and ep != port:
        return False
    # Wildcard host pattern.
    if eglob is not None:
        return _glob_match(eglob, host_lower)
    # CIDR — only if we have an IP.
    if ecidr is not None:
        if host_ip is None:
            return False
        try:
            addr = ipaddress.ip_address(host_ip)
            if addr.version != ecidr.version:
                return False
            return addr in ecidr
        except ValueError:
            return False
    # Exact host.
    if eh is not None:
        if host_lower == eh:
            return True
        if host_ip is not None and host_ip == eh:
            return True
        return False
    # Bare-port entry (no host narrowing).
    return ep is not None and ep == port


def policy_check(host_lower, host_ip, port, blocklist, exceptlist):
    """Returns (allowed, reason).

    Order:
      1. If host_ip is set, check the hardened IP floor — deny on hit.
      2. Walk the blocklist; an entry matches against either the literal
         host (wildcard / DNS-name / bare-port) or the resolved IP
         (CIDR / IP-form host). If a match fires, check EXCEPT.
    Callers MUST pass host_lower (hostname normalised) and host_ip
    (resolved IP, if known). For DNS-rebind defence, callers resolve
    the hostname once before calling and pass the resolved IP here —
    that IP is the one the upstream connect() will use.
    Specificity: exact host > CIDR (smaller mask) > wildcard > bare
    port. EXCEPT carve-outs follow the same precedence model.
    """
    if host_ip and ip_in_floor(host_ip):
        return False, "destination IP in hardened floor (loopback/RFC1918/link-local/metadata)"
    matching_block = None
    for entry in blocklist:
        parsed = _parse_entry(entry)
        if _entry_matches(parsed, host_lower, host_ip, port):
            matching_block = entry
            break
    if matching_block is None:
        return True, "no blocklist match"
    # Check for an EXCEPT that covers this candidate.
    for entry in exceptlist:
        parsed = _parse_entry(entry)
        if _entry_matches(parsed, host_lower, host_ip, port):
            return True, "blocklist entry '%s' overridden by exception '%s'" % (
                matching_block, entry)
    return False, "blocked by NETWORK_BLOCKLIST entry '%s'" % matching_block


# ─── Connection forwarding ────────────────────────────────────────

def _forward(src, dst):
    """Half-duplex copy until EOF or error."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            try:
                dst.sendall(data)
            except OSError:
                break
    except OSError:
        pass
    # Half-close so the peer sees EOF.
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _pump_both_ways(a, b):
    """Bidirectional pump in two threads; join until both close."""
    t1 = threading.Thread(target=_forward, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_forward, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        a.close()
    except OSError:
        pass
    try:
        b.close()
    except OSError:
        pass


def _connect_upstream(host, port, timeout=10.0):
    """Resolve once; pick first A/AAAA; check IP against floor; connect
    to the literal IP. Returns (sock, resolved_ip) or (None, error)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return None, "DNS resolution failed: %s" % e
    if not infos:
        return None, "DNS returned no records"
    family, _, _, _, sockaddr = infos[0]
    ip = sockaddr[0]
    if ip_in_floor(ip):
        return None, "resolved IP %s in hardened floor" % ip
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sockaddr)
    except OSError as e:
        s.close()
        return None, "connect to %s:%d failed: %s" % (ip, port, e)
    # Keep-alive so persistent HTTP connection pools don't churn the
    # backend pool.
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    s.settimeout(None)
    return s, ip


# ─── HTTP CONNECT server ──────────────────────────────────────────
#
# Speaks: CONNECT host:port HTTP/1.1 → 200 Connection established → byte
# tunnel. Reject everything else (GET / POST forwarding is not
# implemented — TLS dominates; agents that need plain HTTP go via the
# HTTPS proxy directly to the host's port-80 endpoint, since
# HTTP_PROXY=http://... applies to HTTPS too via CONNECT).
#
# Request-line length capped at 8 KiB to defuse slowloris-style header
# floods.

_REQUEST_LINE_MAX = 8 * 1024


def _recv_until(sock, terminator, max_bytes):
    """Read from `sock` until `terminator` appears, or max_bytes reached."""
    buf = b""
    while terminator not in buf and len(buf) < max_bytes:
        chunk = sock.recv(min(4096, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf


_HTTP_CONNECT_RX = re.compile(rb"^CONNECT\s+(\S+)\s+HTTP/1\.[01]\s*\r\n", re.IGNORECASE)


def _http_reply(sock, code, reason, body=b""):
    msg = "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (
        code, reason, len(body))
    try:
        sock.sendall(msg.encode("ascii") + body)
    except OSError:
        pass


def handle_http_connect(client, blocklist, exceptlist):
    try:
        header = _recv_until(client, b"\r\n\r\n", _REQUEST_LINE_MAX)
        if not header:
            return
        m = _HTTP_CONNECT_RX.match(header)
        if not m:
            _http_reply(client, 400, "Bad Request",
                        b"agent-sandbox-proxy: only CONNECT is supported\n")
            return
        target = m.group(1).decode("ascii", errors="replace")
        if ":" not in target:
            _http_reply(client, 400, "Bad Request",
                        b"agent-sandbox-proxy: CONNECT target missing port\n")
            return
        # Split on the LAST colon so bracketed-IPv6 [::1]:443 works.
        host_part, _, port_str = target.rpartition(":")
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("port out of range")
        except ValueError:
            _http_reply(client, 400, "Bad Request",
                        b"agent-sandbox-proxy: invalid port\n")
            return
        canon_host, err = normalise_host(host_part)
        if canon_host is None:
            _http_reply(client, 400, "Bad Request",
                        ("agent-sandbox-proxy: invalid host (%s)\n" % err).encode("ascii"))
            return
        # IP form? Pull a literal IP out of the canonical host string
        # for the policy check; otherwise let `_connect_upstream` resolve.
        host_ip = None
        try:
            ipaddress.ip_address(canon_host.strip("[]"))
            host_ip = canon_host.strip("[]")
        except ValueError:
            host_ip = None
        # Pre-DNS policy check on the literal hostname catches wildcard /
        # exact-DNS-name / bare-port entries without paying the DNS hop
        # (and without leaking a blocked hostname into DNS in the first
        # place — e.g., DoH endpoints in the floor blocklist).
        allowed, reason = policy_check(canon_host, host_ip, port,
                                       blocklist, exceptlist)
        if not allowed:
            _http_reply(client, 403, "Forbidden",
                        ("agent-sandbox-proxy: %s\n" % reason).encode("ascii"))
            return
        # If hostname, resolve up front and re-check policy with the
        # resolved IP so CIDR rules and the IP-floor apply. DNS-rebind
        # defence: this IP is the one we pass to connect() — no second
        # resolve.
        if host_ip is None:
            try:
                infos = socket.getaddrinfo(canon_host, port, type=socket.SOCK_STREAM)
                if not infos:
                    _http_reply(client, 502, "Bad Gateway",
                                b"agent-sandbox-proxy: DNS empty\n")
                    return
                host_ip = infos[0][4][0]
            except socket.gaierror as e:
                _http_reply(client, 502, "Bad Gateway",
                            ("agent-sandbox-proxy: DNS failed: %s\n" % e).encode("ascii"))
                return
            allowed, reason = policy_check(canon_host, host_ip, port,
                                           blocklist, exceptlist)
            if not allowed:
                _http_reply(client, 403, "Forbidden",
                            ("agent-sandbox-proxy: %s\n" % reason).encode("ascii"))
                return
        upstream, ip_or_err = _connect_upstream(host_ip, port)
        if upstream is None:
            _http_reply(client, 502, "Bad Gateway",
                        ("agent-sandbox-proxy: %s\n" % ip_or_err).encode("ascii"))
            return
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        _pump_both_ways(client, upstream)
    except Exception as e:
        try:
            _http_reply(client, 500, "Internal Server Error",
                        ("agent-sandbox-proxy: %s\n" % e).encode("ascii"))
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


# ─── SOCKS5 server ────────────────────────────────────────────────
#
# RFC 1928 minimum: no-auth method (0x00), CONNECT command (0x01) only.
# We refuse BIND (0x02) and UDP ASSOCIATE (0x03). Address types:
# IPv4 (0x01), DOMAIN (0x03), IPv6 (0x04).

def _socks_reply(sock, rep):
    """rep: 0=success, 1=general fail, 2=conn-not-allowed-by-ruleset, ..."""
    # BND.ADDR/PORT = 0.0.0.0:0 (clients ignore).
    try:
        sock.sendall(struct.pack("!BBBB4sH", 0x05, rep, 0x00, 0x01,
                                 b"\x00\x00\x00\x00", 0))
    except OSError:
        pass


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_socks5(client, blocklist, exceptlist):
    try:
        # Greeting: VER NMETHODS METHODS...
        hdr = _recv_exact(client, 2)
        if hdr is None or hdr[0] != 0x05:
            return
        nmethods = hdr[1]
        methods = _recv_exact(client, nmethods)
        if methods is None:
            return
        if 0x00 not in methods:
            client.sendall(b"\x05\xff")  # no acceptable methods
            return
        client.sendall(b"\x05\x00")  # no-auth selected
        # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        req = _recv_exact(client, 4)
        if req is None or req[0] != 0x05:
            return
        cmd = req[1]
        atyp = req[3]
        if cmd != 0x01:  # not CONNECT
            _socks_reply(client, 0x07)  # command not supported
            return
        if atyp == 0x01:  # IPv4
            raw = _recv_exact(client, 4)
            if raw is None:
                return
            host = ipaddress.IPv4Address(raw).compressed
            host_lower = host
            host_ip = host
        elif atyp == 0x03:  # DOMAIN
            ln = _recv_exact(client, 1)
            if ln is None:
                return
            name = _recv_exact(client, ln[0])
            if name is None:
                return
            host = name.decode("ascii", errors="replace")
            canon, err = normalise_host(host)
            if canon is None:
                _socks_reply(client, 0x08)  # address type not supported
                return
            host_lower = canon
            host_ip = None
        elif atyp == 0x04:  # IPv6
            raw = _recv_exact(client, 16)
            if raw is None:
                return
            host = ipaddress.IPv6Address(raw).compressed
            host_lower = host
            host_ip = host
        else:
            _socks_reply(client, 0x08)
            return
        port_b = _recv_exact(client, 2)
        if port_b is None:
            return
        port = struct.unpack("!H", port_b)[0]
        # Pre-DNS policy check on the literal hostname (catches wildcard
        # / DNS-name / bare-port entries) — refuses without paying the
        # DNS hop and without leaking a blocked name into the resolver.
        allowed, _reason = policy_check(host_lower, host_ip, port,
                                        blocklist, exceptlist)
        if not allowed:
            _socks_reply(client, 0x02)  # connection not allowed by ruleset
            return
        # Resolve and re-check against the IP (CIDR + IP-floor).
        # DNS-rebind defence: this IP is the one connect() uses.
        if host_ip is None:
            try:
                infos = socket.getaddrinfo(host_lower, port, type=socket.SOCK_STREAM)
                if not infos:
                    _socks_reply(client, 0x04)  # host unreachable
                    return
                host_ip = infos[0][4][0]
            except socket.gaierror:
                _socks_reply(client, 0x04)
                return
            allowed, _reason = policy_check(host_lower, host_ip, port,
                                            blocklist, exceptlist)
            if not allowed:
                _socks_reply(client, 0x02)
                return
        upstream, ip_or_err = _connect_upstream(host_ip, port)
        if upstream is None:
            _socks_reply(client, 0x05)  # connection refused
            return
        _socks_reply(client, 0x00)
        _pump_both_ways(client, upstream)
    except Exception:
        try:
            _socks_reply(client, 0x01)
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


# ─── Server / bridge loops ────────────────────────────────────────

def _accept_loop(listener, handler, *args):
    while True:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        t = threading.Thread(target=handler, args=(conn,) + args, daemon=True)
        t.start()


def server_main(socket_dir, blocklist, exceptlist):
    # Refuse to start if the directory perms are world-accessible.
    st = os.stat(socket_dir)
    if (st.st_mode & 0o077) != 0:
        sys.stderr.write("agent-sandbox-proxy: socket dir %s perms %#o not 0700\n"
                         % (socket_dir, st.st_mode & 0o777))
        sys.exit(2)
    http_path = os.path.join(socket_dir, "http.sock")
    socks_path = os.path.join(socket_dir, "socks.sock")
    # Clean up any stale sockets from a previous launch.
    for p in (http_path, socks_path):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    http_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socks_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o077)
    try:
        http_sock.bind(http_path)
        os.chmod(http_path, 0o600)
        socks_sock.bind(socks_path)
        os.chmod(socks_path, 0o600)
    finally:
        os.umask(old_umask)
    http_sock.listen(64)
    socks_sock.listen(64)
    t1 = threading.Thread(target=_accept_loop,
                          args=(http_sock, handle_http_connect, blocklist, exceptlist),
                          daemon=True)
    t2 = threading.Thread(target=_accept_loop,
                          args=(socks_sock, handle_socks5, blocklist, exceptlist),
                          daemon=True)
    t1.start()
    t2.start()
    # Signal readiness to the launcher via stdout (newline-terminated).
    try:
        sys.stdout.write("ready\n")
        sys.stdout.flush()
    except OSError:
        pass
    # Wait for SIGTERM (from PR_SET_PDEATHSIG or launcher's trap).
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    while True:
        signal.pause()


def _bridge_connection(client, unix_path):
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(unix_path)
    except OSError:
        try:
            client.close()
        except OSError:
            pass
        return
    _pump_both_ways(client, upstream)


def _bridge_listen(host, port, unix_path, ready_event):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    ready_event.set()
    while True:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        t = threading.Thread(target=_bridge_connection,
                             args=(conn, unix_path), daemon=True)
        t.start()


def bridge_main(socket_dir, http_port, socks_port, agent_argv):
    http_path = os.path.join(socket_dir, "http.sock")
    socks_path = os.path.join(socket_dir, "socks.sock")
    # Wait for the server-side sockets to appear (the host-side proxy
    # may take a moment under load). 5s cap.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if os.path.exists(http_path) and os.path.exists(socks_path):
            break
        time.sleep(0.02)
    if not (os.path.exists(http_path) and os.path.exists(socks_path)):
        sys.stderr.write("agent-sandbox-proxy(bridge): host sockets missing at %s\n"
                         % socket_dir)
        sys.exit(2)
    ev_http = threading.Event()
    ev_socks = threading.Event()
    t1 = threading.Thread(target=_bridge_listen,
                          args=("127.0.0.1", http_port, http_path, ev_http),
                          daemon=True)
    t2 = threading.Thread(target=_bridge_listen,
                          args=("127.0.0.1", socks_port, socks_path, ev_socks),
                          daemon=True)
    t1.start()
    t2.start()
    ev_http.wait(timeout=2.0)
    ev_socks.wait(timeout=2.0)
    if not (ev_http.is_set() and ev_socks.is_set()):
        sys.stderr.write("agent-sandbox-proxy(bridge): listeners failed to bind\n")
        sys.exit(2)
    # Fork-exec the agent argv. The bridge is the parent (PID 1 inside
    # the netns); the agent is its child. Exit when the agent exits.
    pid = os.fork()
    if pid == 0:
        # Child: exec the agent.
        try:
            os.execvp(agent_argv[0], agent_argv)
        except OSError as e:
            sys.stderr.write("agent-sandbox-proxy(bridge): execvp %s failed: %s\n"
                             % (agent_argv[0], e))
            os._exit(127)
    # Parent: wait for the agent.
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    sys.exit(1)


# ─── Argv ─────────────────────────────────────────────────────────

def _usage(rc=2):
    sys.stderr.write(
        "usage:\n"
        "  agent-sandbox-proxy.py --server --socket-dir DIR \\\n"
        "      --blocklist-json JSON --except-json JSON\n"
        "  agent-sandbox-proxy.py --bridge --socket-dir DIR \\\n"
        "      --http-port N --socks-port N -- AGENT_CMD [ARGS...]\n"
    )
    sys.exit(rc)


def main(argv):
    mode = None
    socket_dir = None
    blocklist_json = "[]"
    except_json = "[]"
    http_port = 44889
    socks_port = 44890
    agent_argv = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--server":
            mode = "server"
            i += 1
        elif a == "--bridge":
            mode = "bridge"
            i += 1
        elif a == "--socket-dir":
            socket_dir = argv[i + 1]
            i += 2
        elif a == "--blocklist-json":
            blocklist_json = argv[i + 1]
            i += 2
        elif a == "--except-json":
            except_json = argv[i + 1]
            i += 2
        elif a == "--http-port":
            http_port = int(argv[i + 1])
            i += 2
        elif a == "--socks-port":
            socks_port = int(argv[i + 1])
            i += 2
        elif a == "--":
            agent_argv = argv[i + 1:]
            break
        elif a in ("-h", "--help"):
            _usage(0)
        else:
            sys.stderr.write("agent-sandbox-proxy: unknown arg %r\n" % a)
            _usage()
        # while
    if mode is None or socket_dir is None:
        _usage()
    if mode == "server":
        try:
            blocklist = json.loads(blocklist_json)
            exceptlist = json.loads(except_json)
        except ValueError as e:
            sys.stderr.write("agent-sandbox-proxy: bad --blocklist-json: %s\n" % e)
            sys.exit(2)
        if not isinstance(blocklist, list) or not isinstance(exceptlist, list):
            sys.stderr.write("agent-sandbox-proxy: blocklist/except must be JSON arrays\n")
            sys.exit(2)
        server_main(socket_dir, blocklist, exceptlist)
    elif mode == "bridge":
        if not agent_argv:
            sys.stderr.write("agent-sandbox-proxy: --bridge requires -- AGENT_CMD\n")
            _usage()
        bridge_main(socket_dir, http_port, socks_port, agent_argv)


if __name__ == "__main__":
    main(sys.argv)
