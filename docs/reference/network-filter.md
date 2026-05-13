# Network filter

The network filter is an optional layer that restricts the sandboxed
agent's outbound network access. It exists to close one specific
threat: a compromised agent abusing the host's network to spoof mail
under the operator's identity (and adjacent lateral-movement /
exfiltration surface).

## Threat model

On a typical HPC compute node (or any shared multi-tenant host) the
local MTA — Mail Transfer Agent, the daemon (e.g. Postfix or
sendmail) that accepts mail for delivery — listens on `127.0.0.1:25`
and accepts the standard local mail-submission protocol (ports
25/465/587/2525) from any local user without authentication, then
relays under that user's `From:` header. Postfix's `mynetworks`
directive frequently extends that trust to a wider organizational
CIDR (lab subnet, campus /16, etc.), so an adversary controlling a
sandboxed agent can spoof the operator's identity in **two** ways:

1. Speak SMTP directly to `127.0.0.1:25` from any TCP-capable
   language (`bash /dev/tcp/127.0.0.1/25`, Python `smtplib`, …).
2. Speak SMTP directly to a nearby relay whose IP is trusted by
   `mynetworks` — the relay accepts unauthenticated submission for
   any sender, again under the operator's identity.

Both bypass any filesystem-level binary block. The fix is to deny the
TCP path itself at a layer the agent cannot escape.

**Non-goals.** This layer does NOT defend against:

- Covert L7 channels over allowed 443 hostnames the policy admits (a
  determined agent with `pip install requests` can POST to any HTTPS
  endpoint the policy permits). The default blocklist closes the
  obvious universal exfil channels (webhooks-as-mail, paste sites,
  transactional-email HTTPS APIs); SNI-level filtering of arbitrary
  HTTPS destinations is a future layer.
- Host-side mail policy bypass via mechanisms outside the sandbox's
  control (a privileged user on the host with mail-spool access).
  Negotiate host-side mail policy with your site's operations team
  as the Layer 3 complement.

## Modes

`NETWORK_FILTER_MODE` (default: `filtered`):

| Mode | Mechanism | Network reach |
| --- | --- | --- |
| `open` | share the host network namespace; no isolation | full host network (legacy behaviour) |
| `filtered` | new netns (Linux network namespace — a per-process isolated network stack) + helper (pasta or slirp4netns); apply default-deny floor + user/admin blocklist | general outbound TCP/UDP/DNS minus the threat ports |
| `isolated` | new netns with no network at all | none (DNS / pip / git break) |

**Default state (v1.1).** When `pasta` is available on the host,
`NETWORK_FILTER_MODE=filtered` delivers port-level outbound
enforcement: pasta provisions a netns with a tap interface
forwarding to the host network and a private (empty) loopback, and
the bwrap workload runs inside that netns. The port-level blocklist
is enforced at pasta's own outbound boundary via `-T ~N` (TCP) and
`-U ~K` (UDP) exclusion flags generated from
`effective_network_blocklist`. **No nftables / iptables dependency.**

| `NETWORK_FILTER_MODE` | What happens (v1.1) |
| --- | --- |
| `open` | shares host network (legacy behaviour; layer disabled) |
| `filtered` | bwrap inside a pasta netns with `-T/-U` port exclusions enforcing the universal port floor (SMTP submission 24/25/465/587/2525, DoT 853, telnet/finger/rsh/rexec/rsyslog) plus any operator-added bare-port or universal-CIDR-port entries. Falls back per `NETWORK_FILTER_FALLBACK` when pasta is unavailable. |
| `isolated` | full network kill via `bwrap --unshare-net` / `firejail --net=none` |

agent-sandbox ships a verified static `pasta` binary at
`tools/pasta/<arch>/pasta` (x86_64 in v1.1); on Linux hosts this is
the only runtime requirement for `filtered` mode. See "Helper
sourcing" below for the full probe order and alternative install
paths.

**Upgrade from v1.0 (enforcement flip).** v1.0 shipped the
configuration surface + fallback machinery and gated the
helper-probe behind `NETWORK_FILTER_ENABLE_HELPER_PROBE=1` — its
default `filtered + stricter` fell back silently to `isolated`,
so the layer was inert in practice. v1.1 ungates the probe.
Deployments running the v1.0 defaults will START enforcing real
`filtered` mode the moment v1.1 lands on a host with `pasta`
available (and agent-sandbox ships pasta in-tree, so the
"available" condition is almost always met).

If your CI / test harness depended on the v1.0 silent-isolated
fallback (e.g., needed an outbound port the default blocklist
closes), either add `NETWORK_BLOCKLIST_EXCEPT+=(<port>)` for the
specific port or pin `NETWORK_FILTER_MODE=open` for those runs.

**Enforcement scope — what pasta `-T/-U` covers, and what it
doesn't.** pasta's port-exclusion syntax filters by destination
port at the netns boundary. It does NOT inspect destination
hostnames or CIDRs at this layer (that's L4-and-up, requiring SNI
inspection or a transparent proxy).

What v1.1 enforces:
- Universal bare-port closures: `25`, `465`, `587`, `2525` (SMTP
  submission class), `853` (DoT), `23`/`79`/`113`/`512`/`513`/`514`
  (telnet/finger/ident/rexec/rlogin/rsh).
- Loopback host:port entries: `127.0.0.1:25` etc. — already
  structurally unreachable because pasta gives the netns its own
  empty loopback, *and* the universal port closure double-covers.
- Universal `0.0.0.0/0:N` entries — same port-level outcome.
- Bare-port `NETWORK_BLOCKLIST_EXCEPT` carve-outs lift the
  corresponding port closure.

What v1.1 does NOT enforce (skipped silently; emit notes only when
`NETWORK_FILTER_VERBOSE=1`):
- Hostname entries (`api.mailgun.net`, `hooks.slack.com`, etc.) —
  port-level layer can't resolve hostnames-to-IPs at runtime, and
  even if it did the IPs rotate.
- Wildcard hostnames (`*.cloudflare-dns.com`) — needs SNI
  inspection.
- The `*` deny-all pattern — would break DNS resolution through
  pasta's proxy; operators wanting deny-all should pin
  `NETWORK_FILTER_MODE=isolated` directly.
- Site CIDR with non-universal port (e.g. `10.0.0.0/8:443`) —
  enforced as universal-port closure (port-only); the
  CIDR-specificity is dropped.

The identity-hijack threat that motivated this feature (local-MTA
abuse via SMTP submission) is fully closed by the universal
port-class closure. The hostname-level entries in the default
blocklist are tracked for v1.2 L7-proxy work (SNI-aware filtering;
R3 in survey, deferred — see settylab/dotto-nexus#117).

## Fallback policies

`NETWORK_FILTER_FALLBACK` (default: `stricter`):

| Policy | If requested mode is unavailable on the backend |
| --- | --- |
| `strict` | Sandbox refuses to launch. Loud error with fix-paths. |
| `stricter` | Fall back ONLY to a STRICTER (more restrictive) mode. Loud warning. If no stricter mode is possible (e.g. landlock has no netns), the sandbox refuses to launch with an explicit fix-path enumeration. |
| `open` | Fall back ONLY to a LESS restrictive mode (loud warning). NEVER falls to a stricter mode than requested — the policy name reflects user intent ("OK to weaken, but don't strengthen against my wishes"). Probe order: most-strict-of-the-less-strict first (e.g. `isolated` requested → try `filtered` before `open`). |

Per-backend support, v1.1:

| Backend | `open` | `filtered` | `isolated` |
| --- | --- | --- | --- |
| **bwrap** | ✓ | ✓ when `pasta` is available (shipped in-tree at `tools/pasta/<arch>/pasta`, or via distro `passt` package); otherwise falls back per policy | ✓ (`--unshare-net`) |
| **firejail** | ✓ | ✗ (needs a site-provisioned bridge via `--net=<iface>` + `--netfilter`; v1.1 does not auto-provision the bridge — use bwrap or accept the fallback) | ✓ (`--net=none`) |
| **landlock** | ✓ | ✗ (no mount/network namespace) | ✗ (no network namespace) |

### Fallback decision matrix

| Requested | Backend supports it? | Policy `strict` | Policy `stricter` | Policy `open` |
| --- | --- | --- | --- | --- |
| `filtered` | yes | filtered | filtered | filtered |
| `filtered` | no (bwrap/firejail; no helper) | **FAIL** | isolated (loud warning) | open (loud warning) |
| `filtered` | no (landlock; no netns) | **FAIL** | **FAIL** (no stricter mode possible) | open (loud warning) |
| `isolated` | yes | isolated | isolated | isolated |
| `isolated` | no (landlock; no netns) | **FAIL** | **FAIL** (no stricter mode possible) | open (loud warning; only available less-strict mode on landlock) |
| `isolated` | no (bwrap, helper present) | **FAIL** | **FAIL** | filtered (loud warning; the most-strict less-strict option available) |
| `open` | (always) | open | open | open |

Note for the `open` policy row: `open` never falls to a stricter
mode than requested. If you want `filtered` but want to accept
`isolated` as a fallback when no helper is available, use
`stricter` (not `open`).

## Configuration

```bash
# sandbox.conf
NETWORK_FILTER_MODE="filtered"
NETWORK_FILTER_FALLBACK="stricter"

NETWORK_BLOCKLIST=(
    "*.untrusted-vendor.com"   # wildcard host block
    "10.0.0.0/8:25"            # site-specific CIDR + port
    # … see sandbox.conf for additional examples
)

NETWORK_BLOCKLIST_EXCEPT=(
    "mybucket.s3.amazonaws.com"  # carve out a specific bucket
    # … see "Precedence model" below
)
```

### Pattern syntax for `NETWORK_BLOCKLIST` and `NETWORK_BLOCKLIST_EXCEPT`

| Pattern | Meaning |
| --- | --- |
| `"host"` | block all ports on this hostname/IP |
| `"host:port"` | block specific port |
| `"CIDR"` | block all ports on this CIDR range |
| `"CIDR:port"` | block specific port on this range |
| `"port"` (numeric) | block this port outbound on every destination |
| `"[ipv6]:port"` | IPv6 form |
| `"*.suffix"` | bash-glob wildcard on the host part (matches any subdomain prefix) |
| `"*"` | matches every destination (deny-all base for the implicit-allowlist idiom) |

The runtime applies the union of:

1. `_NETWORK_BLOCKLIST_DEFAULTS` (built-in floor in `sandbox-lib.sh`;
   always enforced) — covers the identity-bound exfil + lateral-
   movement surface enumerated in "Default blocklist".
2. Admin baseline `NETWORK_BLOCKLIST` (set in `sandbox-admin.conf`;
   user cannot remove).
3. User `NETWORK_BLOCKLIST` extensions (additive only).
4. Exception list `NETWORK_BLOCKLIST_EXCEPT` (admin + user merged;
   user entries covered by admin BLOCKLIST are stripped at config-
   load — see "Precedence model" below).

Inspect the effective lists at runtime:

```bash
# From a test harness or sandbox-aware tool
source sandbox-lib.sh
effective_network_blocklist       # block entries (floor + admin + user)
effective_network_exception_list  # allowed exceptions (admin + user, post-strip)
```

## Precedence model

Policy resolution under v1.1 enforcement (bwrap + pasta + nft):

**Specificity (most → least specific):**

1. exact `host:port`
2. exact `host` (no port)
3. CIDR with smaller prefix (e.g. `/32` highest)
4. CIDR with larger prefix (e.g. `/0` lowest)
5. wildcard host pattern (`*.example.com`)
6. wildcard `*`
7. bare `port`

**Decision rules:**

- The most-specific matching rule wins.
- Among same-specificity rules, `NETWORK_BLOCKLIST` wins over
  `NETWORK_BLOCKLIST_EXCEPT` (safer default).
- Admin-set rules win over user-set rules at every specificity level.

**Worked examples:**

| Blocklist | Except list | Connection | Outcome |
| --- | --- | --- | --- |
| `*.example.com` | — | `api.example.com` | block (wildcard match) |
| `*.example.com` | `api.example.com` | `api.example.com` | **allow** (exception more specific) |
| `*.example.com` | `api.example.com` | `foo.example.com` | block (no matching exception) |
| `*.amazonaws.com` | `s3.amazonaws.com` | `s3.amazonaws.com` | allow |
| `*` | `github.com`, `api.openai.com` | `github.com` | allow (implicit-allowlist idiom) |
| `*` | `github.com`, `api.openai.com` | `pastebin.com` | block (no exception) |

### Admin precedence

A `NETWORK_BLOCKLIST` entry set in `sandbox-admin.conf` cannot be
carved out by a user `NETWORK_BLOCKLIST_EXCEPT`. The check runs at
config-load time under bash-glob semantics:

```bash
# admin sandbox-admin.conf
NETWORK_BLOCKLIST+=("*.example.com")

# user sandbox.conf
NETWORK_BLOCKLIST_EXCEPT+=("api.example.com")   # stripped at load!
```

The user's `api.example.com` exception is removed and a warning is
emitted:

```
WARNING: User config attempted to except 'api.example.com' but
admin NETWORK_BLOCKLIST has '*.example.com' which covers it —
exception stripped (admin policy is absolute).
```

Admins can carve their own exceptions in their own
`NETWORK_BLOCKLIST_EXCEPT` (admin policy is the floor for both
arrays).

### Implicit-allowlist idiom (`*` + exact hosts)

For deployments that want deny-by-default semantics, the canonical
pattern is:

```bash
NETWORK_BLOCKLIST+=("*")
NETWORK_BLOCKLIST_EXCEPT+=(
    "github.com" "api.github.com"
    "api.anthropic.com" "api.openai.com"
    "pypi.org" "files.pythonhosted.org"
    "conda.anaconda.org"
    # … your minimal essential set
)
```

The `*` rule has the lowest specificity, so any exact-host exception
overrides it. Future-deferred: a curated default-allowlist preset
(survey reference R3) would package this pattern with sensible
defaults; the user direction in
[settylab/dotto-nexus#117](https://github.com/settylab/dotto-nexus/issues/117#issuecomment-4435142136)
deferred R3 in favour of the blocklist-not-allowlist model — the
idiom above remains available for power users who want the inverse
shape.

## Resolver pinning — is it needed?

Empirically verified on a representative HPC node (`gizmok87`,
Ubuntu 18.04, kernel 5.4):

```
$ stat -c '%a %F %N' /etc/resolv.conf
777 symbolic link '/etc/resolv.conf' -> '../run/systemd/resolve/stub-resolv.conf'
$ ls -lL /etc/resolv.conf
-rw-r--r-- 1 nobody 732 May 12 14:54 /etc/resolv.conf
$ [[ -w /etc/resolv.conf ]] && echo writable || echo RO
RO
```

`/etc/resolv.conf` is RO to unprivileged users on the host, and
inside the sandbox `/etc` is bind-mounted read-only via
`READONLY_MOUNTS`. The same is true for `/etc/hosts` (644 root-owned)
and `/etc/nsswitch.conf` (660 root-owned). **No resolver-rewrite
step is needed**; the existing read-only bind-mount of `/etc`
already pins these files inside the sandbox.

The resolver-evasion surface that actually matters for the threat
model is **application-level**: Python `dnspython`, Go's
`net.Resolver`, Rust's `hickory-dns`, and similar libraries can open
their own TCP/UDP sockets to a DoH/DoT endpoint, bypassing
`/etc/resolv.conf` entirely. The network-filter floor blocks this
class:

- DoH hostnames (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`,
  `mozilla.cloudflare-dns.com`) — closes the HTTPS-tunnelled lookup.
- DoT port 853 (universal port block) — closes the TLS-wrapped
  lookup.

Other resolver-mutation surfaces, evaluated:

| Surface | Matters? | Why |
| --- | --- | --- |
| `/etc/resolv.conf` rewrite | no | RO via `READONLY_MOUNTS` on `/etc` |
| `/etc/hosts` mutation | no | same RO bind-mount |
| `/etc/nsswitch.conf` re-order | no | same RO bind-mount |
| `LD_PRELOAD` intercepting `getaddrinfo` | no | the attacker isn't using the system resolver; they'd skip the libc path entirely |
| `RES_OPTIONS` env var | no | glibc-resolver only; attacker routes around |
| Application DoH/DoT clients | **yes** | covered by the DoH-hostname + DoT-port block in the floor |

So the practical defense is the network-layer block of the DoH
hostnames + DoT port (already in the floor), not an in-sandbox
resolver pin.

## Helper sourcing (pasta — no nft)

`filtered` mode on bwrap needs only one helper:

- **`pasta`** — userspace TCP/IP stack from the
  [passt](https://passt.top/) project (BSD-3-Clause arm of the dual
  license). Provisions a tap interface inside the sandbox's netns
  and forwards general outbound traffic to the host's network. Also
  proxies DNS to the host resolver by default (so `getent` / `pip` /
  `git clone` keep working) and gives the netns its own empty
  loopback (so any host MTA on `127.0.0.1` is structurally
  unreachable). The blocklist is enforced at pasta's own outbound
  forwarding boundary via the `-T ~N` (TCP) and `-U ~K` (UDP)
  exclusion flags — no `iptables` / `nft` dependency.

agent-sandbox auto-detects `pasta` at session-start. Probe order:

1. **`command -v pasta`** — distro / Homebrew install. Takes
   precedence; typically newer than the in-tree pin.
   - `apt install passt` (Ubuntu 22.10+, Debian Bookworm+)
   - `dnf install passt` (Fedora 36+, RHEL 9+)
   - `brew install passt` (Linux Homebrew)
2. **`tools/pasta/<arch>/pasta`** — the static binary shipped with
   agent-sandbox (x86_64 in v1.1). SHA256-pinned; license + provenance
   in `tools/pasta/<arch>/NOTICE`. Refresh with
   `./tools/pasta/fetch.sh`; source-build via
   `PASTA_BUILD_FROM_SOURCE=1 ./tools/pasta/fetch.sh` for sites with
   binary-redistribution policy constraints.
3. **lmod (site-specific)** — when the site provides a `passt`
   module, `SANDBOX_MODULES+=("passt/<version>")` puts it on PATH.
   Fred Hutch SciComp tracks a `passt` module request at
   [FredHutch/easybuild-life-sciences#578](https://github.com/FredHutch/easybuild-life-sciences/issues/578)
   (eventual upgrade path; until then the shipped binary covers FH).
4. **`command -v slirp4netns`** — older, slower fallback. v1.1
   reserves slirp4netns support and currently downgrades to isolated
   mode with a warning when only slirp4netns is present.

If pasta is missing, the resolver falls back per
`NETWORK_FILTER_FALLBACK` (default `stricter` → `isolated`; loud
warning naming the gap).

### Helper validation: the forwarding probe

Pasta-binary presence is necessary but not sufficient. On kernels
that still gate `SO_BINDTODEVICE` behind `CAP_NET_RAW` (most kernels
< 5.7, or any host without the 2020 relaxation backported), an
unprivileged pasta starts but logs

```
SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-T auto'
SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-U auto'
```

and silently restricts forwarding to loopback. The sandbox would
launch with the documented pasta argv, and the agent would lose
outbound on every port — including ports the blocklist did not
exclude. Both the threat-model intent (close mail-relay / webhook /
paste / DoH / legacy-r-services) and the operator's reach
expectation collapse.

To close that gap, `_pasta_can_forward_outbound` runs
`pasta --foreground --quiet -- true` after resolving the binary,
inspects stderr for the `forwarding only 127.0.0.1` banner, and on
match flips `_NETWORK_HELPER_PROBE_RESULT="degraded"`. The resolver
treats degraded helpers identically to missing helpers — `filtered`
is not in the supported-modes set; fallback proceeds per
`NETWORK_FILTER_FALLBACK`. The fallback warning quotes the specific
degradation reason rather than the generic "pasta not found" line so
the operator knows the path forward:

1. **`setcap cap_net_raw+ep <pasta>`** on a system-wide pasta binary
   (admin/root needed; cleanest fix; survives upgrades until the
   pasta package version changes).
2. **Upgrade to kernel ≥ 5.7** with the SO_BINDTODEVICE relaxation.
3. **Pin `NETWORK_FILTER_MODE=open` or `isolated`** to make the
   reach trade-off explicit.

#### Probe escape hatch — `NETWORK_FILTER_SKIP_HELPER_PROBE=1`

Operators who have verified their pasta's host-side forwarding works
(e.g. ran the `setcap` step above) can set
`NETWORK_FILTER_SKIP_HELPER_PROBE=1` to skip the ~50ms probe per
sandbox start. **Do not set it as a workaround for the degradation
warning** — setting it on a host where pasta actually degrades
re-introduces the silent-loopback-only failure mode that the probe
exists to catch.

## Real-world recipe — verify filtered mode is enforcing

After deploying v1.1, an operator can confirm `filtered` mode is
actually enforcing inside their sandbox with a handful of one-liners.
Run each inside a sandbox session:

```bash
# (1) DNS + general egress: should resolve + reach github.com.
getent hosts github.com && \
    curl -fsS --max-time 5 -o /dev/null -w '%{http_code}\n' https://github.com/
# Expected: A/AAAA record + "200" or "301".

# (2) SMTP submission: must fail. The universal port-25 closure plus
# pasta's empty loopback both block the path.
exec 3<>/dev/tcp/127.0.0.1/25 2>&1 || echo "BLOCKED — SMTP closed (expected)"
# Expected: "BLOCKED" (Connection refused / ENETUNREACH).

# (3) DoT (DNS-over-TLS) evasion port: must fail. Universal port-853
# closure.
exec 3<>/dev/tcp/1.1.1.1/853 2>&1 || echo "BLOCKED — DoT closed (expected)"
# Expected: "BLOCKED".

# (4) Telnet (legacy r-services): must fail. Port 23 closure.
exec 3<>/dev/tcp/127.0.0.1/23 2>&1 || echo "BLOCKED — telnet closed (expected)"
# Expected: "BLOCKED".
```

Note that v1.1 enforces *port-level* blocks at pasta's boundary,
not hostname-level blocks. A request like
`curl https://hooks.slack.com/` (a hostname entry in the default
blocklist) will **not** fail in v1.1 — hostname-level filtering is
v1.2 L7-proxy scope. Plan defense-in-depth accordingly: the
universal port-class closure shuts the identity-hijack threat (the
motivating concern); hostname surfaces are best handled at the
egress proxy or DNS layer.

If (1) fails: pasta is not on PATH and the in-tree binary is
missing or not executable. Re-run with `NETWORK_FILTER_VERBOSE=1`
to surface the helper-probe trail.

If (2)/(3)/(4) succeed: `filtered` did not resolve. Check the
startup output for the fallback-warning (most likely `filtered →
isolated` because pasta is missing, or `filtered → open` under a
`NETWORK_FILTER_FALLBACK=open` policy).

## Troubleshooting

### "filtered fell back to isolated" on startup (v1.1)

`filtered` requires `pasta` AND a working `SO_BINDTODEVICE`. Common
causes (the fallback warning quotes the specific reason):

- `pasta` not detected: agent-sandbox ships `tools/pasta/<arch>/pasta`
  by default. If you removed it (or are on an unsupported arch like
  aarch64 in v1.1), install via distro package (`apt install passt` /
  `dnf install passt` / `brew install passt`) or run
  `tools/pasta/fetch.sh` to refresh. `make install` lays the shipped
  binary down at `<prefix>/lib/agent-sandbox/tools/pasta/<arch>/pasta`
  automatically; if you installed via `make install` and the binary
  is missing there, re-run `make install`.
- Custom `PATH`: the probe uses `command -v pasta` first; if your
  shell prunes `PATH` aggressively, ensure `/usr/bin` (or wherever
  your distro ships `pasta`) is reachable, or rely on the shipped
  in-tree binary which is path-independent.
- **`pasta` present but degraded to loopback-only** (kernel < 5.7 /
  unprivileged userns / no `CAP_NET_RAW`). The fallback warning will
  quote `pasta started but degraded to loopback-only forwarding`.
  See "Helper validation: the forwarding probe" above for the
  three workarounds; the operationally cleanest is an admin running
  `setcap cap_net_raw+ep` on a system-wide pasta binary.

Fallback alternatives, all valid:

- Accept `isolated` mode (no network at all): pin
  `NETWORK_FILTER_MODE=isolated` — the fallback is silent and
  intentional, and the identity-hijack threat is still closed.
- Accept `open` mode (no isolation): pin `NETWORK_FILTER_MODE=open`.
  **Re-opens the threat.** Use only when host-side mail policy is
  already locked down at the MTA layer.

### "no stricter mode available" failure on landlock

Landlock has neither a mount namespace nor a network namespace, so it
cannot deliver `filtered` or `isolated`. Choices:

- Switch to a bwrap or firejail backend (`SANDBOX_BACKEND=bwrap`).
- Pin `NETWORK_FILTER_MODE=open` on landlock-only hosts.
- Set `NETWORK_FILTER_FALLBACK=open` to accept the silent degrade.

### `sandbox-notify` carve-out

`bin/sandbox-notify` uses `/dev/tty` + tmux IPC (`tmux new-window`)
and does NOT speak SMTP or any other network protocol. It continues
to function in all three modes including `isolated`. No carve-out
required at the configuration level.

### Pre-existing tests fail with "ENETUNREACH" or per-port blocks

In v1.1, when `pasta` is present on the runner,
`NETWORK_FILTER_MODE=filtered` (default) enforces the universal
port floor — ports 24/25/465/587/2525 (SMTP submission class), 853
(DoT), 23/79/113/512/513/514 (legacy r-services). CI / local test
runs that need ports the default blocklist closes can either:

- Pin `NETWORK_FILTER_MODE=open` for the duration of the test (often
  the right call for CI runners on isolated infrastructure).
- Add `NETWORK_BLOCKLIST_EXCEPT+=(<port>)` for the specific bare
  port the test legitimately needs (host:port exceptions are not
  carved at the pasta layer — port-level enforcement is universal).
- Pin `NETWORK_FILTER_MODE=isolated` for tests that explicitly
  exercise the no-network path.

The test suite already gates its network-dependent sections on the
resolved mode (see `test.sh` section 11.4 "Network filter").

## Admin enforcement (sandbox-admin.conf)

```bash
# /etc/agent-sandbox/sandbox-admin.conf
NETWORK_FILTER_MODE="filtered"
NETWORK_FILTER_FALLBACK="strict"      # admins typically pin strict
NETWORK_BLOCKLIST=(
    "hooks.slack.com"
    "api.mailgun.net"
    # … site-specific must-blocks
)
```

User config can only request:

- A mode `>=` the admin pin in the strictness ordering
  (`open` < `filtered` < `isolated`).
- A fallback policy `>=` the admin pin
  (`open` < `stricter` < `strict`).
- A `NETWORK_BLOCKLIST` that is a superset of the admin's (entries
  the admin set cannot be removed).

Violations are restored at config-load time with a warning naming the
offending entry.

## See also

- [Security model](security.md) — overall sandbox threat model and
  layering.
- [Hardening](../admin/hardening.md) — admin's view of the
  defense-in-depth stack.
- [`passt.top`](https://passt.top/) — upstream documentation for
  pasta.
