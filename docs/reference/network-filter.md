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

- **Covert L7 channels over 443 to ANY hostname.** A determined
  agent with `pip install requests` can POST to any HTTPS endpoint;
  the netfilter layer can't inspect TLS SNI. The threat surface
  this fails to cover (webhook-as-mail, transactional-email HTTPS
  APIs, paste sites, DoH resolvers, …) is real, NOT addressed by
  v1.1, and properly closed by a managed egress proxy. See
  ["Known limitations"](#known-limitations) below.
- Host-side mail policy bypass via mechanisms outside the sandbox's
  control (a privileged user on the host with mail-spool access).
  Negotiate host-side mail policy with your site's operations team
  as the Layer 3 complement.

## Modes

`NETWORK_FILTER_MODE` (default: `filtered`). The knob's full
grammar and admin-pin behaviour live in
[configure.md → NETWORK_FILTER_MODE](../configure.md#network_filter_mode);
the table below names what each mode does at the runtime layer:

| Mode | Mechanism | Network reach |
| --- | --- | --- |
| `open` | share the host network namespace; no isolation | full host network (legacy behaviour) |
| `filtered` | new netns (Linux network namespace — a per-process isolated network stack) + pasta tap forwarding + DNS proxy; pasta enforces the universal port floor at its `-T ~N` outbound boundary | general outbound TCP/UDP/DNS minus the blocked ports |
| `isolated` | new netns with no network at all | none (DNS / pip / git break) |

**Default state.** When `pasta` is available on the host,
`NETWORK_FILTER_MODE=filtered` enforces the universal port floor
shipped in `sandbox-lib.sh::_NETWORK_BLOCKLIST_DEFAULTS`: SMTP
submission (24/25/465/587/2525), DoT (853), legacy r-services
(23/79/113/512/513/514). The floor lives in the lib (not the user's
`sandbox.conf`) so an operator upgrading from v1.0 still gets
enforcement on the first session after install — `install.sh`
intentionally does not overwrite a user's existing `sandbox.conf`.
Operator-added bare-port entries in `NETWORK_BLOCKLIST` extend the
floor; bare-port entries in `NETWORK_BLOCKLIST_EXCEPT` lift it.
**No nftables / iptables runtime dependency.**

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

The configuration knobs (`NETWORK_FILTER_MODE`,
`NETWORK_FILTER_FALLBACK`, `NETWORK_BLOCKLIST`,
`NETWORK_BLOCKLIST_EXCEPT`, `NETWORK_FILTER_VERBOSE`) live in the
canonical [config doc](../configure.md#network-filter) alongside
every other sandbox knob — defaults, types, admin-pin behaviour,
pattern grammar, and the precedence model.

This reference doc covers the **implementation**: what the layer
actually does at runtime, what it can and can't enforce, and how
to handle the gaps.

## Known limitations

The v1.1 enforcement layer (pasta `-T/-U` port exclusions) operates
at L3/L4: IP, CIDR, port. It is intentionally a SIMPLE layer with
no userspace stateful inspection, so its limits are sharp and worth
naming up front.

### Hostname-level filtering is not provided

TLS-wrapped traffic (HTTPS on 443, anything else over TLS) carries
the destination hostname only inside the encrypted **SNI** (Server
Name Indication, the TLS handshake field naming the remote host)
handshake. pasta's port-exclusion layer sees the destination IP
and port, never the hostname. Consequences for the threat model:

- **Transactional-email APIs** (Mailgun, SendGrid, Postmark, Resend,
  Amazon SES) — all reached over 443. Cannot be blocked by name.
- **Webhook surfaces** (Slack `hooks.slack.com`, Discord webhooks,
  Teams `*.webhook.office.com`, webhook.site, requestbin) — same.
- **Anonymous file-drop / paste endpoints** (transfer.sh, file.io,
  0x0.st, pastebin.com, …) — same.
- **DoH (DNS-over-HTTPS) resolver hostnames** (`cloudflare-dns.com`,
  `dns.google`, …) — DoH-over-443 cannot be filtered. The DoT
  channel (port 853) IS blocked via the universal port closure.

Earlier drafts of the default blocklist listed all of these as
hostname entries. v1.1 removed them: listing unenforceable entries
created a credibility gap between the documented policy and the
runtime enforcement. The threat is still real; the honest place to
close it is one layer up.

### Mitigation — managed egress proxy with SNI allowlist

The right mechanism for hostname-level egress control is a small
**managed proxy** running inside the sandbox's netns:

- Sandbox sets `HTTPS_PROXY` / `HTTP_PROXY` environment variables
  inside the netns so HTTPS clients (curl, requests, git over
  HTTPS, …) tunnel through the proxy.
- Proxy reads the TLS SNI from the client hello, checks it against
  an allowlist, and either splices the connection through to the
  host network or returns `HTTP 403 Forbidden` before any bytes
  leave the netns.
- For HTTP/2 / HTTP/3 clients that ignore proxy env vars, the
  proxy can additionally bind a transparent-proxy port (TCP 443)
  via pasta's port-forwarding so the egress path becomes
  unavoidable.

Prior art (worth copying):

- **Anthropic's `sandbox-runtime`** ships a small managed proxy
  enforcing exactly this pattern (SNI allowlist, deny-by-default).
- **OpenAI's Codex CLI** sandboxes its agents behind a managed
  proxy with similar shape.
- **`squid`** with `ssl_bump` + `acl` rules implements a
  production-grade version (heavier; needs a CA injected into the
  netns trust store for full MITM, or splice-only SNI inspection
  without MITM).
- **`tinyproxy` + `Filter` directive** — the minimum-viable form;
  HTTP-only without SNI inspection. Useful as a learning step but
  doesn't reach the threat surface here (HTTP is the easy case).

**Status in agent-sandbox** — not shipped in v1.1. Two paths
forward, in rough order of likely user preference:

1. **Document running an external proxy** (squid or similar) and
   provide a `sandbox.conf` snippet wiring `HTTPS_PROXY` +
   `EXTRA_WRITABLE_PATHS` for the proxy's runtime state. Smallest
   surface area for agent-sandbox to maintain.
2. **Ship a small in-tree SNI proxy** (similar pattern to pasta —
   single static binary, BSD-or-equivalent license, in-tree under
   `tools/`). Bigger lift; gives operators a one-knob default-deny
   hostname-allowlist mode.

Either path is tracked as v1.2 scope and explicitly named in
[settylab/dotto-nexus#117](https://github.com/settylab/dotto-nexus/issues/117).

### Deny-all `*` would break DNS

The blocklist syntax accepts `"*"` as a deny-all pattern, but at
the pasta-port layer this would block ALL outbound forwarding
including DNS — pasta's host-resolver proxy still goes through the
netns boundary. Operators wanting deny-all should set
`NETWORK_FILTER_MODE=isolated` directly; the runtime emits a
stderr note and skips the `*` entry at the port-exclusion
generator.

### Hostname / wildcard / `*` entries no-op silently

To avoid spamming session startup with notes about unenforceable
entries (a common shape when an operator copies a snippet from
the older docs or another project), the pasta port-exclusion
generator skips hostname/wildcard/`*` entries silently by
default. Set `NETWORK_FILTER_VERBOSE=1` in the calling
environment to surface a per-entry note. See
[`NETWORK_FILTER_VERBOSE`](../configure.md#network_filter_verbose).

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
`/etc/resolv.conf` entirely. The network-filter floor partially
addresses this class:

- **DoT (DNS-over-TLS)** — fixed port 853, universal port block ✓.
- **DoH (DNS-over-HTTPS)** — traffic is TLS-on-443. The destination
  hostname (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`,
  `mozilla.cloudflare-dns.com`, …) is only visible in the SNI.
  At the netfilter layer this **cannot be filtered** — see the
  [managed-proxy mitigation](#mitigation--managed-egress-proxy-with-sni-allowlist)
  for the proper fix.

Other resolver-mutation surfaces, evaluated:

| Surface | Matters? | Why |
| --- | --- | --- |
| `/etc/resolv.conf` rewrite | no | RO via `READONLY_MOUNTS` on `/etc` |
| `/etc/hosts` mutation | no | same RO bind-mount |
| `/etc/nsswitch.conf` re-order | no | same RO bind-mount |
| `LD_PRELOAD` intercepting `getaddrinfo` | no | the attacker isn't using the system resolver; they'd skip the libc path entirely |
| `RES_OPTIONS` env var | no | glibc-resolver only; attacker routes around |
| Application DoT clients | **yes** | covered by the port-853 floor block |
| Application DoH clients | partial | DoT path closed; DoH-over-443 needs the managed-proxy mitigation |

So the practical defense at the netfilter layer is the universal
port-853 (DoT) block; DoH-over-443 requires the managed proxy.

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

Note that v1.1 enforces **port-level** blocks at pasta's boundary,
not hostname-level. A request like `curl https://hooks.slack.com/`
will succeed — pasta's port-exclusion layer cannot see TLS SNI. The default
blocklist no longer includes any hostname entries (they were
removed in v1.1; see [Known limitations](#known-limitations)). The
identity-hijack threat that motivated this layer is closed by the
universal port-class closure (SMTP submission 24/25/465/587/2525);
hostname-level surfaces (webhooks, transactional-email APIs, paste
sites, DoH-over-443) require a [managed egress
proxy](#mitigation--managed-egress-proxy-with-sni-allowlist).

If (1) fails: pasta is not on PATH and the in-tree binary is
missing or not executable. Re-run with `NETWORK_FILTER_VERBOSE=1`
to surface the helper-probe trail.

If (2)/(3)/(4) succeed: `filtered` did not resolve. Check the
startup output for the fallback-warning (most likely `filtered →
isolated` because pasta is missing, or `filtered → open` under a
`NETWORK_FILTER_FALLBACK=open` policy).

## Troubleshooting

### "filtered fell back to isolated" on startup (v1.1)

`filtered` requires `pasta`. Common causes:

- `pasta` not detected: agent-sandbox ships `tools/pasta/<arch>/pasta`
  by default. If you removed it (or are on an unsupported arch like
  aarch64 in v1.1), install via distro package (`apt install passt` /
  `dnf install passt` / `brew install passt`) or run
  `tools/pasta/fetch.sh` to refresh.
- Custom `PATH`: the probe uses `command -v pasta` first; if your
  shell prunes `PATH` aggressively, ensure `/usr/bin` (or wherever
  your distro ships `pasta`) is reachable, or rely on the shipped
  in-tree binary which is path-independent.

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
    # Bare-port closures (universal — recommended shape):
    "445"                       # SMB direct (lateral-movement)
    "3389"                      # RDP
)
```

**Footgun warning.** Do **not** pin `CIDR:port` entries
(e.g. `"10.0.0.0/8:443"`) expecting site-only closure. pasta's
exclusion layer ignores the host/CIDR part and applies the port
universally — `10.0.0.0/8:443` would close port 443 to **every**
destination (breaking `pip`, `git over HTTPS`, github.com, …). The
generator emits an unconditional `WARNING:` for any non-universal
`CIDR:port` entry; treat it as a config error. Use a managed
egress proxy (see [Known limitations](#known-limitations)) for
CIDR-specific port carve-outs.

User config can only request:

- A mode `>=` the admin pin in the strictness ordering
  (`open` < `filtered` < `isolated`).
- A fallback policy `>=` the admin pin
  (`open` < `stricter` < `strict`).
- A `NETWORK_BLOCKLIST` that is a superset of the admin's (entries
  the admin set cannot be removed).

Violations are restored at config-load time with a warning naming the
offending entry. Full configuration grammar (defaults, types,
admin-pin behaviour, pattern table) lives in
[configure.md → Network filter](../configure.md#network-filter).

## See also

- [Security model](security.md) — overall sandbox threat model and
  layering.
- [Hardening](../admin/hardening.md) — admin's view of the
  defense-in-depth stack.
- [`passt.top`](https://passt.top/) — upstream documentation for
  pasta.
