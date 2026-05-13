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

**Default state (v1.1).** When BOTH a network helper (`pasta`) AND
`nft` (nftables — the Linux kernel packet-filter framework, successor
to iptables) are available on the host, `NETWORK_FILTER_MODE=filtered`
delivers real per-entry enforcement: bwrap unshares the network
namespace into pasta, pasta provisions a tap interface forwarding to
the host network, and an nftables ruleset generated from
`effective_network_blocklist` is installed inside the netns *before*
the workload starts. The default blocklist (50+ entries — see
"Default blocklist" below) is enforced empirically, not just listed
in a policy table.

| `NETWORK_FILTER_MODE` | What happens (v1.1) |
| --- | --- |
| `open` | shares host network (legacy behaviour; layer disabled) |
| `filtered` | bwrap + pasta + nft enforcement when both helpers are present; otherwise falls back per `NETWORK_FILTER_FALLBACK` (default `stricter` → `isolated`; loud warning) |
| `isolated` | full network kill via `bwrap --unshare-net` / `firejail --net=none` |

agent-sandbox ships a verified static `pasta` binary at
`tools/pasta/<arch>/pasta` (x86_64 in v1.1); operators only need to
install `nftables` (`apt install nftables` / `dnf install nftables`)
to flip the default-deny enforcement on. See "Helper sourcing" below
for the full probe order and install paths.

**Upgrade from v1.0 (silent enforcement flip).** v1.0 shipped the
configuration surface + fallback machinery, gated the helper-probe
behind `NETWORK_FILTER_ENABLE_HELPER_PROBE=1`, and defaulted
`filtered + stricter` to fall back to `isolated`. v1.1 removes that
gate. Deployments running the v1.0 defaults will START enforcing
real `filtered` mode the moment v1.1 lands on a host with `pasta` +
`nft` available — no config change is required. If your CI / test
harness depended on the v1.0 silent-isolated fallback (e.g., used
`getent` against external resolvers), you may need to add the
relevant hostnames to `NETWORK_BLOCKLIST_EXCEPT` or pin
`NETWORK_FILTER_MODE=open` for those runs.

**Enforcement limits (acknowledged v1.2 scope).** nftables cannot
inspect SNI on TLS-wrapped traffic. Wildcard hostnames
(`*.cloudflare-dns.com`) and the deny-all `*` pattern are therefore
not enforceable at the netfilter layer; the generator emits a
stderr note and skips them. Bare-port entries (`853` blocks DoT;
`25`/`465`/`587` block SMTP submission) remain fully enforced and
close the most common evasion paths. Hostname entries are resolved
to IPs at session-start and the resulting IPs are blocked — this is
best-effort and may drift if upstream DNS changes mid-session. The
v1.2 scope (R3 in survey, deferred — see the issue thread) covers a
small L7 proxy for SNI-aware filtering of the wildcard surface.

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
| **bwrap** | ✓ | ✓ when `pasta` AND `nft` both available; otherwise falls back per policy | ✓ (`--unshare-net`) |
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

## Helper sourcing (pasta + nft)

`filtered` mode on bwrap needs two helpers on the host:

- **`pasta`** — userspace TCP/IP stack from the
  [passt](https://passt.top/) project (BSD-3-Clause arm of the dual
  license). Provisions a tap interface inside the sandbox's netns
  and forwards general outbound traffic to the host's network. Also
  proxies DNS to the host resolver by default, so `getent` / `pip` /
  `git clone` keep working through pasta.
- **`nft`** — the nftables CLI. Installs the per-entry blocklist
  ruleset inside the netns before the workload starts.

agent-sandbox auto-detects both at session-start. The helper-probe
order for `pasta`:

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

For `nft`: `apt install nftables` (Ubuntu/Debian), `dnf install nftables`
(RHEL/Fedora). macOS has no native nftables — `filtered` mode is
Linux-only.

If either helper is missing, the resolver falls back per
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
# Expected: A/AAAA record + "200" or "301"

# (2) SMTP submission: must fail. The local MTA is unreachable.
exec 3<>/dev/tcp/127.0.0.1/25 2>&1 || echo "BLOCKED — SMTP closed (expected)"
# Expected: "BLOCKED" (Connection refused / ENETUNREACH).

# (3) DoH evasion port: must fail. Universal port-853 (DoT) drop.
exec 3<>/dev/tcp/1.1.1.1/853 2>&1 || echo "BLOCKED — DoT closed (expected)"
# Expected: "BLOCKED".

# (4) Webhook surface (universal): must fail. The transactional-mail
# floor blocks the hostname at session-start by IP-resolution.
curl -fsS --max-time 3 https://hooks.slack.com/ 2>&1 || echo "BLOCKED — webhook closed (expected)"
# Expected: "BLOCKED" or curl exit-code 28 (timeout) / 7 (no route).
```

If (1) fails: pasta DNS proxy not working — confirm `pasta` is
running (check the parent process tree).

If (2)/(3)/(4) succeed: the nft ruleset isn't loading. Re-run with
`SANDBOX_DEBUG=1` to surface the generated ruleset + nft stderr.

## Troubleshooting

### "filtered fell back to isolated" on startup (v1.1)

`filtered` requires BOTH `pasta` AND `nft`. Common causes:

- `nftables` not installed: `apt install nftables` /
  `dnf install nftables`. The package is small and dependency-free.
- `pasta` not detected: agent-sandbox ships `tools/pasta/<arch>/pasta`
  by default. If you removed it (or are on an unsupported arch like
  aarch64 in v1.1), install via distro package (`apt install passt`)
  or run `tools/pasta/fetch.sh` to refresh.
- Custom `PATH`: the probe uses `command -v` for both helpers; if
  your shell prunes `PATH` aggressively, ensure `/usr/sbin` (where
  `nft` typically lives) is reachable.

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

In v1.1, when `pasta` + `nft` are present on the runner,
`NETWORK_FILTER_MODE=filtered` (default) enforces the full default
blocklist — including ports 25/465/587 (SMTP), 853 (DoT), 23/514
(telnet/rsh), the configured CIDR/host floor, and several DoH
hostnames resolved to current IPs. CI / local test runs that need
ports the default blocklist closes can either:

- Pin `NETWORK_FILTER_MODE=open` for the duration of the test (often
  the right call for CI runners on isolated infrastructure).
- Add `NETWORK_BLOCKLIST_EXCEPT+=(...)` entries for specific hosts /
  ports the test legitimately needs.
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
