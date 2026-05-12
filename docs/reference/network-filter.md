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

**v1.0 implementation status.** The configuration surface, mode
resolution, and fallback machinery ship in v1.0. The bwrap +
pasta + `nft` (nftables — the Linux kernel packet-filter framework,
successor to iptables) chain that delivers a real `filtered` mode is
reserved for v1.1 — the helper-detection function in `sandbox-lib.sh`
(`_resolve_network_helper`) is gated by `NETWORK_FILTER_ENABLE_HELPER_PROBE=1`
and returns "no helper" by default in v1.0. The practical effect
on v1.0 deployments:

- `NETWORK_FILTER_MODE=open` — unchanged.
- `NETWORK_FILTER_MODE=filtered` — falls back to `isolated` per the
  default `stricter` policy. Loud startup warning names every fix
  path.
- `NETWORK_FILTER_MODE=isolated` — works as documented; full
  network kill via `bwrap --unshare-net` / `firejail --net=none`.

When v1.1 ships the integration, deployments running with `filtered +
stricter` will silently start using real filtered mode the moment
the helper is on PATH (or `tools/pasta/pasta` is installed via
`tools/pasta/fetch.sh`). No config change is required to flip over.

The default blocklist already enumerates the full identity-bound
exfil surface (mail submission ports, transactional-email HTTPS
APIs, webhook-as-mail surfaces, anonymous file-drop endpoints,
public paste services, DoH resolvers (DoH = DNS-over-HTTPS, which
bypasses standard DNS resolver pinning by tunnelling lookups over
443) — see "Default blocklist" below for the full list with one-line
rationales). Under v1.0 these
entries describe the policy table only — the resolver still computes
them via `effective_network_blocklist`, the test suite asserts they
are present, but the helper that actually enforces them per-entry
is gated until v1.1. The v1.0 `isolated`-fallback path closes the
threat by stricter means (full network kill) rather than per-entry
enforcement.

## Fallback policies

`NETWORK_FILTER_FALLBACK` (default: `stricter`):

| Policy | If requested mode is unavailable on the backend |
| --- | --- |
| `strict` | Sandbox refuses to launch. Loud error with fix-paths. |
| `stricter` | Fall back ONLY to a STRICTER (more restrictive) mode. Loud warning. If no stricter mode is possible (e.g. landlock has no netns), the sandbox refuses to launch with an explicit fix-path enumeration. |
| `open` | Fall back ONLY to a LESS restrictive mode (loud warning). NEVER falls to a stricter mode than requested — the policy name reflects user intent ("OK to weaken, but don't strengthen against my wishes"). Probe order: most-strict-of-the-less-strict first (e.g. `isolated` requested → try `filtered` before `open`). |

Per-backend support, v1.0:

| Backend | `open` | `filtered` | `isolated` |
| --- | --- | --- | --- |
| **bwrap** | ✓ | helper-probe gated (v1.1 ships the integration); v1.0 falls back per policy | ✓ (`--unshare-net`) |
| **firejail** | ✓ | gated for v1.1 (`--netfilter` with generated iptables ruleset) | ✓ (`--net=none`) |
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

Policy resolution under v1.1 enforcement (gated for v1.0; v1.0 ships
the policy table but the per-connection evaluation is the v1.1
helper's job):

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

## Helper binary (pasta)

`pasta` is the userspace TCP/IP stack from the
[passt](https://passt.top/) project (BSD-3-Clause arm of the dual
license). When v1.1 wires the integration, `pasta` provisions a tap
device inside the sandbox's network namespace, forwards general
outbound traffic to the host's network, and pairs with `nft` rules
inside the netns to enforce the blocklist.

Install paths, in order of preference:

1. **System package**: `apt install passt` (Ubuntu 22.10+, Debian
   Bookworm+), `dnf install passt` (Fedora 36+, RHEL 9+),
   `brew install passt`.
2. **Shipped fetch**: `./tools/pasta/fetch.sh` — downloads the pinned
   upstream source tarball, builds a static binary for the host
   architecture, installs at `tools/pasta/pasta`.
3. **lmod (site-specific)**: `SANDBOX_MODULES+=("passt/<version>")`
   when the site provides a module. Sites with an EasyBuild pipeline
   can request the upstream `passt` recipe; the easyconfig is a small
   addition (the binary has no third-party deps).

The helper-detection function probes in PATH-first order:
distro/Homebrew `pasta`, then the shipped binary, then `slirp4netns`
as a fallback (older, slower, GPL-2.0+ source-offer obligation).

## Troubleshooting

### "filtered fell back to isolated" on startup

The most common cause in v1.0: the bwrap+pasta integration is gated.
The fix-path enumeration printed by the sandbox names the choices —
the practical ones are:

- Accept `isolated` mode (no network at all): pin
  `NETWORK_FILTER_MODE=isolated` so the fallback is silent and
  intentional. The threat is still closed.
- Accept `open` mode (no isolation): pin `NETWORK_FILTER_MODE=open`.
  **Re-opens the threat.** Use only when host-side mail policy is
  already locked down.
- Wait for v1.1: the integration will ship without a config change.

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

### Pre-existing tests fail with "ENETUNREACH"

`NETWORK_FILTER_MODE=filtered` (default) falls back to `isolated` in
v1.0, which kills the sandbox's network. CI / local test runs that
expect network access need either `NETWORK_FILTER_MODE=open` for the
duration of the test or a host-side `pasta` install plus the v1.1
integration. The test suite gates its network-dependent sections on
the resolved mode (see `test.sh` section "Network filter").

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
