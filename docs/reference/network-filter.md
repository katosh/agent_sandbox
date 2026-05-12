# Network filter

The network filter is an optional layer that restricts the sandboxed
agent's outbound network access. It exists to close one specific
threat: a compromised agent abusing the host's network to spoof mail
under the operator's identity (and adjacent lateral-movement /
exfiltration surface).

## Threat model

On a typical HPC compute node the local MTA (Postfix or
sendmail-compat) listens on `127.0.0.1:25` and accepts unauthenticated
mail submission from any local user, then relays under that user's
`From:` header. The `mynetworks` directive frequently extends that
trust to the whole campus IP range (`140.107.216.0/21` on Fred Hutch
gizmo, for example), so an adversary controlling a sandboxed agent
can spoof the operator's identity in **two** ways:

1. Speak SMTP directly to `127.0.0.1:25` from any TCP-capable
   language (`bash /dev/tcp/127.0.0.1/25`, Python `smtplib`, …).
2. Speak SMTP directly to the campus relay (`mx.fhcrc.org:25`) — the
   relay trusts any IP in `mynetworks`, again unauthenticated.

Both bypass any filesystem-level binary block. The fix is to deny the
TCP path itself at a layer the agent cannot escape.

**Non-goals.** This layer does NOT defend against:

- Covert L7 channels over allowed 443 hostnames (a determined agent
  with `pip install requests` can POST to any HTTPS endpoint the
  allowlist permits — webhooks-as-mail, paste sites, transactional-
  email HTTPS APIs). SNI-level filtering is a future layer.
- Host-side mail policy bypass via mechanisms outside the sandbox's
  control (a privileged user on the host with mail-spool access).
  Negotiate host-side policy with site SciComp as the Layer 3
  complement.

## Modes

`NETWORK_FILTER_MODE` (default: `filtered`):

| Mode | Mechanism | Network reach |
| --- | --- | --- |
| `open` | share the host network namespace; no isolation | full host network (legacy behaviour) |
| `filtered` | new netns + helper (pasta or slirp4netns); apply default-deny floor + user/admin blocklist | general outbound TCP/UDP/DNS minus the threat ports |
| `isolated` | new netns with no network at all | none (DNS / pip / git break) |

**v1.0 implementation status.** The configuration surface, mode
resolution, and fallback machinery ship in v1.0. The bwrap +
pasta + nft chain that delivers a real `filtered` mode is reserved
for v1.1 — the helper-detection function in `sandbox-lib.sh`
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

## Fallback policies

`NETWORK_FILTER_FALLBACK` (default: `stricter`):

| Policy | If requested mode is unavailable on the backend |
| --- | --- |
| `strict` | Sandbox refuses to launch. Loud error with fix-paths. |
| `stricter` | Fall back ONLY to a stricter mode. Loud warning. If no stricter mode is possible (e.g. landlock has no netns), the sandbox refuses to launch with an explicit fix-path enumeration. |
| `open` | Fall back to ANY available mode, preferring stricter first, then less restrictive. Will silently degrade to host network if no isolated mode is available. Loud startup warning on any fallback. |

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
| `filtered` | no (bwrap/firejail; no helper) | **FAIL** | isolated (loud warning) | isolated, then open (loud warning) |
| `filtered` | no (landlock; no netns) | **FAIL** | **FAIL** (no stricter mode possible) | open (loud warning) |
| `isolated` | yes | isolated | isolated | isolated |
| `isolated` | no (landlock) | **FAIL** | **FAIL** (no stricter mode possible) | open (loud warning) |
| `open` | (always) | open | open | open |

## Configuration

```bash
# sandbox.conf
NETWORK_FILTER_MODE="filtered"
NETWORK_FILTER_FALLBACK="stricter"

NETWORK_BLOCKLIST=(
    "hooks.slack.com"          # opt-in extra: webhook-as-mail
    "api.mailgun.net"          # opt-in extra: transactional mail HTTPS API
    "transfer.sh"              # opt-in extra: anonymous file drop
    # … see sandbox.conf for the curated commented-out list
)
```

### Pattern syntax for `NETWORK_BLOCKLIST`

| Pattern | Meaning |
| --- | --- |
| `"host"` | block all ports on this hostname/IP |
| `"host:port"` | block specific port |
| `"CIDR"` | block all ports on this CIDR range |
| `"CIDR:port"` | block specific port on this range |
| `"port"` (numeric) | block this port outbound on every destination |
| `"[ipv6]:port"` | IPv6 form |

The runtime applies the union of:

1. `_NETWORK_BLOCKLIST_DEFAULTS` (built-in floor in `sandbox-lib.sh`;
   always enforced) — covers mail-submission ports on loopback, the
   campus mail-relay /16, and outbound-to-anywhere.
2. Admin baseline `NETWORK_BLOCKLIST` (set in
   `sandbox-admin.conf`; user cannot remove).
3. User `NETWORK_BLOCKLIST` extensions (additive only).

Inspect the effective list at runtime:

```bash
# From a test harness or sandbox-aware tool
source sandbox-lib.sh && effective_network_blocklist
```

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
   when the site provides a module. A
   `FredHutch/easybuild-life-sciences` request has been filed for
   Fred Hutch.

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
