# agent-sandbox in the agent-sandboxing landscape

> **Disclaimer.** This is not a formal benchmark or security audit of peer
> tools. It is a best-effort survey of publicly available documentation and
> source code, written so that readers evaluating agent-sandboxing choices on
> shared HPC clusters can place this project in context. Project capabilities
> change quickly — verify against each project's current docs before making
> deployment decisions. Last reviewed: **2026-05-15** (originally surveyed
> **2026-05-07**; refreshed on 2026-05-15 for the v0.10.x network-filter
> mode-quartet and mail-block additions).

## The field

Sandboxing for AI coding agents has converged into roughly six isolation
layers: process-level kernel-bind wrappers (bubblewrap, firejail, Landlock),
OCI-container wrappers, gVisor + Kubernetes runtimes, Firecracker / libkrun
microVMs, WASM language-level containment, and hosted SaaS dev-environment
runtimes (Devin, Replit, Cursor, Codespaces). A 2026-05 snowball survey
across [`dloss/awesome-agent-sandboxes`](https://github.com/dloss/awesome-agent-sandboxes)
and the broader GitHub topic surfaced ~30 named projects, of which 25 had
been pushed to in the previous 90 days. Each layer makes a different
trade-off between isolation strength, host integration, and operational
weight; no single layer dominates.

## Where agent-sandbox sits

agent-sandbox is a **process-level kernel-bind wrapper**: it builds a
restricted view of the host filesystem using the kernel's existing
isolation primitives (mount namespaces via `bubblewrap`, file-access rules
via Landlock, or path policies via firejail) and then runs the agent's
shell inside that view. No image to build, no daemon, no virtual machine.

The closest peers on isolation primitives are:

- **[Anthropic `sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime)** — the open-source companion to Claude Code's built-in `/sandbox`. Linux: bwrap + seccomp + a host-side HTTP/SOCKS5 egress proxy. macOS: Apple Seatbelt. Apache-2.0.
- **OpenAI Codex CLI's [`codex-linux-sandbox`](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md)** — bwrap (default) + seccomp + Landlock fallback, with `unshare-net` plus an internal TCP→UDS→TCP managed-proxy mode for egress control. Apache-2.0, on-by-default for non-trusted commands.
- **[`always-further/nono`](https://github.com/always-further/nono)** — Landlock-only on Linux, Seatbelt on macOS, with a credential proxy that keeps API keys outside the sandbox entirely. Apache-2.0.
- **[`nikvdp/cco`](https://github.com/nikvdp/cco)** ("Claude Condom") — tiered: native primitive when available (sandbox-exec on macOS, bwrap on Linux), Docker as a fallback. MIT.
- **[`bindsch/scode`](https://github.com/bindsch/scode)** — single-script bwrap (Linux) / Seatbelt (macOS) wrapper with a unified policy across multiple agent harnesses. MIT.

The cluster shares a thesis: the agent already runs on the user's host, so
the cheapest way to reduce blast radius is to narrow the host view it sees
rather than relocate the agent into a separate machine. Different members
emphasize different things — `nono` foregrounds credential handling,
Codex CLI foregrounds being on-by-default, agent-sandbox foregrounds HPC
compatibility — but the kernel primitives underneath are largely the
same.

## What is unique to agent-sandbox

**Kernel-namespace-enforced network egress, not tool-cooperative.**
v0.10.1 ships four [`NETWORK_FILTER_MODE`](network-filter.md#modes)
values — `open` < `filtered` < `proxied` < `isolated` — and the three
non-`open` modes run the sandboxed agent inside an `--unshare-net`
network namespace. `filtered` (the shipped default) provisions a
[pasta](https://passt.top/)-backed tap interface to the host network
and closes the identity-bound port floor (SMTP submission
24/25/465/587/2525, DoT 853, telnet/finger/ident/rexec/rlogin/rsh) at
pasta's own `-T ~N` / `-U ~K` outbound-forwarding boundary — no
nftables or iptables dependency. `proxied` (v0.10.1, the
[fallback target for pasta-deficient hosts](network-filter.md#proxied-mode-host-side-http-connect-socks5-fallback))
puts the empty netns behind a host-side HTTP CONNECT + SOCKS5 daemon
(`tools/proxy/agent-sandbox-proxy.py`) reached via two bind-mounted
Unix sockets, enforcing the full blocklist (hostname, wildcard, CIDR,
bare port) at CONNECT time on top of a hardened IP floor the user
cannot lift (RFC1918, link-local, CGNAT, cloud metadata, IPv6 ULA).
`isolated` is `--unshare-net` with no helper.

The mechanism is the differentiator. A non-cooperating, jailbroken,
or compromised agent inside the sandbox **cannot** reach the network
outside the configured policy regardless of what its tool layer
thinks about its permissions — the kernel does not consult the
agent's tools list. Contrast with agent-layer permission gates
(Claude Code's `--allowedTools` / `--dangerously-skip-permissions`
/ per-action permission prompts, and similar permission systems in
other CLI harnesses), which mediate the agent's *cooperation* with
the gate and can be ignored once jailbroken. The mode-quartet and
fallback resolver live in
[`sandbox-lib.sh`](https://github.com/katosh/agent_sandbox/blob/main/sandbox-lib.sh)
(`NETWORK_FILTER_MODE`, `NETWORK_FILTER_FALLBACK`,
`_resolve_network_helper`); helper binaries under `tools/pasta/`
(SHA256-pinned static pasta) and `tools/proxy/` (single-file Python
helper). In the [feature matrix](#feature-matrix) below this puts
`filtered`/`proxied` in the same enforcement class as Anthropic
`sandbox-runtime`'s bwrap + proxy combination and Codex CLI's
`unshare-net` + managed-proxy, and outside the enforcement class of
cco / scode (no enforcement) and cooperative-tool-permission gates
generally.

**HPC/Slurm awareness via the chaperon proxy.** Of the projects surveyed,
agent-sandbox is the only one that targets shared-cluster multi-tenant
deployments as a first-class scenario. The [chaperon](chaperon.md) is a
host-side proxy that mediates `sbatch`, `srun`, `squeue`, `scancel`,
`scontrol`, `sacct`, and `sacctmgr` from inside the sandbox: every job is
rewritten to wrap its payload in `sandbox-exec.sh` on the compute node,
arguments are whitelisted, the munge authentication socket is blocked
inside the sandbox, and the queue view is scoped to sandbox sessions in
the same project. None of the kernel-bind peers above offer an analogue;
none of the microVM or container offerings fit cleanly inside the
existing `sbatch` submission model that HPC sites already operate.

**Bind-mount FS isolation rather than path-denylist FS isolation.** Most
of the peer wrappers maintain an explicit deny-list of host paths the
agent should not see (`~/.ssh`, cloud-credential directories, etc.). When
the deny-list grows or is incomplete, agents have repeatedly found
workarounds — for example, invoking `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/wget`
to load a binary that an `execve`-only block had hidden, or routing
through `/proc/self/root` to reach paths denied at their canonical names
([Ona, 2026-04](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox)).
agent-sandbox's primary backend (bwrap) operates at a layer below where
those evasions live: the agent runs in a separate mount namespace whose
filesystem is rebuilt from `~/.ssh`-blank inputs, so denied paths return
`ENOENT` and there is no canonical name reachable through `ld-linux` or
`/proc/self/root`. The Landlock fallback is weaker (path-based,
`EACCES`); see [Security model — Backend Comparison](security.md#backend-comparison).

**Deterrent stubs against AI mail exfiltration.**
[`NETWORK_MAIL_BLOCK`](network-filter.md#outbound-mail-policy)
(v0.10.1) replaces 30 canonical mailer binaries (the
`_MAIL_BLOCK_STUB_NAMES` set in `sandbox-lib.sh` — `sendmail`,
`mail`, `mailx`, `mutt`, `msmtp`, the postfix admin tools, `swaks`,
`exim`, `dma`, the qmail client family, and others) with a
[stub](https://github.com/katosh/agent_sandbox/blob/main/tools/mail-block/mail-block-stub.sh)
that exits 77 (`EX_NOPERM`) and prints a sixteen-line message
addressed *to an AI agent* — the policy is configured not transient,
every known mailer resolves to this stub, retrying with another
binary or another path produces the same result, escalate to the
user rather than search. Two reinforcing path-resolution layers
(`--ro-bind` over canonical absolute paths plus a per-launch
PATH-prefix symlink farm) ensure the stub wins regardless of how
`argv[0]` resolves — Lmod-injected, brew-installed, hand-built, or
distro-shipped.

This is defense-in-depth above the network filter's port closure,
targeting the agentic retry loop specifically. The port-level filter
catches the language-level dialer (`python -c 'smtplib...'`,
`curl smtp://`, `nc relay 25`); the stub catches the `execve` *before*
the dial, with a message that explicitly forecloses the search tree.
Of the surveyed peers none ship an analogue: domain-allowlist proxies
(Anthropic, nono, Codex CLI, matchlock) also drop SMTP, but silently
at L4 — to a cooperating agent that reads as a transient network
fault and invites retry across binaries and paths. Bwrap only in
v0.10.1; firejail / landlock parity is mechanically straightforward
and tracked as follow-up.

## Feature matrix

Six deeply-compared peers plus four reference rows. Peer rows
snapshotted **2026-05-07**; agent-sandbox row refreshed **2026-05-15**
for the v0.10.x network-filter mode-quartet and mail-block
additions. Cells reflect each project's documented behaviour at the
respective snapshot date; verify against each project's current docs.

| Project | License | Approach | FS isolation | Network policy | GPU passthrough | Multi-tenant safety | HPC/Slurm aware |
|---|---|---|---|---|---|---|---|
| **agent-sandbox** | MIT | Linux kernel-bind: bwrap → firejail → Landlock fallback | Hidden (`ENOENT`) on bwrap/firejail; `EACCES` on Landlock; project-dir-only writable | **Kernel-namespace-enforced**, four `NETWORK_FILTER_MODE` modes (`open`/`filtered`/`proxied`/`isolated`); `filtered` default uses a pasta-backed netns with an identity-bound port-class deny floor; `proxied` adds a host-side HTTP CONNECT + SOCKS5 daemon enforcing the full hostname/wildcard/CIDR blocklist; deterrent-stub mail-block layer over 30 canonical mailer binaries | `DEVICES+=(/dev/nvidia*)`, admin-locked `DEVICES_BLACKLIST` | Kernel-enforced; chaperon scopes Slurm to project | **Yes — only project in the surveyed field.** Chaperon mediates sbatch/srun/squeue/scancel/scontrol/sacct/sacctmgr |
| **Anthropic `sandbox-runtime`** | Apache-2.0 | Linux: bwrap + seccomp + HTTP/SOCKS5 proxy. macOS: Seatbelt | Deny-then-allow reads, allow-only writes | **Domain allowlist via host-side proxy**; seccomp blocks Unix-socket creation | Not a stated goal | Single-user host | No |
| **OpenAI Codex CLI sandbox** | Apache-2.0 | Linux: bwrap (default) + seccomp + Landlock fallback. macOS: Seatbelt | `--ro-bind / /` everywhere, write-restricted to whitelisted roots; `/dev/null` write-allowed | `unshare-net` + internal TCP→UDS→TCP managed-proxy | Not in tree | Single-user, in-process | No |
| **nono** | Apache-2.0 | Linux: Landlock-only. macOS: Seatbelt | Kernel-irrevocable Landlock rules | **Credential proxy** keeps API keys outside sandbox; injects auth at egress | Not a stated goal | Capability-based; restrictions inherit to children | No |
| **cco** | MIT | macOS sandbox-exec / Linux bwrap, Docker fallback | Native: full host RO + project RW. Docker mode: only mounted paths | Not enforced (unless Docker mode chosen) | n/a | Single-user developer use | No |
| **scode** | MIT | Single bash script: bwrap (Linux) / Seatbelt (macOS) | Path-based access control over 35+ credential paths and 28+ env-var patterns | Not enforced | n/a | Single-user developer use | No |
| **kubernetes-sigs/agent-sandbox** | Apache-2.0 | Kubernetes CRD; pluggable runtime (gVisor / Kata) | Pod-level | NetworkPolicy via Kubernetes | Via device-plugin / ResourceClaim | **Designed for it** — kube-RBAC, singleton stateful pod | Not directly |
| **e2b** | Apache-2.0 | Hosted Firecracker microVM | Hardware VM-isolated | Configurable per-sandbox | Available on premium tiers | **Yes, by hypervisor** | No (cloud-only) |
| **matchlock** | MIT | Local Firecracker (Linux) / Vz.framework (macOS) | Per-VM overlay; ephemeral | **Allowlist proxy + MITM secret injection** | Not a stated goal | Hypervisor-level | No |
| **microsandbox** | Apache-2.0 | Local libkrun microVM, MCP integration | Per-VM | Configurable per VM | Not in default profile | Hardware-isolated | No |

**Reference rows (hosted, not deeply compared because their internals
are not open):** [Daytona](https://github.com/daytonaio/daytona) (OCI
containers, AGPL-3.0), [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox)
(hosted Firecracker with snapshot/restore),
[Modal Sandboxes](https://modal.com/docs/guide/sandbox) (hosted gVisor),
[`alibaba/OpenSandbox`](https://github.com/alibaba/OpenSandbox)
(Apache-2.0; OCI + gVisor + Kata + Firecracker, the closest open-source
peer to a full agent-runtime PaaS).

## What this means for agent-sandbox's design

agent-sandbox is opinionated about a narrow scenario — **a single AI
coding agent running on a user's HPC login node, with kernel-enforced
boundaries against credential and cross-project leakage** — and trades
breadth for fit. The tools above sketch a few directions where the field
has gone further; we have looked at each and recorded our current stance.

### Closed since the v0.8.0 survey

**Network-namespace isolation and egress enforcement.** The original
survey (v0.8.0) listed "agent-sandbox does not isolate the network
namespace today" as a gap and "a host-side proxy that restricts the
sandbox to a configured set of domains" as not on the roadmap. v1.0
(v0.9-cycle) shipped the configuration surface and fallback resolver;
v1.1 (v0.10.0) shipped port-level enforcement via pasta + netns;
v0.10.1 shipped the host-side HTTP CONNECT + SOCKS5 proxy
(`proxied` mode) with hostname/wildcard/CIDR enforcement. The
shipped [`NETWORK_BLOCKLIST` floor](network-filter.md#configuration)
closes the identity-bound exfil + lateral-movement surface (mail
relays, webhook-as-mail endpoints, transactional-email APIs,
file-drop / paste services, DoH/DoT, legacy r-services) without
requiring operators to enumerate every host the agent legitimately
needs. The
[implicit-allowlist idiom](network-filter.md#implicit-allowlist-idiom-exact-hosts)
(`NETWORK_BLOCKLIST=("*")` plus `NETWORK_BLOCKLIST_EXCEPT` of exact
hosts) is documented for power users who want deny-by-default
semantics. Mechanism citation:
[Kernel-namespace-enforced network egress](#what-is-unique-to-agent-sandbox)
above.

**Mail-block deterrent layer.** A novel addition vs. the surveyed
peers — `NETWORK_MAIL_BLOCK=auto|on|off` replaces 30 canonical mailer
binaries with a stub that exits 77 and prints a deterrent message
addressed to an AI agent. Mechanism citation:
[Deterrent stubs against AI mail exfiltration](#what-is-unique-to-agent-sandbox)
above.

**Tamper-resistance messaging.** `nono` foregrounds the property
that Landlock rules cannot be widened by the sandboxed process.
v0.9.0 added a [Tamper resistance section](security.md#tamper-resistance)
to the security model naming the equivalent (and stronger) property
on the bwrap primitive: once the sandbox is up, the agent inside
cannot weaken isolation — no `dangerouslyDisableSandbox` flag, no
in-process bypass, mount/PID/seccomp state irrevocable for the
sandboxed PIDs. v0.9.0 also added a
[Cooperative reinforcement section](security.md#cooperative-reinforcement-agent-side-awareness)
documenting the per-agent Sandbox Integrity injection — defense in
depth on top of kernel enforcement, so a cooperating agent stops
wasting turns on "retry without sandbox" attempts and a hostile
instruction in the agent's input data becomes a recognizable
prompt-injection signal.

### Still deferred

**Credential injection at the egress boundary.** `nono` and
`matchlock` keep API keys outside the sandbox and inject them at the
proxy. The v0.10.1 `proxied` mode is a policy-checking proxy, not an
auth-mediating one — credentials live inside the sandbox alongside
the agent the same way they do on the other kernel-bind peers.
Adding credential injection on top of the existing `tools/proxy/`
daemon is a clean extension (the Python helper is in the right place
architecturally) but **not on the current roadmap**; the present
recommendation is `BLOCKED_ENV_VARS` + `BLOCKED_ENV_PATTERNS` to
keep credential env vars out of the agent's environment in the first
place.

**Curated default-allowlist preset for known agent destinations.**
The shipped policy is deny-by-blocklist. A curated inverse preset
(`NETWORK_BLOCKLIST=("*")` with a maintained `NETWORK_BLOCKLIST_EXCEPT`
covering Anthropic, OpenAI, GitHub, PyPI, conda, and common HPC site
endpoints) was deferred in favour of the blocklist model — the
implicit-allowlist idiom remains available for power users who want
to express the inverse shape today.

**SNI-aware HTTPS filtering under `filtered`.** pasta `-T/-U` filters
by destination port at the netns boundary; hostname / wildcard / CIDR
entries are silently skipped under `filtered` (notes emitted only
under `NETWORK_FILTER_VERBOSE=1`) and only enforced under `proxied`.
The universal port-class closure is what's load-bearing for the
identity-hijack threat under `filtered`; L7 (SNI) inspection of
arbitrary HTTPS destinations on top of `filtered` is future scope.

**Snapshot / restore and stateful resumption.** Vercel Sandbox and
Daytona check-point the agent's filesystem and dependencies so a
session can resume after restart. agent-sandbox's threat model does
not motivate this, and Apptainer already covers the
reproducible-environment case on HPC. **Out of scope by design** —
see [Sandbox vs. Apptainer](apptainer-comparison.md) for the longer
discussion of how the two complement each other.

## Bottom line

For AI agent containment on shared HPC, agent-sandbox occupies a niche
that no other open-source project surveyed targets directly: a
process-level kernel-bind sandbox with kernel-namespace-enforced
network egress (four modes, pasta + HTTP CONNECT + SOCKS5), a deterrent
mail-block layer targeted at agent retry behaviour, and a Slurm-aware
proxy — suitable for multi-user clusters where containers need root
and microVMs are operationally heavy. Within the kernel-bind cluster,
peers offer adjacent enforcement shapes — Anthropic `sandbox-runtime`'s
domain allowlist, `nono`'s credential proxy, Codex CLI's unshare-net +
managed-proxy — and the credential-injection direction is one this
project has not pursued. Outside the cluster, microVM and gVisor
offerings provide stronger isolation at the cost of HPC integration.
Pick the layer that matches your threat model and your operational
footprint — and read the [Security model](security.md), the
[Network filter reference](network-filter.md), and the per-backend
[Known Limitations](security.md#known-limitations) before deploying
any of them.

## Survey provenance

Source for this comparison: an internal landscape survey conducted on
**2026-05-07** against the v0.8.0 release, tracked at
[`settylab/dotto-nexus#99`](https://github.com/settylab/dotto-nexus/issues/99)
(private). The survey methodology, full candidate triage, and exclusion
reasons live in that thread for forensic reference. This page is a
distillation, not a copy — the comparison-table cells were verified
against each project's primary documentation at the snapshot date.

Refreshed on **2026-05-15** for the v0.10.x additions: the network-filter
configuration surface (PR #52, v0.9 cycle), port-level `filtered`
enforcement via pasta (PRs #53–#54, v0.10.0), the `proxied` mode for
pasta-deficient hosts (PR #58, v0.10.1), and the `NETWORK_MAIL_BLOCK`
deterrent-stub layer (PR #61, v0.10.1) — plus the v0.9.0 Tamper
resistance / Cooperative reinforcement sections of the
[security model](security.md). The peer rows were not re-snapshotted in
this refresh; if you spot a stale cell, please open an issue.
