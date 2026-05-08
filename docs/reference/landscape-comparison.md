# agent-sandbox in the agent-sandboxing landscape

> **Disclaimer.** This is not a formal benchmark or security audit of peer
> tools. It is a best-effort survey of publicly available documentation and
> source code, written so that readers evaluating agent-sandboxing choices on
> shared HPC clusters can place this project in context. Project capabilities
> change quickly — verify against each project's current docs before making
> deployment decisions. Last reviewed: **2026-05-07**.

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

## Feature matrix

Six deeply-compared peers plus four reference rows. Snapshot date
**2026-05-07**; cells reflect each project's documented behaviour at that
time. Verify against each project's current docs.

| Project | License | Approach | FS isolation | Network policy | GPU passthrough | Multi-tenant safety | HPC/Slurm aware |
|---|---|---|---|---|---|---|---|
| **agent-sandbox** | MIT | Linux kernel-bind: bwrap → firejail → Landlock fallback | Hidden (`ENOENT`) on bwrap/firejail; `EACCES` on Landlock; project-dir-only writable | Open by default (Anthropic API requirement); admin nftables hardening templates | `DEVICES+=(/dev/nvidia*)`, admin-locked `DEVICES_BLACKLIST` | Kernel-enforced; chaperon scopes Slurm to project | **Yes — only project in the surveyed field.** Chaperon mediates sbatch/srun/squeue/scancel/scontrol/sacct/sacctmgr |
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

**Domain-allowlist egress proxy.** Anthropic `sandbox-runtime`, `nono`,
Codex CLI, and `matchlock` ship a host-side proxy that restricts the
sandbox to a configured set of domains. agent-sandbox accepts open
network as a [documented trade-off](security.md#accepted-trade-offs):
agents need API access, and a workable allowlist that covers Anthropic,
OpenAI, GitHub, package indexes, conda channels, and HPC-specific
endpoints is non-trivial to maintain. The chaperon's UDS-over-bwrap
pattern is the obvious architectural template if this is ever pursued,
but it is **not on the current roadmap** — admins who want this today
should layer nftables / cgroups-net at the host level (see
[Admin Hardening](../admin/hardening.md)).

**Credential injection at the egress boundary.** `nono` and `matchlock`
keep API keys outside the sandbox and inject them at the proxy. Useful,
but coupled to having a proxy in the first place; same status as above.

**Network-namespace isolation as an opt-in profile.** `matchlock` ships
a `--no-network` mode and Codex CLI's bwrap mode unshares the network
namespace by default. agent-sandbox does not isolate the network
namespace today (sharing it is required for DNS / NSS / munge / Slurm in
the bwrap and firejail backends). A profile that drops network for
post-hoc analysis or offline review is a clean future addition that does
not conflict with the existing posture, but is **not on the roadmap**.

**Tamper-resistance messaging.** `nono` foregrounds the property that
Landlock rules cannot be widened by the sandboxed process. agent-sandbox
already provides equivalent (or stronger) tamper-resistance with the
bwrap backend — the agent runs in a separate user, mount, and PID
namespace it cannot rejoin — but the security docs do not currently
state this as a property of its own. A future docs pass should close
that messaging gap.

**Snapshot / restore and stateful resumption.** Vercel Sandbox and
Daytona check-point the agent's filesystem and dependencies so a session
can resume after restart. agent-sandbox's threat model does not motivate
this, and Apptainer already covers the reproducible-environment case on
HPC. **Out of scope by design** — see
[Sandbox vs. Apptainer](apptainer-comparison.md) for the longer
discussion of how the two complement each other.

## Bottom line

For AI agent containment on shared HPC, agent-sandbox occupies a niche
that no other open-source project surveyed targets directly: a
process-level kernel-bind sandbox with a Slurm-aware proxy, suitable for
multi-user clusters where containers need root and microVMs are
operationally heavy. Within the kernel-bind cluster, peers have
explored egress allowlists and credential proxies further than this
project has; outside the cluster, microVM and gVisor offerings provide
stronger isolation at the cost of HPC integration. Pick the layer that
matches your threat model and your operational footprint — and read the
[Security model](security.md) and the per-backend
[Known Limitations](security.md#known-limitations) before deploying any
of them.

## Survey provenance

Source for this comparison: an internal landscape survey conducted on
**2026-05-07** against the v0.8.0 release, tracked at
[`settylab/dotto-nexus#99`](https://github.com/settylab/dotto-nexus/issues/99)
(private). The survey methodology, full candidate triage, and exclusion
reasons live in that thread for forensic reference. This page is a
distillation, not a copy — the comparison-table cells were verified
against each project's primary documentation at the snapshot date. If
you spot a stale cell, please open an issue.
