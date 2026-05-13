# tools/pasta/ — network-filter helper

`pasta` (from the [passt](https://passt.top/) project, BSD-3-Clause
arm of the dual GPL/BSD license) is the network helper agent-sandbox
uses to deliver `NETWORK_FILTER_MODE=filtered` on bwrap backends
without root or unprivileged-eBPF availability.

## Status (v1.1)

`filtered`-mode enforcement is live by default. When pasta is
available on the host, the bwrap backend wraps the sandbox in a
pasta-provisioned netns and pasta enforces the port-level blocklist
at its own outbound boundary via `-T ~N` (TCP) and `-U ~K` (UDP)
exclusion flags generated from `effective_network_blocklist`. **No
nftables / iptables runtime dependency.** The
`NETWORK_FILTER_ENABLE_HELPER_PROBE` gate from v1.0 is gone.

## Shipped binary

The repo ships a verified static pasta binary at
`tools/pasta/<arch>/pasta` (x86_64 in v1.1). The matching SHA256
is pinned in `SHA256SUMS`; build provenance is in `NOTICE`. The
runtime helper-probe finds this binary automatically.

To refresh or re-pin:

```bash
./tools/pasta/fetch.sh                           # fetch pre-built + verify SHA256
PASTA_BUILD_FROM_SOURCE=1 ./tools/pasta/fetch.sh # build from upstream source
```

The default path fetches the pinned upstream build from
`https://passt.top/builds/<tag>/<arch>/pasta` and rewrites
`SHA256SUMS`. Source builds require kernel headers ≥ 5.9 (for
`<linux/close_range.h>`); on older build hosts use the binary path.

## Helper detection order

The runtime helper-detection in
`sandbox-lib.sh::_resolve_network_helper` probes in this order:

1. `command -v pasta` — distro / Homebrew install (operator-supplied,
   typically newer than the in-tree pin).
2. `tools/pasta/<arch>/pasta` — the shipped binary in this directory.
3. `command -v slirp4netns` — older fallback (GPL-2.0 source-offer
   obligation; less preferred and currently degraded to plain
   isolated mode + warning — full slirp4netns wiring is follow-up).

If pasta is missing, the resolver falls back per
`NETWORK_FILTER_FALLBACK` (default `stricter` → `isolated`; loud
warning).

## Alternative install paths

- **Distro packages**: `apt install passt` (Ubuntu 22.10+, Debian
  Bookworm+), `dnf install passt` (Fedora 36+, RHEL 9+),
  `brew install passt` (Linux Homebrew).
- **lmod (site-specific)**: when the site provides a `passt` module,
  `SANDBOX_MODULES+=("passt/<version>")` puts it on PATH and the
  helper-probe picks it up first.
- **Source build**: `PASTA_BUILD_FROM_SOURCE=1 ./tools/pasta/fetch.sh`
  for sites with binary-redistribution policy constraints.

## License

The shipped binary is redistributed under the **BSD-3-Clause** arm
of passt's dual `GPL-2.0-or-later OR BSD-3-Clause` license. The
license text from upstream is at `<arch>/LICENSE-BSD-3-Clause`; the
attribution + provenance statement is at `<arch>/NOTICE`.
