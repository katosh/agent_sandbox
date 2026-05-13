# tools/pasta/ — network-filter helper

`pasta` (from the [passt](https://passt.top/) project, BSD-3-Clause arm)
is the network helper agent-sandbox uses to deliver
`NETWORK_FILTER_MODE=filtered` on bwrap backends without root or
unprivileged-eBPF availability.

## Status

**v1.1: real `filtered`-mode enforcement is live by default.** When
a network helper (pasta) AND `nft` are both available on the host,
the bwrap backend wraps the sandbox in a pasta-provisioned netns and
installs an nftables ruleset generated from
`effective_network_blocklist`. The
`NETWORK_FILTER_ENABLE_HELPER_PROBE` gate from v1.0 is gone.

## Shipped binary

The repo ships a verified static pasta binary at
`tools/pasta/<arch>/pasta` (currently x86_64 only). The matching
SHA256 is pinned in `SHA256SUMS`; the build provenance is in
`NOTICE`. The runtime helper-probe finds this binary automatically.

To refresh or re-pin:

```bash
./tools/pasta/fetch.sh                       # fetch pre-built binary, verify SHA256
PASTA_BUILD_FROM_SOURCE=1 ./tools/pasta/fetch.sh   # build from upstream source instead
```

The default path fetches the pinned upstream build from
`https://passt.top/builds/<tag>/<arch>/pasta` and rewrites
`SHA256SUMS`. Source builds require kernel headers ≥ 5.9 (for
`<linux/close_range.h>`); on older build hosts use the binary path.

## Helper detection order

The runtime helper-detection in
`sandbox-lib.sh::_resolve_network_helper` probes for `pasta` in this
order:

1. `command -v pasta` — distro / Homebrew install (operator-supplied,
   typically newer than the in-tree pin)
2. `tools/pasta/<arch>/pasta` — the shipped binary in this directory
3. `command -v slirp4netns` — alternative helper (older, slower, GPL
   source-offer obligation; less preferred)

In addition, `nft` (nftables) must be available on PATH — pasta
provisions the netns and tap interface but the per-entry blocklist is
enforced by nftables rules installed inside that netns. If either
helper is missing, the resolver falls back per `NETWORK_FILTER_FALLBACK`
(default `stricter` → `isolated`; loud warning).

## Alternative install paths

- **Distro packages**: `apt install passt nftables` (Ubuntu 22.10+,
  Debian Bookworm+), `dnf install passt nftables` (Fedora 36+,
  RHEL 9+).
- **Homebrew**: `brew install passt`. (nftables is Linux-only; macOS
  hosts won't reach `filtered` mode regardless.)
- **lmod (site-specific)**: when the site provides a `passt` module,
  pin via `SANDBOX_MODULES+=("passt/<version>")` and the helper-probe
  picks it up first (it lands on PATH).
- **Source build**: `PASTA_BUILD_FROM_SOURCE=1 ./tools/pasta/fetch.sh`
  for sites with binary-redistribution policy constraints.

## License

The shipped binary is redistributed under the **BSD-3-Clause** arm of
passt's dual `GPL-2.0-or-later OR BSD-3-Clause` license. The license
text from upstream is at `<arch>/LICENSE-BSD-3-Clause`; the
attribution + provenance statement is at `<arch>/NOTICE`.
