# tools/pasta/ — network-filter helper

`pasta` (from the [passt](https://passt.top/) project, BSD-3-Clause arm)
is the network helper agent-sandbox uses to deliver
`NETWORK_FILTER_MODE=filtered` on bwrap backends without root or
unprivileged-eBPF availability.

## Status

**v1.0 ships the fetcher and the helper-detection scaffolding; the
bwrap + pasta + nft integration that actually consumes the binary is
v1.1 work.** Running `fetch.sh` today is harmless but the binary stays
unused until the integration lands and the
`NETWORK_FILTER_ENABLE_HELPER_PROBE` gate in `sandbox-lib.sh` flips
on. Until then, every `filtered`-mode request falls back per the
`NETWORK_FILTER_FALLBACK` policy (default `stricter` → `isolated`).

## Install

```bash
./tools/pasta/fetch.sh
```

This downloads the pinned upstream source tarball from
`https://passt.top/passt/snapshot/`, builds a static `pasta` for the
host architecture (musl-static when `musl-gcc` is available, glibc-
static otherwise), and installs it at `tools/pasta/pasta`. The
matching `LICENSES/BSD-3-Clause.txt` is staged alongside per
upstream's redistribution terms (BSD-3-Clause arm, no source-offer
obligation).

The runtime helper-detection in `sandbox-lib.sh::_resolve_network_helper`
probes for `pasta` in this order:

1. `command -v pasta` — distro / Homebrew install
2. `tools/pasta/pasta` — this shipped binary
3. `command -v slirp4netns` — alternative helper

## Alternative install paths

- **Distro packages**: `apt install passt` (Ubuntu 22.10+, Debian
  Bookworm+), `dnf install passt` (Fedora 36+, RHEL 9+).
- **Homebrew**: `brew install passt`.
- **lmod (site-specific)**: when the site provides a `passt` module,
  pin via `SANDBOX_MODULES+=("passt/<version>")` and skip `fetch.sh`.
  The upstream easyconfig is small (no third-party deps); sites with
  an EasyBuild pipeline can submit a recipe request.

## License

The shipped binary is redistributed under the **BSD-3-Clause** arm of
passt's dual `GPL-2.0-or-later OR BSD-3-Clause` license. The matching
`LICENSE-BSD-3-Clause` file is staged here by `fetch.sh`.
