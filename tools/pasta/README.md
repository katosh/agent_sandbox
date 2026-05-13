# tools/pasta/ — network-filter helper

`pasta` (from the [passt](https://passt.top/) project, BSD-3-Clause arm)
is the network helper agent-sandbox uses to deliver
`NETWORK_FILTER_MODE=filtered` on bwrap backends without root or
unprivileged-eBPF availability.

## Status

**v1.1: real `filtered`-mode enforcement is live by default.** When
pasta is available on the host AND its host-side forwarding works,
the bwrap backend wraps the sandbox in a pasta-provisioned netns and
asks pasta to drop outbound traffic on the blocklisted port set via
its `-T ~N` (TCP) / `-U ~K` (UDP) exclusion syntax. Enforcement happens
at pasta's own forwarding boundary — **NO nftables / iptables runtime
dependency**. The `NETWORK_FILTER_ENABLE_HELPER_PROBE` gate from v1.0
is gone.

## Shipped binary

The repo ships a verified static pasta binary at
`tools/pasta/<arch>/pasta` (currently x86_64 only). The matching
SHA256 is pinned in `SHA256SUMS`; the build provenance is in
`NOTICE`. `make install` lays it down at
`<prefix>/lib/agent-sandbox/tools/pasta/<arch>/pasta` and the
runtime helper-probe finds it automatically.

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
2. `<SANDBOX_DIR>/tools/pasta/<arch>/pasta` — the shipped binary
   landed there by `make install` (or by running `./tools/pasta/fetch.sh`
   in a dev tree)
3. `command -v slirp4netns` — alternative helper (older, slower, GPL
   source-offer obligation; less preferred, currently degraded to
   isolated fallback)

If the resolver finds none of these, it falls back per
`NETWORK_FILTER_FALLBACK` (default `stricter` → `isolated`; loud
warning).

## Helper validation: the forwarding probe

Pasta-binary presence is necessary but not sufficient. On kernels
that gate `SO_BINDTODEVICE` behind `CAP_NET_RAW` (most kernels < 5.7,
or any host without the 2020 relaxation backported), an unprivileged
pasta starts but logs

```
SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-T auto'
SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-U auto'
```

and silently restricts forwarding to loopback only. Without a probe
the resolver would declare `filtered` deliverable, the sandbox would
launch with the documented pasta argv, and the agent would lose
outbound on every port — even ports the blocklist did NOT exclude. The
threat-model intent (close mail-relay / webhook / paste / DoH /
legacy-r-services) is unmet AND the agent can't do its job.

To close that gap, `_pasta_can_forward_outbound` runs
`pasta --foreground --quiet -- true` after resolving the binary and
inspects stderr for the `forwarding only 127.0.0.1` banner. On match,
`_NETWORK_HELPER_PROBE_RESULT="degraded"` is set in the resolver's
scope; the resolver does not include `filtered` in the supported set
and falls back per policy. The fallback warning surfaces the specific
degradation reason and the three workarounds:

1. **`setcap cap_net_raw+ep <pasta>`** on a system-wide pasta binary
   (admin / root needed; cleanest fix; one-time per upgrade).
2. **Upgrade to kernel ≥ 5.7** with the SO_BINDTODEVICE relaxation.
3. **Pin `NETWORK_FILTER_MODE=open` or `isolated`** to make the
   reach trade-off explicit.

### Escape hatch

`NETWORK_FILTER_SKIP_HELPER_PROBE=1` bypasses the probe. Set this only
when you have verified pasta's host-side forwarding works (e.g. you
ran `setcap cap_net_raw+ep` on a system pasta and want to skip the
~50ms probe per sandbox start). Setting it on a host where pasta
degrades will re-introduce the silent-loopback-only failure mode; do
not set it as a workaround for the warning.

## Alternative install paths

- **`make install` (default):** the shipped `tools/pasta/<arch>/pasta`
  lands at `<prefix>/lib/agent-sandbox/tools/pasta/<arch>/pasta`
  automatically. No extra step.
- **Distro packages**: `apt install passt` (Ubuntu 22.10+, Debian
  Bookworm+), `dnf install passt` (Fedora 36+, RHEL 9+). Distro
  packages typically land on PATH and so take precedence over the
  shipped binary in the probe order above.
- **Homebrew**: `brew install passt`.
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
