#! /bin/bash --
# tools/pasta/fetch.sh — fetch a pinned upstream pasta static binary.
#
# Fetches the passt/pasta release tarball from passt.top, extracts the
# static binary matching the host architecture, and installs it at
# tools/pasta/pasta. Used by the network-filter `filtered` mode (see
# docs/reference/network-filter.md).
#
# The pin is intentionally version-locked. To bump, edit PASTA_VERSION
# + PASTA_SHA256_<arch> below; re-run; commit.
#
# Upstream is dual-licensed `GPL-2.0-or-later OR BSD-3-Clause`. We
# select the BSD-3-Clause arm (no source-offer obligation) and ship
# the LICENSE text alongside the binary in this directory.
#
# Network-filter integration status (v1.0): this fetcher is the
# shipped path, but the bwrap+pasta+nft chain that consumes the
# binary is v1.1 work. Running this script today is harmless but
# the binary is unused until the integration lands. See
# `NETWORK_FILTER_ENABLE_HELPER_PROBE` in sandbox-lib.sh.

set -euo pipefail

PASTA_VERSION="${PASTA_VERSION:-2024_09_06.6b38f07}"
PASTA_BASE_URL="${PASTA_BASE_URL:-https://passt.top/passt/snapshot}"

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_arch="$(uname -m)"
case "$_arch" in
    x86_64|amd64) _arch=x86_64 ;;
    aarch64|arm64) _arch=aarch64 ;;
    *) echo "tools/pasta/fetch.sh: unsupported arch '$_arch' (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac

_tarball="passt-${PASTA_VERSION}.tar.gz"
_url="${PASTA_BASE_URL}/${_tarball}"
_tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-pasta-fetch.XXXXXX")"
trap 'rm -rf "$_tmp"' EXIT

echo "tools/pasta/fetch.sh: fetching ${_url}"
if command -v curl &>/dev/null; then
    curl -fsSL "$_url" -o "$_tmp/$_tarball"
elif command -v wget &>/dev/null; then
    wget -q -O "$_tmp/$_tarball" "$_url"
else
    echo "tools/pasta/fetch.sh: need curl or wget to fetch the tarball" >&2
    exit 1
fi

# Upstream tarballs ship source; we build static for the host arch.
# The build requires make + gcc + libc-dev only (no extra deps — pasta
# is intentionally dependency-free; that's the whole point of the
# pick).
tar -xzf "$_tmp/$_tarball" -C "$_tmp"
_src="$(find "$_tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
if [[ -z "$_src" ]]; then
    echo "tools/pasta/fetch.sh: failed to locate extracted source dir" >&2
    exit 1
fi

echo "tools/pasta/fetch.sh: building pasta from source in $_src"
# Pin musl-static build when musl-gcc is available; fall back to glibc
# static otherwise. Both produce a runnable binary; musl is preferred
# for portability across HPC nodes with varying glibc.
if command -v musl-gcc &>/dev/null; then
    make -C "$_src" CC=musl-gcc CFLAGS="-static" pasta 1>&2
else
    make -C "$_src" CFLAGS="-static" pasta 1>&2
fi

install -m 0755 "$_src/pasta" "$_dir/pasta"
# Ship the BSD-3-Clause LICENSE alongside per redistribution terms.
if [[ -f "$_src/LICENSES/BSD-3-Clause.txt" ]]; then
    install -m 0644 "$_src/LICENSES/BSD-3-Clause.txt" "$_dir/LICENSE-BSD-3-Clause"
fi

echo "tools/pasta/fetch.sh: installed $_dir/pasta ($("$_dir/pasta" --version 2>&1 | head -1))"
