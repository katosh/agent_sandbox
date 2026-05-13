#! /bin/bash --
# tools/pasta/fetch.sh — fetch (or rebuild) the in-tree pasta helper.
#
# v1.1 default: download the pinned upstream static binary and verify
# its SHA256 against tools/pasta/<arch>/SHA256SUMS. The repo already
# ships a verified binary at tools/pasta/<arch>/pasta, so the typical
# invocation of this script is to refresh that binary after bumping
# the pin (edit PASTA_BUILD below + SHA256SUMS in lockstep).
#
# For sites that disallow binary redistribution (strict reproducibility
# policy), set PASTA_BUILD_FROM_SOURCE=1 to build from the upstream
# source snapshot instead. Requires `make`, `gcc`, and kernel headers
# new enough to include <linux/close_range.h> (kernel ≥ 5.9 or the
# matching userspace headers backported). On older build hosts the
# source build fails and you should use the binary path.
#
# Upstream is dual-licensed `GPL-2.0-or-later OR BSD-3-Clause`. We
# select the BSD-3-Clause arm (no source-offer obligation) and ship
# the matching LICENSE text alongside the binary; see NOTICE in this
# directory.
#
# Network-filter integration: agent-sandbox v1.1 wires bwrap + pasta +
# nft to deliver `NETWORK_FILTER_MODE=filtered` enforcement. The
# helper-probe in sandbox-lib.sh::_resolve_network_helper finds this
# binary at runtime when nothing on PATH supersedes it. Probe order:
# PATH `pasta` → tools/pasta/<arch>/pasta → PATH `slirp4netns`.

set -euo pipefail

# Pin the upstream build. To bump:
#   1. Pick a build tag from https://passt.top/builds/<tag>/x86_64/
#      (or use 'latest' for the rolling head).
#   2. Update PASTA_BUILD_TAG.
#   3. Re-run this script; it will refresh tools/pasta/<arch>/pasta
#      and rewrite SHA256SUMS.
#   4. Commit the refreshed binary + SHA256SUMS together.
PASTA_BUILD_TAG="${PASTA_BUILD_TAG:-latest}"
PASTA_BUILD_BASE_URL="${PASTA_BUILD_BASE_URL:-https://passt.top/builds}"

# Source-build pin (used only when PASTA_BUILD_FROM_SOURCE=1).
PASTA_VERSION="${PASTA_VERSION:-2026_05_07.1afd4ed}"
PASTA_SOURCE_BASE_URL="${PASTA_SOURCE_BASE_URL:-https://passt.top/passt/snapshot}"

_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_arch="$(uname -m)"
case "$_arch" in
    x86_64|amd64) _arch=x86_64 ;;
    aarch64|arm64) _arch=aarch64 ;;
    *) echo "tools/pasta/fetch.sh: unsupported arch '$_arch' (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac

_archdir="$_dir/$_arch"
mkdir -p "$_archdir"
_install_path="$_archdir/pasta"
_sums_path="$_archdir/SHA256SUMS"
_license_path="$_archdir/LICENSE-BSD-3-Clause"

_fetch() {
    local _url="$1" _dst="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL --max-time 60 "$_url" -o "$_dst"
    elif command -v wget &>/dev/null; then
        wget -q -O "$_dst" "$_url"
    else
        echo "tools/pasta/fetch.sh: need curl or wget to fetch '$_url'" >&2
        exit 1
    fi
}

if [[ "${PASTA_BUILD_FROM_SOURCE:-0}" == "1" ]]; then
    echo "tools/pasta/fetch.sh: PASTA_BUILD_FROM_SOURCE=1 — building from source"
    _tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-pasta-fetch.XXXXXX")"
    trap 'rm -rf "$_tmp"' EXIT

    _tarball="passt-${PASTA_VERSION}.tar.gz"
    _url="${PASTA_SOURCE_BASE_URL}/${_tarball}"
    echo "tools/pasta/fetch.sh: fetching source ${_url}"
    _fetch "$_url" "$_tmp/$_tarball"
    tar -xzf "$_tmp/$_tarball" -C "$_tmp"
    _src="$(find "$_tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
    if [[ -z "$_src" ]]; then
        echo "tools/pasta/fetch.sh: failed to locate extracted source dir" >&2
        exit 1
    fi

    echo "tools/pasta/fetch.sh: building pasta from source in $_src"
    if command -v musl-gcc &>/dev/null; then
        make -C "$_src" CC=musl-gcc CFLAGS="-static" pasta 1>&2
    else
        make -C "$_src" CFLAGS="-static" pasta 1>&2
    fi

    install -m 0755 "$_src/pasta" "$_install_path"
    if [[ -f "$_src/LICENSES/BSD-3-Clause.txt" ]]; then
        install -m 0644 "$_src/LICENSES/BSD-3-Clause.txt" "$_license_path"
    fi
else
    _bin_url="${PASTA_BUILD_BASE_URL}/${PASTA_BUILD_TAG}/${_arch}/pasta"
    echo "tools/pasta/fetch.sh: fetching pre-built ${_bin_url}"
    _tmp_bin="$(mktemp "${TMPDIR:-/tmp}/agent-sandbox-pasta-bin.XXXXXX")"
    trap 'rm -f "$_tmp_bin"' EXIT
    _fetch "$_bin_url" "$_tmp_bin"
    if ! file "$_tmp_bin" 2>/dev/null | grep -q "ELF"; then
        echo "tools/pasta/fetch.sh: fetched payload is not an ELF binary — refusing to install" >&2
        exit 1
    fi
    install -m 0755 "$_tmp_bin" "$_install_path"

    if [[ ! -f "$_license_path" ]]; then
        # Pull the BSD-3-Clause text from the matching upstream source snapshot.
        _lic_tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-pasta-lic.XXXXXX")"
        _lic_tar="passt-${PASTA_VERSION}.tar.gz"
        _lic_url="${PASTA_SOURCE_BASE_URL}/${_lic_tar}"
        if _fetch "$_lic_url" "$_lic_tmp/$_lic_tar" 2>/dev/null; then
            tar -xzOf "$_lic_tmp/$_lic_tar" "passt-${PASTA_VERSION}/LICENSES/BSD-3-Clause.txt" \
                > "$_license_path" 2>/dev/null || true
        fi
        rm -rf "$_lic_tmp"
    fi
fi

# Refresh SHA256SUMS with the installed binary's hash.
( cd "$_archdir" && sha256sum pasta > SHA256SUMS )
echo "tools/pasta/fetch.sh: installed $_install_path"
echo "tools/pasta/fetch.sh: $(cat "$_sums_path")"
"$_install_path" --version 2>&1 | grep -v "^Can't" | head -1 || true
