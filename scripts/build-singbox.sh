#!/usr/bin/env bash
# Build upstream sing-box from its release tag with the build tags bosun
# needs (with_v2ray_api for per-user stats). Unmodified upstream source;
# module checksums are verified by the Go toolchain.
#
# usage: scripts/build-singbox.sh <version> <goos> <goarch> [outdir]
# SUFFIX (env, e.g. "-r2") names a rebuild of the same upstream version
# with more tags; the manifest refers to it as <version><suffix>.
set -euo pipefail
VERSION=${1:?version, e.g. 1.14.0}
GOOS=${2:?goos}
GOARCH=${3:?goarch}
OUT=$(mkdir -p "${4:-dist}" && cd "${4:-dist}" && pwd)
TAGS="with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard"

WORK_TMP=$(mktemp -d)
trap 'rm -rf "$WORK_TMP"' EXIT

# go refuses cross-compiled installs into GOBIN, so point a throwaway GOPATH
# at the temp dir and let it use GOPATH/bin/<goos>_<goarch>/. The module
# cache stays the real one (GOMODCACHE) so downloads are shared.
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
cd "$WORK_TMP"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" GOPATH="$WORK_TMP/gopath" GOBIN= GOFLAGS=-mod=mod \
  go install -trimpath -tags "$TAGS" \
    -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${VERSION}" \
    "github.com/sagernet/sing-box/cmd/sing-box@v${VERSION}"

BIN=$(find "$WORK_TMP/gopath/bin" -type f -name 'sing-box*' | head -1)
NAME="sing-box-${VERSION}${SUFFIX:-}-${GOOS}-${GOARCH}"
cp "$BIN" "$OUT/$NAME"
chmod 0755 "$OUT/$NAME"
echo "built $OUT/$NAME"
