#!/usr/bin/env bash
# Build upstream Xray-core from its release tag with the flags upstream's own
# release workflow uses, so the binary differs from the official one only in
# the Go toolchain it was compiled with (the official builds lag behind Go
# security releases). Unmodified upstream source; module checksums are
# verified by the Go toolchain.
#
# usage: scripts/build-xray.sh <version> <goos> <goarch> [outdir]
# SUFFIX (env, e.g. "-r1") names the rebuild; the manifest refers to it as
# <version><suffix>. XRAY_COMMIT (env) is stamped into `xray version`, as
# upstream does.
set -euo pipefail
VERSION=${1:?version, e.g. 26.3.27}
GOOS=${2:?goos}
GOARCH=${3:?goarch}
OUT=$(mkdir -p "${4:-dist}" && cd "${4:-dist}" && pwd)

WORK_TMP=$(mktemp -d)
trap 'rm -rf "$WORK_TMP"' EXIT

# Xray's module path has no /v26 suffix, so its tags are not valid module
# versions for "go install pkg@version": build from a checkout of the tag,
# as upstream does. Dependencies are still verified against its go.sum.
git -c advice.detachedHead=false clone -q --depth 1 --branch "v${VERSION}" https://github.com/XTLS/Xray-core "$WORK_TMP/src"
cd "$WORK_TMP/src"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build -o "$WORK_TMP/xray" -trimpath -buildvcs=false -gcflags="all=-l=4" \
    -ldflags "-X github.com/xtls/xray-core/core.build=${XRAY_COMMIT:-} -s -w -buildid=" ./main

BIN="$WORK_TMP/xray"
NAME="xray-${VERSION}${SUFFIX:-}-${GOOS}-${GOARCH}"
cp "$BIN" "$OUT/$NAME"
chmod 0755 "$OUT/$NAME"
echo "built $OUT/$NAME"
