#!/usr/bin/env bash
# Build upstream Xray-core from its release tag with the flags upstream's own
# release workflow uses. XRAY_SECURITY_DEPS=2026-10 additionally updates
# vetted module versions; upstream Go source remains unchanged. Module
# checksums are verified by the Go toolchain.
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
case "${XRAY_SECURITY_DEPS:-}" in
  "") ;;
  2026-10)
    GOWORK=off go get golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.61.0 \
      golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.84.0 \
      github.com/klauspost/compress@v1.18.7
    ;;
  *) echo "unknown Xray security dependency profile" >&2; exit 1 ;;
esac
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build -o "$WORK_TMP/xray" -trimpath -buildvcs=false -gcflags="all=-l=4" \
    -ldflags "-X github.com/xtls/xray-core/core.build=${XRAY_COMMIT:-} -s -w -buildid=" ./main

BIN="$WORK_TMP/xray"
NAME="xray-${VERSION}${SUFFIX:-}-${GOOS}-${GOARCH}"
cp "$BIN" "$OUT/$NAME"
chmod 0755 "$OUT/$NAME"
if [[ "$GOOS" == linux && "$GOARCH" == amd64 && -n "${XRAY_SECURITY_DEPS:-}" ]]; then
  # Stripped binary scanning overreports package-wide advisories. Analyze
  # the exact build source and dependency graph before publishing it.
  GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./main
  cp go.mod "$OUT/XRAY-go.mod"
  cp go.sum "$OUT/XRAY-go.sum"
  cp LICENSE "$OUT/XRAY-LICENSE.txt"
  git rev-parse HEAD > "$OUT/XRAY-SOURCE-COMMIT.txt"
fi
echo "built $OUT/$NAME"
