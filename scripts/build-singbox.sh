#!/usr/bin/env bash
# Build the reviewed upstream tag with security-only dependency updates.
# Source is temporary and never vendored into bosun.
set -euo pipefail
VERSION=${1:?version}
TARGET_OS=${2:?goos}
TARGET_ARCH=${3:?goarch}
CORE_OUTPUT=$(mkdir -p "${4:-dist}" && cd "${4:-dist}" && pwd)
CORE_SUFFIX=${SUFFIX:--r1}
if [[ "$VERSION" != 1.14.4 || "$CORE_SUFFIX" != -r1 ]]; then
  echo 'Only the reviewed 1.14.4-r1 package can be built by this revision.' >&2
  exit 1
fi
CORE_COMMIT=c005f35300ce76427dc285481ec5695f5b179cd2
CORE_TAGS=with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard
CORE_WORK=$(mktemp -d)
trap 'rm -rf "$CORE_WORK"' EXIT
git clone --quiet --depth 1 --branch "v$VERSION" https://github.com/SagerNet/sing-box.git "$CORE_WORK/source"
test "$(git -C "$CORE_WORK/source" rev-parse HEAD)" = "$CORE_COMMIT"
cd "$CORE_WORK/source"
GOTOOLCHAIN=go1.26.10 GOFLAGS=-mod=mod GOWORK=off go get \
  golang.org/x/crypto@v0.57.0 golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 golang.org/x/mod@v0.41.0 \
  google.golang.org/grpc@v1.83.2 github.com/go-chi/chi/v5@v5.3.0 \
  github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.10 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" GOFLAGS=-mod=readonly GOWORK=off \
  go build -trimpath -buildvcs=false -tags "$CORE_TAGS" \
    -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=$VERSION" \
    -o "$CORE_OUTPUT/sing-box-$VERSION$CORE_SUFFIX-$TARGET_OS-$TARGET_ARCH" ./cmd/sing-box
# Build the scanner for the host; analyze target-platform source, not a
# cross-compiled scanner that cannot execute on the build host.
GOTOOLCHAIN=go1.26.10 GOWORK=off GOBIN="$CORE_WORK/tools" go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.10 GOWORK=off GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
  "$CORE_WORK/tools/govulncheck" -tags "$CORE_TAGS" ./cmd/sing-box
# Include the modified manifests in corresponding source, and keep original
# package identities immutable. All outputs share the same release prefix.
PREFIX="sing-box-$VERSION$CORE_SUFFIX"
git ls-files -z | tar -czf "$CORE_OUTPUT/$PREFIX-source.tar.gz" --null -T -
cp go.mod "$CORE_OUTPUT/$PREFIX-go.mod"
cp go.sum "$CORE_OUTPUT/$PREFIX-go.sum"
cp LICENSE "$CORE_OUTPUT/$PREFIX-LICENSE.txt"
cat > "$CORE_OUTPUT/$PREFIX-BUILD.txt" <<'BUILD'
Distribution: SagerNet/sing-box
Upstream: https://github.com/SagerNet/sing-box
Tag: v1.14.4
Commit: c005f35300ce76427dc285481ec5695f5b179cd2
Package: 1.14.4-r1
Compiler: Go 1.26.10, CGO_ENABLED=0
Build: go build -trimpath -buildvcs=false
Tags: with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard
Linker: -s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4
Dependencies: golang.org/x/crypto@v0.57.0 golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 golang.org/x/mod@v0.41.0 google.golang.org/grpc@v1.83.2 github.com/go-chi/chi/v5@v5.3.0 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2
Source: upstream Go sources unchanged; go.mod/go.sum updated with the pins above. Corresponding source archive, resolved module manifests and GPL license included.
Activation: caution package; unpinned installations retain the compatible default. Correct duplicate outbound-group members and explicitly activate through core management. Download alone does not activate it.
BUILD
