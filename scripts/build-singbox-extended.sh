#!/usr/bin/env bash
# Build the pinned fork with vetted dependency updates and the statistics API required by
# bosun. GPL source is fetched into a temporary checkout, never vendored here.
set -euo pipefail
TARGET_OS=${1:?goos}
TARGET_ARCH=${2:?goarch}
CORE_OUTPUT=$(mkdir -p "${3:-dist}" && cd "${3:-dist}" && pwd)
CORE_TAG=v1.14.1-extended-2.7.2
CORE_COMMIT=55faa763f986f4ca8a492d9b2719bc6330d2bef5
CORE_WORK=$(mktemp -d)
trap 'rm -rf "$CORE_WORK"' EXIT
git clone --quiet --depth 1 --branch "$CORE_TAG" https://github.com/shtorm-7/sing-box-extended.git "$CORE_WORK/source"
test "$(git -C "$CORE_WORK/source" rev-parse HEAD)" = "$CORE_COMMIT"
cd "$CORE_WORK/source"
GOTOOLCHAIN=go1.26.11 GOFLAGS=-mod=mod GOWORK=off go get \
  golang.org/x/crypto@v0.57.0 golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 golang.org/x/mod@v0.41.0 \
  google.golang.org/grpc@v1.83.2 github.com/go-chi/chi/v5@v5.3.0 \
  github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2
CGO_ENABLED=0 GOTOOLCHAIN=go1.26.11 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false \
    -tags with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard \
    -ldflags '-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14.1-extended-2.7.2' \
    -o "$CORE_OUTPUT/sing-box-extended-$TARGET_OS-$TARGET_ARCH" ./cmd/sing-box
# Binary-only scanning overreports package-wide advisories from modules in
# stripped Go binaries. Analyze the exact source and build tags as well.
if [[ "$TARGET_OS" == linux && "$TARGET_ARCH" == amd64 ]]; then
  GOTOOLCHAIN=go1.26.11 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 \
    -tags with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard ./cmd/sing-box
fi
git ls-files -z | tar -czf "$CORE_OUTPUT/sing-box-extended-source.tar.gz" --null -T -
cp LICENSE "$CORE_OUTPUT/sing-box-extended-LICENSE.txt"
cat > "$CORE_OUTPUT/sing-box-extended-BUILD.txt" <<'EOF'
Distribution: shtorm-7/sing-box-extended
Upstream: https://github.com/shtorm-7/sing-box-extended
Tag: v1.14.1-extended-2.7.2
Commit: 55faa763f986f4ca8a492d9b2719bc6330d2bef5
Package: 1.14.1-extended-2.7.2-r5
Compiler: Go 1.26.11, CGO_ENABLED=0
Build: go build -trimpath -buildvcs=false
Tags: with_quic,with_utls,with_clash_api,with_v2ray_api,with_gvisor,with_acme,with_wireguard
Linker: -s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14.1-extended-2.7.2
Dependencies: golang.org/x/crypto@v0.57.0 golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 golang.org/x/mod@v0.41.0 google.golang.org/grpc@v1.83.2 github.com/go-chi/chi/v5@v5.3.0 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2
Source: upstream Go sources unchanged; go.mod/go.sum updated with the pins above. Corresponding source archive, updated module manifests and GPL license included.
EOF
