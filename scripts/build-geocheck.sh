#!/bin/sh
# Rebuild the MIT-licensed diagnostic tool from an immutable upstream tag.
# Keep it a separate executable: it is never linked into a proxy core.
set -eu
script_root=$(cd "$(dirname "$0")/.." && pwd)
GOTOOLCHAIN=$(awk '$1 == "toolchain" { print $2 }' "$script_root/go.mod")
export GOTOOLCHAIN
[ -n "$GOTOOLCHAIN" ] || { echo "missing pinned Go toolchain" >&2; exit 1; }
out=${1:-bin}
mkdir -p "$out"
out=$(cd "$out" && pwd)
module=github.com/remnawave/geocheck
version=v0.3.0
cached_source=$(go mod download -json "$module@$version" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
# Keep the downloaded module cache immutable; update only the reviewed
# dependency needed by the HTTP/2 and HTML parser/renderer security fixes
# in a temporary copy (GO-2026-6860 and GO-2026-6866).
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT
cp -R "$cached_source/." "$source_dir/"
chmod -R u+w "$source_dir"
go -C "$source_dir" get golang.org/x/net@v0.62.0
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOFLAGS=-mod=readonly \
    go build -C "$source_dir" -trimpath \
    -ldflags "-s -w -X $module/internal/version.Version=$version-bosun" \
    -o "$out/geocheck-linux-$arch" ./cmd/geocheck
  go version "$out/geocheck-linux-$arch"
  go version "$out/geocheck-linux-$arch" | grep -q "$GOTOOLCHAIN$" || exit 1
done

cp "$script_root/licenses/geocheck-MIT.txt" "$out/geocheck-LICENSE.txt"
