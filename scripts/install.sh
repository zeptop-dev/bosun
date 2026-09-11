#!/bin/sh
# bosun installer for Linux (systemd). Usage:
#   sh install.sh --captain https://captain.example.com --pair ABCD-EFGH [--version v0.3.1]
# Re-running upgrades the binary and keeps /etc/bosun/config.yaml.
set -eu

PROJECT="boyang-hu%2Fbosun"
API="https://gitlab.com/api/v4/projects/$PROJECT"
CAPTAIN="" PAIR="" VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --captain) CAPTAIN="$2"; shift 2 ;;
    --pair) PAIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "$API/releases?per_page=1" | sed -n 's/.*"tag_name":"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || { echo "could not determine the latest release" >&2; exit 1; }
fi
BASE="$API/packages/generic/bosun/$VERSION"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo "downloading bosun $VERSION ($ARCH)"
curl -fsSL -o "$TMP/bosun" "$BASE/bosun-linux-$ARCH"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
WANT=$(grep " bosun-linux-$ARCH\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
GOT=$(sha256sum "$TMP/bosun" | cut -d' ' -f1)
[ "$WANT" = "$GOT" ] || { echo "checksum mismatch: want $WANT got $GOT" >&2; exit 1; }
install -m 0755 "$TMP/bosun" /usr/local/bin/bosun

mkdir -p /etc/bosun /var/lib/bosun
if [ ! -f /etc/bosun/config.yaml ]; then
  [ -n "$CAPTAIN" ] && [ -n "$PAIR" ] || { echo "--captain and --pair are required on first install" >&2; exit 1; }
  cat > /etc/bosun/config.yaml <<CFG
data_dir: /var/lib/bosun
log_level: info
metrics_listen: 127.0.0.1:9100

cores:
  order: [singbox, xray, mita, hysteria]
  singbox: { stats_listen: 127.0.0.1:9101, log_level: warn }
  xray: { version: "26.3.27", api_listen: 127.0.0.1:9102, log_level: warning }
  mita: { log_level: INFO }
  hysteria: { auth_listen: 127.0.0.1:9103, stats_listen: 127.0.0.1:9104, log_level: warn }

panel:
  driver: captain
  captain:
    url: $CAPTAIN
    pair_code: $PAIR
CFG
  chmod 0600 /etc/bosun/config.yaml
  echo "wrote /etc/bosun/config.yaml"
fi

curl -fsSL -o /etc/systemd/system/bosun.service "https://gitlab.com/boyang-hu/bosun/-/raw/$VERSION/deploy/bosun.service"
systemctl daemon-reload
systemctl enable --now bosun
systemctl restart bosun
sleep 2
systemctl --no-pager --lines=5 status bosun || true
echo "bosun $VERSION installed. Logs: journalctl -u bosun -f"
