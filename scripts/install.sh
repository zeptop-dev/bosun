#!/bin/sh
# bosun installer for Linux (systemd). Usage:
#   sh install.sh                                   standalone: web panel on :2053
#   sh install.sh --captain https://captain.example.com --pair ABCD-EFGH
#   sh install.sh --version v0.4.0 [--web-listen 127.0.0.1:2053]
#   sh install.sh uninstall [--keep-data]     remove the service, binary, config (and data)
# Re-running upgrades the binary and keeps /etc/bosun/config.yaml. Piped
# through sh the script never touches the disk.
set -eu

REPO="zeptop-dev/bosun"
CAPTAIN="" PAIR="" VERSION="" WEB_LISTEN=":2053" ACTION=install KEEP_DATA=0
while [ $# -gt 0 ]; do
  case "$1" in
    uninstall) ACTION=uninstall; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --captain) CAPTAIN="$2"; shift 2 ;;
    --pair) PAIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --web-listen) WEB_LISTEN="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

if [ "$ACTION" = uninstall ]; then
  echo "This stops bosun and its cores and removes /usr/local/bin/bosun, /etc/bosun$( [ "$KEEP_DATA" = 1 ] || echo ' and /var/lib/bosun (cores, certificates, local state)')."
  if [ -r /dev/tty ]; then printf 'Type yes to continue: ' >/dev/tty; read -r ans </dev/tty; [ "$ans" = yes ] || { echo "aborted"; exit 1; }; fi
  systemctl disable --now bosun 2>/dev/null || true
  rm -f /etc/systemd/system/bosun.service; systemctl daemon-reload
  rm -rf /usr/local/bin/bosun /usr/local/bin/bosun.backup /usr/local/bin/bosun.backup.version /etc/bosun
  [ "$KEEP_DATA" = 1 ] || rm -rf /var/lib/bosun
  echo "bosun removed."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || { echo "could not determine the latest release" >&2; exit 1; }
fi
BASE="https://github.com/$REPO/releases/download/$VERSION"
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
  if [ -n "$CAPTAIN" ] && [ -z "$PAIR" ] || [ -z "$CAPTAIN" ] && [ -n "$PAIR" ]; then
    echo "--captain and --pair go together" >&2; exit 1
  fi
  if [ -n "$CAPTAIN" ]; then
    PANEL="panel:
  driver: captain
  captain:
    url: $CAPTAIN
    pair_code: $PAIR"
  else
    PANEL="panel:
  driver: local

web:
  listen: \"$WEB_LISTEN\""
  fi
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

$PANEL
CFG
  chmod 0600 /etc/bosun/config.yaml
  echo "wrote /etc/bosun/config.yaml"
fi

curl -fsSL -o /etc/systemd/system/bosun.service "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.service"
systemctl daemon-reload
systemctl enable --now bosun
systemctl restart bosun
sleep 2
systemctl --no-pager --lines=5 status bosun || true
echo "bosun $VERSION installed. Logs: journalctl -u bosun -f"
if [ -z "$CAPTAIN" ]; then
  echo
  echo "web panel: http://<this-server>${WEB_LISTEN}/"
  echo "login:"
  journalctl -u bosun --no-pager -o cat 2>/dev/null | grep -o 'username=[^ ]* password=[^ ]*' | tail -1 || true
  echo "(lost it? run: bosun admin reset-password)"
fi
