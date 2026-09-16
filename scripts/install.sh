#!/bin/sh
# bosun installer for Linux (systemd, or OpenRC on Alpine). Usage:
#   sh install.sh                                   standalone: asks for the panel login and port
#   sh install.sh --yes                             standalone with defaults (admin / random / :2053)
#   sh install.sh --captain https://captain.example.com --pair ABCD-EFGH
#   sh install.sh --version v0.4.0 [--web-listen 127.0.0.1:2053] [--user U] [--password P]
#   sh install.sh uninstall [--keep-data]     remove the service, binary, config (and data)
# Re-running upgrades the binary and keeps /etc/bosun/config.yaml. Piped
# through sh the script never touches the disk.
set -eu

REPO="zeptop-dev/bosun"
CAPTAIN="" PAIR="" VERSION="" WEB_LISTEN="" ACTION=install KEEP_DATA=0 YES=0 PANEL_USER="" PANEL_PASS=""
while [ $# -gt 0 ]; do
  case "$1" in
    uninstall) ACTION=uninstall; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --captain) CAPTAIN="$2"; shift 2 ;;
    --pair) PAIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --web-listen) WEB_LISTEN="$2"; shift 2 ;;
    --user) PANEL_USER="$2"; shift 2 ;;
    --password) PANEL_PASS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
# Init system: systemd, or OpenRC (Alpine).
if command -v systemctl >/dev/null; then INIT=systemd
elif command -v rc-service >/dev/null; then INIT=openrc
else echo "systemd or OpenRC is required" >&2; exit 1; fi

if [ "$ACTION" = uninstall ]; then
  echo "This stops bosun and its cores and removes /usr/local/bin/bosun, /etc/bosun$( [ "$KEEP_DATA" = 1 ] || echo ' and /var/lib/bosun (cores, certificates, local state)')."
  if [ -r /dev/tty ]; then printf 'Type yes to continue: ' >/dev/tty; read -r ans </dev/tty; [ "$ans" = yes ] || { echo "aborted"; exit 1; }; fi
  if [ "$INIT" = systemd ]; then
    systemctl disable --now bosun 2>/dev/null || true
    rm -f /etc/systemd/system/bosun.service; systemctl daemon-reload
  else
    rc-service bosun stop 2>/dev/null || true
    rc-update del bosun default 2>/dev/null || true
    rm -f /etc/init.d/bosun
  fi
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

# ask prints a prompt on the terminal and reads the answer from /dev/tty, so
# the questions work even when the script itself arrives through a pipe.
ask() { printf '%s' "$1" >/dev/tty; read -r ans </dev/tty || ans=""; }
ask_secret() {
  printf '%s' "$1" >/dev/tty
  stty -echo </dev/tty 2>/dev/null || true
  read -r ans </dev/tty || ans=""
  stty echo </dev/tty 2>/dev/null || true
  printf '\n' >/dev/tty
}
random_port() { awk 'BEGIN{srand(); print 20000+int(rand()*40000)}'; }

FIRST_INSTALL=0
[ -f /etc/bosun/config.yaml ] || FIRST_INSTALL=1
if [ "$FIRST_INSTALL" = 1 ] && [ -z "$CAPTAIN" ]; then
  # Standalone: choose the panel login and port. Piped or --yes: defaults.
  if [ "$YES" = 0 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    echo "Standalone web panel setup (Enter keeps the default):"
    [ -n "$PANEL_USER" ] || { ask "  panel username [admin]: "; PANEL_USER="$ans"; }
    if [ -z "$PANEL_PASS" ]; then
      ask_secret "  panel password [blank = random]: "; PANEL_PASS="$ans"
      if [ -n "$PANEL_PASS" ]; then
        ask_secret "  repeat password: "
        [ "$ans" = "$PANEL_PASS" ] || { echo "passwords differ" >&2; exit 1; }
        [ "${#PANEL_PASS}" -ge 8 ] || { echo "password must be at least 8 characters" >&2; exit 1; }
      fi
    fi
    if [ -z "$WEB_LISTEN" ]; then
      ask "  panel port [2053; r = random]: "
      case "$ans" in
        "") WEB_LISTEN=":2053" ;;
        r|R) WEB_LISTEN=":$(random_port)" ;;
        *) case "$ans" in *[!0-9]*) echo "port must be a number" >&2; exit 1 ;; esac; WEB_LISTEN=":$ans" ;;
      esac
    fi
  fi
  [ -n "$PANEL_USER" ] || PANEL_USER=admin
  [ -n "$WEB_LISTEN" ] || WEB_LISTEN=":2053"
fi
[ -n "$WEB_LISTEN" ] || WEB_LISTEN=":2053"

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
  # snell: {}   # Surge snell-server (closed source, downloaded from Surge on first start); needed for snell inbounds

$PANEL
CFG
  chmod 0600 /etc/bosun/config.yaml
  echo "wrote /etc/bosun/config.yaml"
fi

# Seed the panel login before the first start so the password is known
# here instead of buried in the journal.
LOGIN=""
if [ "$FIRST_INSTALL" = 1 ] && [ -z "$CAPTAIN" ]; then
  if [ -n "$PANEL_PASS" ]; then
    LOGIN=$(/usr/local/bin/bosun admin set -c /etc/bosun/config.yaml -user "$PANEL_USER" -password "$PANEL_PASS" | tr '\n' ' ')
  else
    LOGIN=$(/usr/local/bin/bosun admin set -c /etc/bosun/config.yaml -user "$PANEL_USER" | tr '\n' ' ')
  fi
fi

if [ "$INIT" = systemd ]; then
  curl -fsSL -o /etc/systemd/system/bosun.service "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.service"
  systemctl daemon-reload
  systemctl enable --now bosun
  systemctl restart bosun
  sleep 2
  systemctl --no-pager --lines=5 status bosun || true
  echo "bosun $VERSION installed. Logs: journalctl -u bosun -f"
else
  curl -fsSL -o /etc/init.d/bosun "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.initd"
  chmod 0755 /etc/init.d/bosun
  rc-update add bosun default >/dev/null 2>&1 || true
  rc-service bosun restart || rc-service bosun start
  sleep 2
  rc-service bosun status || true
  echo "bosun $VERSION installed. Logs: tail -f /var/log/bosun.log"
fi
if [ -z "$CAPTAIN" ]; then
  echo
  PORT=$(grep -E '^\s*listen:' /etc/bosun/config.yaml | sed -n 's/.*listen: *"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' | head -1)
  [ -n "$PORT" ] || PORT="$WEB_LISTEN"
  echo "web panel: http://<this-server>${PORT}/"
  if [ -n "$LOGIN" ]; then
    echo "login: $LOGIN"
  else
    echo "login: unchanged (existing install); set a new one with: bosun admin set -c /etc/bosun/config.yaml -user admin -password ..."
  fi
  echo "(lost it? run: bosun admin reset-password -c /etc/bosun/config.yaml)"
fi
