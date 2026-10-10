#!/bin/sh
# bosun installer for Linux (systemd, or OpenRC on Alpine). Usage:
#   sh install.sh                                   standalone: asks for the panel login and port
#   sh install.sh --yes                             standalone with defaults (admin / random / :2053)
#   sh install.sh --captain https://captain.example.com --pair ABCD-EFGH
#   sh install.sh --version v0.4.0 [--web-listen 127.0.0.1:2053] [--user U] [--password P]
#   sh install.sh uninstall [--keep-data]     remove the service, binary, config (and data)
#   sh install.sh upgrade [--version vX.Y.Z]
#   sh install.sh --mode docker [--web-upgrade]
#   sh install.sh enable-web-upgrade
# Re-running upgrades the binary and keeps /etc/bosun/config.yaml. Piped
# through sh the script never touches the disk.
set -eu

# have_tty says whether the script can actually reach a terminal. /dev/tty
# exists and passes [ -r ] even under "ssh host 'curl … | sh'", where
# opening it fails with ENXIO ("cannot create /dev/tty"), so the only
# honest test is to open it — in a subshell, because a redirection that
# fails on a special built-in ends the whole shell under POSIX sh.
# Without a terminal, questions are skipped and anything still missing
# has to come from a flag.
have_tty() { ( exec 3>/dev/tty ) 2>/dev/null; }

PRODUCT=bosun NATIVE=/usr/local/bin/bosun MODE="" WEB_UPGRADE=0
REPO="zeptop-dev/bosun"
CAPTAIN="" PAIR="" VERSION="" WEB_LISTEN="" ACTION=install KEEP_DATA=0 YES=0 PANEL_USER="" PANEL_PASS=""
while [ $# -gt 0 ]; do
  case "$1" in
    install|upgrade|uninstall|enable-web-upgrade) ACTION="$1"; shift ;;
    --web-upgrade) WEB_UPGRADE=1; shift ;;
    --mode) MODE="$2"; shift 2 ;;
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
[ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# Lifecycle commands never re-run installation prompts or rewrite deployment settings.
resolve_version() {
  if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  fi
  printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'invalid release version' >&2; exit 1; }
}
download_worker() {
  command -v curl >/dev/null || { echo 'curl is required to download the release' >&2; exit 1; }
  resolve_version
  case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo 'unsupported architecture' >&2; exit 1 ;; esac
  BASE="https://github.com/$REPO/releases/download/$VERSION"
  curl -fsSL -o "$TMP/$PRODUCT" "$BASE/$PRODUCT-linux-$ARCH"
  curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
  WANT=$(awk -v file="$PRODUCT-linux-$ARCH" '$2 == file {print $1}' "$TMP/SHA256SUMS")
  GOT=$(sha256sum "$TMP/$PRODUCT" | cut -d' ' -f1)
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo 'checksum mismatch' >&2; exit 1; }
  chmod 0755 "$TMP/$PRODUCT"
  WORKER="$TMP/$PRODUCT"
}
prepare_worker() {
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
  candidate="/usr/local/lib/$PRODUCT-updater/worker"
  if [ -x "$candidate" ] && [ ! -L "$candidate" ] && [ "$(stat -c %u "$candidate")" = 0 ] && [ "$("$candidate" installer-version 2>/dev/null || true)" = 1 ]; then
    cp "$candidate" "$TMP/$PRODUCT"; chmod 0755 "$TMP/$PRODUCT"; WORKER="$TMP/$PRODUCT"; return
  fi
  download_worker
}
native_command() {
  if [ "$PRODUCT" = captain ]; then runuser -u captain -- "$NATIVE" "$@"
  else "$NATIVE" "$@"; fi
}
if [ "$ACTION" = uninstall ]; then
  echo "Remove $PRODUCT containers, service, binaries, configuration, database, backups and certificates. Shared Docker and unrelated applications are preserved."
  if [ "$YES" != 1 ]; then
    have_tty || { echo 'pass --yes to confirm uninstall without a terminal' >&2; exit 1; }
    printf 'Type yes to permanently uninstall: ' >/dev/tty; read -r ans </dev/tty
    [ "$ans" = yes ] || { echo 'aborted'; exit 1; }
  fi
  prepare_worker
  if [ "$KEEP_DATA" = 1 ]; then "$WORKER" uninstall --yes --keep-data; else "$WORKER" uninstall --yes; fi
  exit 0
fi
if [ "$ACTION" = upgrade ] || [ "$ACTION" = enable-web-upgrade ]; then
  if [ -z "$MODE" ]; then
    if [ -f "/opt/$PRODUCT/docker-compose.yml" ] || [ -f "/opt/$PRODUCT/docker-compose.yaml" ] || [ -f "/opt/$PRODUCT/compose.yml" ] || [ -f "/opt/$PRODUCT/compose.yaml" ]; then MODE=docker
    elif [ -x "$NATIVE" ]; then MODE=binary
    else echo 'no existing installation found; install first' >&2; exit 1; fi
  fi
  case "$MODE" in docker|binary) ;; *) echo '--mode must be docker or binary' >&2; exit 1 ;; esac
  prepare_worker
  if [ "$MODE" = docker ]; then
    # One-time registration is also available to old Docker installations.
    if [ "$ACTION" = enable-web-upgrade ] || ! "$WORKER" docker-updater status >/dev/null 2>&1; then
      "$WORKER" docker-updater setup --dir "/opt/$PRODUCT"
    fi
    if [ "$ACTION" = upgrade ]; then
      resolve_version
      "$WORKER" docker-updater upgrade --version "$VERSION"
      echo "Upgrade queued. Status: /usr/local/lib/$PRODUCT-updater/worker docker-updater status"
    fi
  else
    [ "$ACTION" = upgrade ] || { echo 'binary installations already support web updates' >&2; exit 1; }
    # Stage and verify the new release before stopping the existing service.
    download_worker
    "$WORKER" installer-check-layout "/etc/$PRODUCT/config.yaml"
    CURRENT=$(native_command version | awk '{print $2}')
    "$WORKER" installer-check-upgrade "$CURRENT" || { echo 'target must be a newer release' >&2; exit 1; }
    install -m 0755 "$WORKER" "$TMP/next"
    if [ "$PRODUCT" = captain ]; then chown captain:captain "$TMP/next"; fi
    mkdir -p "/var/lib/$PRODUCT-updater/backups"
    chmod 0700 "/var/lib/$PRODUCT-updater" "/var/lib/$PRODUCT-updater/backups"
    BACKUP="/var/lib/$PRODUCT-updater/backups/binary-$(date +%Y%m%d%H%M%S)"
    mkdir -m 0700 "$BACKUP"
    cp -p "$NATIVE" "$TMP/previous"
    printf '%s\n' "$CURRENT" > "$TMP/previous.version"
    if command -v systemctl >/dev/null; then systemctl stop "$PRODUCT"; INIT=systemd
    else rc-service "$PRODUCT" stop; INIT=openrc; fi
    resume_old() { if [ "$INIT" = systemd ]; then systemctl start "$PRODUCT"; else rc-service "$PRODUCT" start; fi; }
    if ! tar -czf "$BACKUP/data.tar.gz" -C / "etc/$PRODUCT" "var/lib/$PRODUCT"; then resume_old; echo 'backup failed; old service restarted' >&2; exit 1; fi
    if ! { mv -T "$TMP/previous" "$NATIVE.backup" && mv -T "$TMP/previous.version" "$NATIVE.backup.version" && mv -T "$TMP/next" "$NATIVE"; }; then
      resume_old; echo 'binary replacement failed; existing service restarted' >&2; exit 1
    fi
    resume_old
    READY=0
    for _attempt in 1 2 3 4 5 6 7 8 9 10; do
      if native_command healthcheck --version "$VERSION" >/dev/null 2>&1; then READY=1; break; fi
      sleep 2
    done
    [ "$READY" = 1 ] || { echo "New service did not become ready. Data backup: $BACKUP. No automatic database downgrade was attempted." >&2; exit 1; }
    echo "$PRODUCT $VERSION installed. Pre-upgrade data: $BACKUP. Service configuration was preserved."
  fi
  exit 0
fi

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
# Binary mode uses the host init system; Docker installation does not require it.
MODE=${MODE:-binary}
case "$MODE" in docker|binary) ;; *) echo '--mode must be docker or binary' >&2; exit 1 ;; esac
if [ "$MODE" = binary ]; then
  if command -v systemctl >/dev/null; then INIT=systemd
  elif command -v rc-service >/dev/null; then INIT=openrc
  else echo 'systemd or OpenRC is required' >&2; exit 1; fi
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
if [ "$MODE" = binary ]; then install -m 0755 "$TMP/bosun" /usr/local/bin/bosun.new; mv /usr/local/bin/bosun.new /usr/local/bin/bosun; fi

# nft and tc back the per-user speed limits, nft forwards and strict
# ingress; minimal images (Debian cloud, Alpine) ship without them. Best
# effort: bosun runs without them and the doctor says what is missing.
if [ "$MODE" = binary ] && { ! command -v nft >/dev/null || ! command -v tc >/dev/null; }; then
  echo "installing nftables and iproute2 (speed limits, nft forwards, strict ingress)"
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables iproute2 >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  elif command -v apk >/dev/null; then
    apk add -q nftables iproute2 >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  elif command -v dnf >/dev/null; then
    dnf install -y -q nftables iproute-tc >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  fi
fi

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
  if [ "$YES" = 0 ] && have_tty; then
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
  [ -n "$PANEL_USER" ] || PANEL_USER="admin"
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
  user: bosun-proxy   # cores run unprivileged (created on first start); egress to private/metadata ranges is dropped
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

if [ "$MODE" = docker ]; then
  docker compose version >/dev/null || { echo 'Docker Compose is required' >&2; exit 1; }
  mkdir -p /opt/bosun
  if [ ! -f /opt/bosun/docker-compose.yml ]; then
    cat > /opt/bosun/docker-compose.yml <<YAML
services:
  bosun:
    image: zeptop/bosun:$VERSION
    restart: unless-stopped
    network_mode: host
    stop_grace_period: 60s
    volumes:
      - /etc/bosun/config.yaml:/etc/bosun/config.yaml:ro
      - bosun-data:/var/lib/bosun
volumes:
  bosun-data:
YAML
  fi
  cd /opt/bosun
  docker compose pull bosun
  if [ "$FIRST_INSTALL" = 1 ] && [ -z "$CAPTAIN" ]; then
    docker compose run --rm --no-deps bosun admin set -user "$PANEL_USER" -password "$PANEL_PASS"
  fi
  docker compose up -d bosun
  if [ "$WEB_UPGRADE" = 1 ]; then "$TMP/bosun" docker-updater setup --dir /opt/bosun; fi
  echo 'bosun installed with Docker. Manage: cd /opt/bosun && docker compose logs -f'
  exit 0
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
