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

PRODUCT=bosun NATIVE=/usr/local/bin/bosun MODE="" WEB_UPGRADE=0 NODE_MODE=full
REPO="zeptop-dev/bosun"
SAVED_DOWNLOADS_KNOWN=0 TOKEN_FILE_SET=0
DOWNLOAD_SOURCE="" TOKEN_FILE="/var/lib/bosun/captain.token"
CAPTAIN="" PAIR="" VERSION="" WEB_LISTEN="" ACTION=install KEEP_DATA=0 YES=0 PANEL_USER="" PANEL_PASS=""
while [ $# -gt 0 ]; do
  case "$1" in
    install|upgrade|uninstall|enable-web-upgrade) ACTION="$1"; shift ;;
    --monitor-only) NODE_MODE=monitor; shift ;;
    --web-upgrade) WEB_UPGRADE=1; shift ;;
    --mode) MODE="$2"; shift 2 ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --captain) CAPTAIN="$2"; shift 2 ;;
    --download-source) DOWNLOAD_SOURCE="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; TOKEN_FILE_SET=1; shift 2 ;;
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

# An offline uninstall can use the trusted local worker even when the running
# application's config is unreadable. Copy before executing its capability
# check so the same private file is used for the eventual uninstall.
trusted_worker_file() {
  [ -f "$1" ] && [ -x "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1" 2>/dev/null)" = 0 ] || return 1
  worker_mode=$(stat -c %a "$1" 2>/dev/null) || return 1
  case "$worker_mode" in ''|*[!0-7]*|*[2367][0-7]|*[2367]) return 1 ;; esac
}
copy_cached_worker() {
  candidate="/usr/local/lib/$PRODUCT-updater/worker"
  trusted_worker_file "$candidate" || return 1
  # Preserve owner/mode and symlinks while copying, then verify the private
  # copy too: a changed source cannot become trusted merely because root
  # created the destination file.
  if ! cp -pP "$candidate" "$TMP/$PRODUCT" || ! trusted_worker_file "$TMP/$PRODUCT" || ! chmod 0755 "$TMP/$PRODUCT"; then rm -f "$TMP/$PRODUCT"; return 1; fi
  if [ "$("$TMP/$PRODUCT" installer-version 2>/dev/null || true)" != 1 ]; then rm -f "$TMP/$PRODUCT"; return 1; fi
  WORKER="$TMP/$PRODUCT"
}

confirm_uninstall() {
  echo "Remove $PRODUCT containers, service, binaries, configuration, database, backups and certificates. Shared Docker and unrelated applications are preserved."
  if [ "$YES" != 1 ]; then
    have_tty || { echo 'pass --yes to confirm uninstall without a terminal' >&2; exit 1; }
    printf 'Type yes to permanently uninstall: ' >/dev/tty; read -r ans </dev/tty
    [ "$ans" = yes ] || { echo 'aborted'; exit 1; }
  fi
}
run_uninstall() {
  if [ "$KEEP_DATA" = 1 ]; then "$WORKER" uninstall --yes --keep-data; else "$WORKER" uninstall --yes; fi
}
if [ "$ACTION" = uninstall ]; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
  if copy_cached_worker; then
    confirm_uninstall
    run_uninstall
    exit 0
  fi
  rm -rf "$TMP"
  unset TMP
  trap - EXIT HUP INT TERM
  # No usable private worker: continue the normal, strict source/config
  # validation below. Never infer GitHub from a failed config read.
fi

# A current native installation can describe its configuration without shell
# evaluation or parsing YAML. Old binaries do not have this command.
if [ -x "$NATIVE" ] && [ -f /etc/bosun/config.yaml ]; then
  if saved_downloads=$("$NATIVE" installer-download-config /etc/bosun/config.yaml 2>/dev/null); then
    SAVED_DOWNLOADS_KNOWN=1
    saved_source=$(printf '%s\n' "$saved_downloads" | sed -n '1p')
    saved_url=$(printf '%s\n' "$saved_downloads" | sed -n '2p')
    saved_token_file=$(printf '%s\n' "$saved_downloads" | sed -n '3p')
    [ -n "$DOWNLOAD_SOURCE" ] || DOWNLOAD_SOURCE=$saved_source
    [ -n "$CAPTAIN" ] || CAPTAIN=$saved_url
    if [ "$TOKEN_FILE_SET" != 1 ] && [ -n "$saved_token_file" ]; then TOKEN_FILE=$saved_token_file; fi
  elif [ -z "$DOWNLOAD_SOURCE" ]; then
    # Only releases predating this option can safely retain the historical
    # GitHub default when they do not understand the read-only helper.
    current_version=$("$NATIVE" version 2>/dev/null | awk '{print $2}')
    if ! printf '%s\n' "$current_version" | grep -Eq '^v0\.[0-9]+\.[0-9]+$' || ! printf '%s\n' "$current_version" | awk -F. '{exit !(($2+0)<89)}'; then
      echo 'Cannot read existing download configuration; refusing to guess a download source.' >&2; exit 1
    fi
  fi
fi
DOWNLOAD_SOURCE=${DOWNLOAD_SOURCE:-github}
case "$DOWNLOAD_SOURCE" in github|captain) ;; *) echo '--download-source must be github or captain' >&2; exit 1 ;; esac
if [ "$DOWNLOAD_SOURCE" = captain ]; then
  case "$CAPTAIN" in https://*) ;; *) echo 'Captain downloads require an HTTPS --captain endpoint' >&2; exit 1 ;; esac
  printf '%s\n' "$CAPTAIN" | LC_ALL=C grep -Eq '^https://(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?/?$' || { echo 'invalid Captain download endpoint' >&2; exit 1; }
  case "$CAPTAIN" in */../*|*/./*|*/..|*/.) echo 'invalid Captain download endpoint path' >&2; exit 1 ;; esac
  CAPTAIN=${CAPTAIN%/}
  if [ "$SAVED_DOWNLOADS_KNOWN" = 1 ] && [ -n "$saved_url" ] && [ "${saved_url%/}" != "$CAPTAIN" ]; then
    echo 'Captain endpoint differs from the existing configuration; no node credential was sent. Update the endpoint explicitly before retrying.' >&2; exit 1
  fi
  if [ -z "$PAIR" ] && { [ "$SAVED_DOWNLOADS_KNOWN" != 1 ] || [ -z "${saved_url:-}" ] || [ "${saved_url%/}" != "$CAPTAIN" ]; }; then
    echo 'Cannot verify the destination of the existing node token. Use a fresh pairing code for installation or a current configured bosun for upgrades.' >&2; exit 1
  fi
  [ "$MODE" != docker ] || { echo 'Captain delivery supports native installation; Docker images require a reachable registry' >&2; exit 1; }
  if [ "$ACTION" != uninstall ] && [ -z "$PAIR" ] && [ ! -s "$TOKEN_FILE" ]; then echo 'Captain downloads require a pairing code or an existing node token' >&2; exit 1; fi
fi

# In Captain mode no redirect may send bootstrap credentials to another host.
# The permanent token is read from a private header file, never put in argv/URL.
fetch() {
  if [ "$DOWNLOAD_SOURCE" != captain ]; then curl -fsSL "$@"; return; fi
  auth_file=$(umask 077; mktemp "$TMP/captain-headers.XXXXXX")
  if [ -z "$PAIR" ] && [ -s "$TOKEN_FILE" ]; then
    token=$(cat "$TOKEN_FILE")
    case "$token" in *[!a-zA-Z0-9_-]*|'') rm -f "$auth_file"; echo 'invalid node token file' >&2; return 1 ;; esac
    printf 'Authorization: Bearer %s\n' "$token" > "$auth_file"
    unset token
  else
    case "$PAIR" in *[!a-zA-Z0-9_-]*|'') rm -f "$auth_file"; echo 'invalid pairing code' >&2; return 1 ;; esac
    printf 'X-Bosun-Pair-Code: %s\n' "$PAIR" > "$auth_file"
  fi
  if curl -fsSL --globoff --max-redirs 0 --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 --header "@$auth_file" "$@"; then
    rm -f "$auth_file"; return 0
  else
    result=$?; rm -f "$auth_file"; return "$result"
  fi
}

# YAML single-quoted scalars preserve punctuation and whitespace in values.
yaml_quote() { printf "'"; printf '%s' "$1" | sed "s/'/''/g"; printf "'"; }

# Lifecycle commands never re-run installation prompts or rewrite deployment settings.
resolve_version() {
  if [ -z "$VERSION" ]; then
    if [ "$DOWNLOAD_SOURCE" = captain ]; then
      VERSION=$(fetch "$CAPTAIN/api/agent/downloads/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    else
      VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    fi
  fi
  printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'invalid release version' >&2; exit 1; }
  if [ "$DOWNLOAD_SOURCE" = captain ]; then
    printf '%s\n' "$VERSION" | awk -F. '{sub(/^v/,"",$1); exit !(($1+0)>0 || ($2+0)>=89)}' || { echo 'Captain delivery requires bosun v0.89.0 or newer; wait for its official release' >&2; exit 1; }
    BASE="$CAPTAIN/api/agent/downloads/bosun/$VERSION"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
}

download_worker() {
  command -v curl >/dev/null || { echo 'curl is required to download the release' >&2; exit 1; }
  resolve_version
  case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo 'unsupported architecture' >&2; exit 1 ;; esac
  fetch -o "$TMP/$PRODUCT" "$BASE/$PRODUCT-linux-$ARCH"
  fetch -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
  WANT=$(awk -v file="$PRODUCT-linux-$ARCH" '$2 == file {print $1}' "$TMP/SHA256SUMS")
  GOT=$(sha256sum "$TMP/$PRODUCT" | cut -d' ' -f1)
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo 'checksum mismatch' >&2; exit 1; }
  chmod 0755 "$TMP/$PRODUCT"
  WORKER="$TMP/$PRODUCT"
}
prepare_worker() {
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
  if copy_cached_worker; then return; fi
  download_worker
}
native_command() {
  if [ "$PRODUCT" = captain ]; then runuser -u captain -- "$NATIVE" "$@"
  else "$NATIVE" "$@"; fi
}
if [ "$ACTION" = uninstall ]; then
  confirm_uninstall
  prepare_worker
  run_uninstall
  exit 0
fi
if [ "$ACTION" = upgrade ] || [ "$ACTION" = enable-web-upgrade ]; then
  if [ -z "$MODE" ]; then
    if [ -f "/opt/$PRODUCT/docker-compose.yml" ] || [ -f "/opt/$PRODUCT/docker-compose.yaml" ] || [ -f "/opt/$PRODUCT/compose.yml" ] || [ -f "/opt/$PRODUCT/compose.yaml" ]; then MODE=docker
    elif [ -x "$NATIVE" ]; then MODE=binary
    else echo 'no existing installation found; install first' >&2; exit 1; fi
  fi
  case "$MODE" in docker|binary) ;; *) echo '--mode must be docker or binary' >&2; exit 1 ;; esac
  [ "$DOWNLOAD_SOURCE" != captain ] || [ "$MODE" != docker ] || { echo 'Captain delivery cannot upgrade Docker images' >&2; exit 1; }
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

if [ "$NODE_MODE" = monitor ]; then
  [ -n "$CAPTAIN" ] && [ -n "$PAIR" ] || { echo '--monitor-only requires --captain and --pair' >&2; exit 1; }
  [ ! -f /etc/bosun/config.yaml ] || { echo 'Existing installation: change node mode from Captain instead.' >&2; exit 1; }
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

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
resolve_version
echo "downloading bosun $VERSION ($ARCH) via $DOWNLOAD_SOURCE"
fetch -o "$TMP/bosun" "$BASE/bosun-linux-$ARCH"
fetch -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
WANT=$(grep " bosun-linux-$ARCH\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
GOT=$(sha256sum "$TMP/bosun" | cut -d' ' -f1)
[ "$WANT" = "$GOT" ] || { echo "checksum mismatch: want $WANT got $GOT" >&2; exit 1; }
if [ "$DOWNLOAD_SOURCE" = captain ] && [ -f /etc/bosun/config.yaml ]; then
  chmod 0755 "$TMP/bosun"
  saved_downloads=$("$TMP/bosun" installer-download-config /etc/bosun/config.yaml) || { echo 'Cannot validate existing download settings; configuration was preserved.' >&2; exit 1; }
  saved_source=$(printf '%s\n' "$saved_downloads" | sed -n '1p')
  saved_url=$(printf '%s\n' "$saved_downloads" | sed -n '2p')
  if [ "$saved_source" != captain ] || [ "${saved_url%/}" != "$CAPTAIN" ]; then
    echo 'Existing configuration was preserved. Set panel.captain.download_source to captain and panel.captain.url to this endpoint before reinstalling, or use the native upgrade action.' >&2
    exit 1
  fi
fi
if [ "$MODE" = binary ]; then install -m 0755 "$TMP/bosun" /usr/local/bin/bosun.new; mv /usr/local/bin/bosun.new /usr/local/bin/bosun; fi

# nft and tc back the per-user speed limits, nft forwards and strict
# ingress; minimal images (Debian cloud, Alpine) ship without them. Best
# effort: bosun runs without them and the doctor says what is missing.
if [ "$NODE_MODE" = full ] && [ "$MODE" = binary ] && { ! command -v nft >/dev/null || ! command -v tc >/dev/null || ! command -v ip >/dev/null || ! command -v wg >/dev/null; }; then
  if [ "$DOWNLOAD_SOURCE" = captain ]; then
    echo 'Captain delivers bosun and managed cores. Missing nftables/iproute2/wireguard-tools must be installed from a reachable OS package repository; automatic OS downloads are skipped.' >&2
  else
  echo "installing nftables, iproute2 and wireguard-tools (network enforcement and managed tunnels)"
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables iproute2 wireguard-tools >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  elif command -v apk >/dev/null; then
    apk add -q nftables iproute2 iproute2-tc wireguard-tools >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  elif command -v dnf >/dev/null; then
    dnf install -y -q nftables iproute iproute-tc wireguard-tools >/dev/null 2>&1 || echo "  could not install them; speed limits and nft forwards stay off" >&2
  fi
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

NODE_MODE_LINE=""
[ "$NODE_MODE" != monitor ] || NODE_MODE_LINE="node_mode: monitor"
# Old releases use strict configuration parsing. Their GitHub default must not
# acquire a field introduced by the optional Captain delivery feature.
DOWNLOAD_SOURCE_LINE=""
[ "$DOWNLOAD_SOURCE" != captain ] || DOWNLOAD_SOURCE_LINE="    download_source: captain"
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
    url: $(yaml_quote "$CAPTAIN")
    pair_code: $(yaml_quote "$PAIR")
$DOWNLOAD_SOURCE_LINE
    token_file: $(yaml_quote "$TOKEN_FILE")"
  else
    PANEL="panel:
  driver: local

web:
  listen: \"$WEB_LISTEN\""
  fi
  cat > /etc/bosun/config.yaml <<CFG
data_dir: /var/lib/bosun
log_level: info
${NODE_MODE_LINE}
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
    PRIVATE_CAPS=""
    [ "$NODE_MODE" != full ] || PRIVATE_CAPS="    cap_add: [NET_ADMIN]"
    cat > /opt/bosun/docker-compose.yml <<YAML
services:
  bosun:
    image: zeptop/bosun:$VERSION
    restart: unless-stopped
    network_mode: host
${PRIVATE_CAPS}
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
  if [ "$NODE_MODE" != monitor ] && docker compose run --rm --no-deps bosun private-access-supported >/dev/null 2>&1; then
    docker compose run --rm --no-deps bosun prepare-private-access || echo 'Private access needs attention; see the checks above.' >&2
  fi
  docker compose up -d bosun
  if [ "$WEB_UPGRADE" = 1 ]; then "$TMP/bosun" docker-updater setup --dir /opt/bosun; fi
  echo 'bosun installed with Docker. Manage: cd /opt/bosun && docker compose logs -f'
  exit 0
fi

# Older pinned binaries may not implement preparation. Preserve existing
# configs; the command creates only the configured non-root account.
if [ "$NODE_MODE" != monitor ] && /usr/local/bin/bosun private-access-supported >/dev/null 2>&1; then
  /usr/local/bin/bosun prepare-private-access -c /etc/bosun/config.yaml || echo 'Private access needs attention; see the checks above.' >&2
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
  if [ "$DOWNLOAD_SOURCE" = captain ]; then SERVICE_URL="$CAPTAIN/api/agent/downloads/bootstrap/bosun.service"
  else SERVICE_URL="https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.service"; fi
  fetch -o "$TMP/bosun.service" "$SERVICE_URL"
  install -m 0644 "$TMP/bosun.service" /etc/systemd/system/bosun.service
  systemctl daemon-reload
  systemctl enable --now bosun
  systemctl restart bosun
  sleep 2
  systemctl --no-pager --lines=5 status bosun || true
  echo "bosun $VERSION installed. Logs: journalctl -u bosun -f"
else
  if [ "$DOWNLOAD_SOURCE" = captain ]; then SERVICE_URL="$CAPTAIN/api/agent/downloads/bootstrap/bosun.initd"
  else SERVICE_URL="https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.initd"; fi
  fetch -o "$TMP/bosun.initd" "$SERVICE_URL"
  install -m 0755 "$TMP/bosun.initd" /etc/init.d/bosun
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
