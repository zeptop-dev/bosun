#!/bin/sh
# bosun installer for Linux (systemd, OpenRC, or OpenWrt monitor-only). Usage:
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
OPENWRT=0
[ ! -f /etc/openwrt_release ] || OPENWRT=1
DATA_DIR=/var/lib/bosun
[ "$OPENWRT" != 1 ] || DATA_DIR=/etc/bosun/data
SAVED_DOWNLOADS_KNOWN=0 TOKEN_FILE_SET=0
DOWNLOAD_SOURCE="" TOKEN_FILE="$DATA_DIR/captain.token"
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

# A router must never be turned into a managed proxy/firewall host by accident.
if [ "$OPENWRT" = 1 ]; then
  [ "$MODE" != docker ] || { echo 'OpenWrt supports native monitor-only installation.' >&2; exit 1; }
  if [ "$ACTION" != uninstall ]; then
    [ -x /sbin/procd ] && [ -f /etc/rc.common ] || { echo 'OpenWrt procd is required.' >&2; exit 1; }
    if [ -f /etc/bosun/config.yaml ]; then
      [ -x "$NATIVE" ] && [ "$("$NATIVE" installer-node-mode /etc/bosun/config.yaml 2>/dev/null)" = monitor ] || { echo 'Existing OpenWrt installation must be monitor-only; configuration was preserved.' >&2; exit 1; }
      NODE_MODE=monitor
    else
      [ "$NODE_MODE" = monitor ] || { echo 'OpenWrt requires --monitor-only, --captain and --pair.' >&2; exit 1; }
    fi
  fi
fi

# OpenWrt base images may omit the install utility. Every destination here is
# a fixed installer-owned file; refuse directories/symlinks before replacement.
install_file() {
  [ ! -L "$3" ] && [ ! -d "$3" ] || { echo 'unsafe installer destination' >&2; return 1; }
  cp "$2" "$3"
  chmod "$1" "$3"
}

move_file() {
  [ ! -L "$2" ] && [ ! -d "$2" ] || { echo 'unsafe installer destination' >&2; return 1; }
  mv -f "$1" "$2"
}

native_init() {
  if [ "$OPENWRT" = 1 ]; then INIT=procd
  elif command -v systemctl >/dev/null; then INIT=systemd
  elif command -v rc-service >/dev/null; then INIT=openrc
  else echo 'systemd, OpenRC or OpenWrt procd is required' >&2; exit 1; fi
}
native_service() {
  case "$INIT" in
    procd) /etc/init.d/bosun "$1" ;;
    systemd) systemctl "$1" "$PRODUCT" ;;
    openrc) rc-service "$PRODUCT" "$1" ;;
  esac
}

# An offline uninstall can use the trusted local worker even when the running
# application's config is unreadable. Copy before executing its capability
# check so the same private file is used for the eventual uninstall.
trusted_worker_file() {
  [ -f "$1" ] && [ -x "$1" ] && [ ! -L "$1" ] || return 1
  if [ "$OPENWRT" = 1 ]; then
    # BusyBox often has no stat applet. Numeric ls ownership plus its fixed
    # permission columns are sufficient; do not execute an untrusted helper
    # merely to inspect the helper's own ownership.
    worker_meta=$(LC_ALL=C ls -ldn "$1") || return 1
    printf '%s\n' "$worker_meta" | awk '{exit !($3 == 0 && substr($1,6,1) != "w" && substr($1,9,1) != "w")}'
    return $?
  fi
  [ "$(stat -c %u "$1" 2>/dev/null)" = 0 ] || return 1
  worker_mode=$(stat -c %a "$1" 2>/dev/null) || return 1
  case "$worker_mode" in ''|*[!0-7]*|*[2367][0-7]|*[2367]) return 1 ;; esac
}
copy_cached_worker() {
  candidate="/usr/local/lib/$PRODUCT-updater/worker"
  if ! trusted_worker_file "$candidate"; then
    [ "$OPENWRT" = 1 ] && trusted_worker_file "$NATIVE" || return 1
    candidate=$NATIVE
  fi
  # Preserve owner/mode and symlinks while copying, then verify the private
  # copy too: a changed source cannot become trusted merely because root
  # created the destination file.
  if ! cp -pP "$candidate" "$TMP/$PRODUCT" || ! trusted_worker_file "$TMP/$PRODUCT" || ! chmod 0755 "$TMP/$PRODUCT"; then rm -f "$TMP/$PRODUCT"; return 1; fi
  if [ "$("$TMP/$PRODUCT" installer-version 2>/dev/null || true)" != 1 ]; then rm -f "$TMP/$PRODUCT"; return 1; fi
  if [ "$OPENWRT" = 1 ] && [ "$("$TMP/$PRODUCT" installer-openwrt-supported 2>/dev/null || true)" != 1 ]; then rm -f "$TMP/$PRODUCT"; return 1; fi
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

# Probe before downloading anything or constructing a credential header. The
# dedicated listener and older main listeners intentionally use different health
# contracts. A missing dedicated route alone never means Captain is unreachable.
captain_preflight() {
  case "$ACTION" in install|upgrade) ;; *) return 0 ;; esac
  [ -n "$CAPTAIN" ] || return 0
  # A URL carrying userinfo, query data or fragments must not reach curl, logs or
  # a proxy. Keep historical HTTP and path-prefixed main endpoints working.
  case "$CAPTAIN" in
    *[[:space:][:cntrl:]]*) echo 'Captain preflight: invalid endpoint; whitespace and control characters are not allowed.' >&2; return 1 ;;
  esac
  printf '%s\n' "$CAPTAIN" | LC_ALL=C grep -Eq '^https?://(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?(/[a-zA-Z0-9._~/-]*)?$' || {
    echo 'Captain preflight: invalid endpoint; use an HTTP(S) URL without credentials, query or fragment.' >&2; return 1
  }
  command -v curl >/dev/null || { echo 'Captain preflight: curl is required.' >&2; return 1; }
  check_dir=$(umask 077; mktemp -d)
  check_ok=0
  for check_path in /api/agent/health /api/health; do
    check_rc=0
    # -q must be curl's first argument: local curlrc headers/auth must not turn
    # an anonymous check into a credential-bearing request. Never follow redirects
    # and never print curl diagnostics, response bodies or the supplied endpoint.
    # ulimit also bounds chunked bodies on old curl versions whose max-filesize
    # only checks Content-Length. It applies only to this short-lived subprocess.
    check_http=$( (ulimit -f 16 || exit 1; curl -q -s --globoff --max-redirs 0 --proto '=http,https' --connect-timeout 5 --max-time 10 --max-filesize 4096 --output "$check_dir/body" --write-out '%{http_code}' "${CAPTAIN%/}$check_path") 2>/dev/null) || check_rc=$?
    # Error pages can exceed the body cap. The HTTP status is still useful
    # evidence, so classify it before a size/write error hides a proxy failure.
    check_reason=""
    case "$check_http" in
      404|405) continue ;;
      3??) check_reason='redirect refused; use the final Captain endpoint and check reverse-proxy rules.' ;;
      521) check_reason='HTTP 521: the proxy could not connect to the origin listener.' ;;
      522) check_reason='HTTP 522: the proxy timed out connecting to the origin; check the origin port and firewall.' ;;
      525) check_reason='HTTP 525: TLS handshake failed between the proxy and origin.' ;;
      526) check_reason='HTTP 526: the proxy rejected the origin certificate.' ;;
      4??|5??) check_reason="HTTP $check_http: check reverse-proxy routing and access rules." ;;
    esac
    if [ -n "$check_reason" ]; then
      echo "Captain preflight: $check_reason No pairing code or node token was sent." >&2
      rm -rf "$check_dir"; return 1
    fi
    if [ "$check_rc" != 0 ]; then
      case "$check_rc" in
        5|6) check_reason='DNS resolution failed; check the Captain hostname and DNS resolver.' ;;
        7) check_reason='connection failed; check the listener, published port and firewall from this node.' ;;
        28) check_reason='connection or response timed out; check routing, port restrictions and firewall from this node.' ;;
        35|51|58|59|60|64|66|77|80|82|83|90|91) check_reason='TLS verification or handshake failed; check hostname, certificate chain and system clock.' ;;
        23|63|152|153) check_reason='health response exceeded the size limit; this may not be a Captain endpoint.' ;;
        *) check_reason='HTTP transport failed before a valid health response.' ;;
      esac
      echo "Captain preflight: $check_reason No pairing code or node token was sent." >&2
      rm -rf "$check_dir"; return 1
    fi
    if [ "$(wc -c < "$check_dir/body")" -gt 4096 ]; then
      echo 'Captain preflight: health response exceeded the size limit; no credentials were sent.' >&2
      rm -rf "$check_dir"; return 1
    fi
    case "$check_http" in
      200)
        # A small, flat health object is required, not a login/SPA/HTML page
        # containing a success word. Unknown scalar fields are tolerated.
        if awk -v kind="$check_path" '
          { body=body $0 "\n" }
          END {
            # Health contract strings contain no whitespace. Preserve line breaks
            # until checking quoted strings, then normalize JSON line whitespace.
            for (i=1;i<=length(body);i++) {
              ch=substr(body,i,1)
              if (ch=="\"") quoted=!quoted
              else if (quoted && ch ~ /[[:space:]]/) exit 1
            }
            gsub(/\n/," ",body)
            if (body !~ /^[ \t\r\n]*\{/ || body !~ /\}[ \t\r\n]*$/) exit 1
            sub(/^[ \t\r\n]*\{/,"",body); sub(/\}[ \t\r\n]*$/,"",body)
            n=split(body,fields,","); ok=0; service=0; clock=0
            for (i=1;i<=n;i++) {
              if (fields[i] !~ /^[ \t\r\n]*"[a-zA-Z_]+"[ \t\r\n]*:[ \t\r\n]*("[a-zA-Z0-9_.:-]*"|true|false|null|-?[0-9]+)[ \t\r\n]*$/) exit 1
              split(fields[i],parts,"\""); key=parts[2]
              if (seen[key]++) exit 1
              if (key=="ok") ok=(fields[i] ~ /:[ \t\r\n]*true[ \t\r\n]*$/)
              if (key=="service") service=(fields[i] ~ /:[ \t\r\n]*"captain-agent"[ \t\r\n]*$/)
              if (key=="time") clock=(fields[i] ~ /:[ \t\r\n]*[0-9]+[ \t\r\n]*$/)
            }
            if (kind=="/api/agent/health") exit !(ok && service)
            exit !(ok && clock)
          }' "$check_dir/body"; then check_ok=1; break; fi
        ;;
      *) echo 'Captain preflight: unexpected HTTP response; no pairing code or node token was sent.' >&2; rm -rf "$check_dir"; return 1 ;;
    esac
  done
  rm -rf "$check_dir"
  [ "$check_ok" = 1 ] || {
    echo 'Captain preflight: neither Agent nor main health returned a compatible Captain response; check the endpoint and reverse-proxy paths. No pairing code or node token was sent.' >&2; return 1
  }
  echo 'Captain endpoint check passed (no credentials sent).'
}

# In Captain mode no redirect may send bootstrap credentials to another host.
# The permanent token is read from a private header file, never put in argv/URL.
# Ignore curlrc: it can add extra URLs, credentials or TLS overrides to a fetch.
fetch() {
  if [ "$DOWNLOAD_SOURCE" != captain ]; then curl -q -fsSL "$@"; return; fi
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
  if curl -q -fsSL --globoff --max-redirs 0 --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 600 --header "@$auth_file" "$@"; then
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
  if [ "$OPENWRT" = 1 ]; then
    printf '%s\n' "$VERSION" | awk -F. '{sub(/^v/,"",$1); exit !(($1+0)>0 || ($2+0)>=89)}' || { echo 'OpenWrt requires bosun v0.89.0 or newer; wait for its official release' >&2; exit 1; }
  fi
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
  captain_preflight
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
    install_file 0755 "$WORKER" "$TMP/next"
    if [ "$PRODUCT" = captain ]; then chown captain:captain "$TMP/next"; fi
    BACKUP_ROOT="/var/lib/$PRODUCT-updater"
    [ "$OPENWRT" != 1 ] || BACKUP_ROOT=/etc/bosun-updater
    mkdir -p "$BACKUP_ROOT/backups"
    chmod 0700 "$BACKUP_ROOT" "$BACKUP_ROOT/backups"
    BACKUP="$BACKUP_ROOT/backups/binary-$(date +%Y%m%d%H%M%S)"
    mkdir -m 0700 "$BACKUP"
    cp -p "$NATIVE" "$TMP/previous"
    printf '%s\n' "$CURRENT" > "$TMP/previous.version"
    native_init
    native_service stop
    resume_old() { native_service start; }
    BACKUP_DATA="var/lib/$PRODUCT"
    [ "$OPENWRT" != 1 ] || BACKUP_DATA="etc/bosun/data"
    if ! tar -czf "$BACKUP/data.tar.gz" -C / "etc/$PRODUCT" "$BACKUP_DATA"; then resume_old; echo 'backup failed; old service restarted' >&2; exit 1; fi
    if ! { move_file "$TMP/previous" "$NATIVE.backup" && move_file "$TMP/previous.version" "$NATIVE.backup.version" && move_file "$TMP/next" "$NATIVE"; }; then
      resume_old; echo 'binary replacement failed; existing service restarted' >&2; exit 1
    fi
    resume_old
    READY=0
    for _attempt in 1 2 3 4 5 6 7 8 9 10; do
      if native_command healthcheck --version "$VERSION" --data-dir "$DATA_DIR" >/dev/null 2>&1; then READY=1; break; fi
      sleep 2
    done
    [ "$READY" = 1 ] || { echo "New service did not become ready. Data backup: $BACKUP. No automatic database downgrade was attempted." >&2; exit 1; }
    echo "$PRODUCT $VERSION installed. Pre-upgrade data: $BACKUP. Service configuration was preserved."
  fi
  exit 0
fi

if [ "$NODE_MODE" = monitor ]; then
  if [ "$OPENWRT" != 1 ] || [ ! -f /etc/bosun/config.yaml ]; then
    [ -n "$CAPTAIN" ] && [ -n "$PAIR" ] || { echo '--monitor-only requires --captain and --pair' >&2; exit 1; }
    [ ! -f /etc/bosun/config.yaml ] || { echo 'Existing installation: change node mode from Captain instead.' >&2; exit 1; }
  fi
fi
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
# Binary mode uses the host init system; Docker installation does not require it.
MODE=${MODE:-binary}
case "$MODE" in docker|binary) ;; *) echo '--mode must be docker or binary' >&2; exit 1 ;; esac
if [ "$MODE" = binary ]; then
  native_init
fi
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
captain_preflight
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
if [ "$MODE" = binary ]; then mkdir -p /usr/local/bin; install_file 0755 "$TMP/bosun" /usr/local/bin/bosun.new; move_file /usr/local/bin/bosun.new /usr/local/bin/bosun; fi

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

mkdir -p /etc/bosun "$DATA_DIR"
[ "$OPENWRT" != 1 ] || chmod 0700 /etc/bosun "$DATA_DIR"
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
data_dir: $DATA_DIR
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
  install_file 0644 "$TMP/bosun.service" /etc/systemd/system/bosun.service
  systemctl daemon-reload
  systemctl enable --now bosun
  systemctl restart bosun
  sleep 2
  systemctl --no-pager --lines=5 status bosun || true
  echo "bosun $VERSION installed. Logs: journalctl -u bosun -f"
elif [ "$INIT" = procd ]; then
  if [ "$DOWNLOAD_SOURCE" = captain ]; then SERVICE_URL="$CAPTAIN/api/agent/downloads/bootstrap/bosun.procd"
  else SERVICE_URL="https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.procd"; fi
  fetch -o "$TMP/bosun.procd" "$SERVICE_URL"
  install_file 0755 "$TMP/bosun.procd" /etc/init.d/bosun
  /etc/init.d/bosun enable
  /etc/init.d/bosun restart
  echo "bosun $VERSION monitor installed. Logs: logread -e bosun"
else
  if [ "$DOWNLOAD_SOURCE" = captain ]; then SERVICE_URL="$CAPTAIN/api/agent/downloads/bootstrap/bosun.initd"
  else SERVICE_URL="https://raw.githubusercontent.com/$REPO/$VERSION/deploy/bosun.initd"; fi
  fetch -o "$TMP/bosun.initd" "$SERVICE_URL"
  install_file 0755 "$TMP/bosun.initd" /etc/init.d/bosun
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
