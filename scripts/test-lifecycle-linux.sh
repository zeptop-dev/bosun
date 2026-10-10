#!/bin/sh
# Destructive lifecycle integration ONLY in a private mount/PID namespace and
# a disposable Docker daemon. Pass a directory containing tools/docker/*,
# tools/docker-compose, hostupdate.test, and four product-version.bin fixtures.
set -eu
TEST_ROOT=${1:?fixture directory required}
case "$TEST_ROOT" in /var/tmp/zboard-lifecycle-test) ;; *) echo 'unexpected fixture path' >&2; exit 1 ;; esac
if [ "${2:-}" != inside ]; then
  exec unshare --mount --pid --fork --mount-proc --propagation private "$0" "$TEST_ROOT" inside
fi
[ "$(id -u)" = 0 ] || exit 1
rm -rf "$TEST_ROOT/root"
mkdir -p "$TEST_ROOT/root/etc" "$TEST_ROOT/root/opt" "$TEST_ROOT/root/varlib" "$TEST_ROOT/root/usrlocal" "$TEST_ROOT/root/run" "$TEST_ROOT/root/tmp" "$TEST_ROOT/root/varlog" "$TEST_ROOT/fakebin" "$TEST_ROOT/docker-config/cli-plugins"
# Copy /etc into the namespace: account/service cleanup must not affect the host.
chmod 0700 "$TEST_ROOT"
for config in passwd group nsswitch.conf hosts resolv.conf os-release login.defs; do
  [ ! -e "/etc/$config" ] || cp -L "/etc/$config" "$TEST_ROOT/root/etc/$config"
done
cp -a /etc/pam.d /etc/alternatives "$TEST_ROOT/root/etc/"
mkdir -p "$TEST_ROOT/root/etc/ssl/certs"
cp /etc/ssl/certs/ca-certificates.crt "$TEST_ROOT/root/etc/ssl/certs/"
mount --bind "$TEST_ROOT/root/etc" /etc
mount --bind "$TEST_ROOT/root/opt" /opt
mount --bind "$TEST_ROOT/root/varlib" /var/lib
mount --bind "$TEST_ROOT/root/usrlocal" /usr/local
mount --bind "$TEST_ROOT/root/run" /run
mount --bind "$TEST_ROOT/root/tmp" /tmp
chmod 1777 /tmp
mount --bind "$TEST_ROOT/root/varlog" /var/log
mkdir -p /run/systemd/system /etc/systemd/system /usr/local/lib /usr/local/bin
unset XDG_RUNTIME_DIR
# Init calls are recorded rather than sent to the host PID 1. The test drives
# the real updater HTTP handler itself, independently of the app lifecycle.
cat > "$TEST_ROOT/fakebin/systemctl" <<'SH'
#!/bin/sh
set -eu
action=${1:-}; product=${2:-}
[ "$product" != --now ] || product=${3:-}
case "$product" in captain|bosun) ;; *) exit 0 ;; esac
pidfile="$BOSUN_LIFECYCLE_FIXTURE/$product-native.pid"
case "$action" in
  stop|disable)
    if [ -f "$pidfile" ]; then
      kill "$(cat "$pidfile")" 2>/dev/null || true
      rm -f "$pidfile"
      sleep 1
    fi ;;
  start)
    if [ "$product" = captain ]; then binary=/opt/captain/captain; verb=serve
    else binary=/usr/local/bin/bosun; verb=run; fi
    if [ "$product" = captain ]; then
      # Match Captain's ProtectSystem=strict constraint: readiness must not
      # require a writable /tmp. Only this child gets the read-only mount.
      unshare --mount sh -c 'mount --bind /tmp /tmp; mount -o remount,bind,ro /tmp; exec runuser -u captain -- "$@"' sh "$binary" "$verb" -c "/etc/$product/config.yaml" > "$BOSUN_LIFECYCLE_FIXTURE/$product-native.log" 2>&1 &
    else
      "$binary" "$verb" -c "/etc/$product/config.yaml" > "$BOSUN_LIFECYCLE_FIXTURE/$product-native.log" 2>&1 &
    fi
    echo "$!" > "$pidfile" ;;
esac
exit 0
SH
chmod 755 "$TEST_ROOT/fakebin/systemctl"
cat > "$TEST_ROOT/fakebin/docker" <<'SH'
#!/bin/sh
"$BOSUN_LIFECYCLE_FIXTURE/tools/docker/docker" "$@" 2>>"$BOSUN_LIFECYCLE_FIXTURE/docker-errors.log"
SH
chmod 755 "$TEST_ROOT/fakebin/docker"
: > "$TEST_ROOT/docker-errors.log"
cp "$TEST_ROOT/tools/docker-compose" "$TEST_ROOT/docker-config/cli-plugins/docker-compose"
export PATH="$TEST_ROOT/fakebin:$TEST_ROOT/tools/docker:$PATH"
export DOCKER_HOST="unix://$TEST_ROOT/docker.sock" DOCKER_CONFIG="$TEST_ROOT/docker-config" DOCKER_BUILDKIT=0
export BOSUN_LIFECYCLE_FIXTURE="$TEST_ROOT"
dockerd --host "$DOCKER_HOST" --data-root "$TEST_ROOT/docker-data" --exec-root "$TEST_ROOT/docker-exec" --pidfile "$TEST_ROOT/docker.pid" --bridge none --iptables=false --ip6tables=false --ip-forward=false --ip-masq=false --storage-driver=vfs --exec-opt native.cgroupdriver=cgroupfs > "$TEST_ROOT/dockerd.log" 2>&1 &
DOCKER_PID=$!
trap 'kill "$DOCKER_PID" 2>/dev/null || true; wait "$DOCKER_PID" 2>/dev/null || true' EXIT HUP INT TERM
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
  if docker info >/dev/null 2>&1; then break; fi
  sleep 1
done
docker info >/dev/null
"$TEST_ROOT/hostupdate.test" -test.run '^TestDockerLifecycle$' -test.v -test.timeout 10m
# Download stub serves the compiled fixture assets and real SHA256 checksums.
# Unknown URLs fail rather than accidentally accessing a real install script.
cat > "$TEST_ROOT/fakebin/curl" <<'PY'
#!/usr/bin/python3
import hashlib, os, re, sys
args=sys.argv[1:]
match=re.fullmatch(r'https://github.com/zeptop-dev/(captain|bosun)/releases/download/(v[0-9.]+)/([^/]+)', args[-1])
if not match: sys.exit(2)
product,version,asset=match.groups()
source=os.path.join(os.environ['BOSUN_LIFECYCLE_FIXTURE'],product+'-'+version+'.bin')
data=open(source,'rb').read()
if asset=='SHA256SUMS': data=(hashlib.sha256(data).hexdigest()+'  '+product+'-linux-amd64\n').encode()
elif asset!=product+'-linux-amd64': sys.exit(2)
open(args[args.index('-o')+1],'wb').write(data)
PY
chmod 755 "$TEST_ROOT/fakebin/curl"
for product in captain bosun; do
  case "$product" in captain) version=v1.17.0; previous=v1.16.0; native=/opt/captain/captain ;; bosun) version=v0.65.0; previous=v0.64.3; native=/usr/local/bin/bosun ;; esac
  mkdir -p "$(dirname "$native")" "/etc/$product" "/var/lib/$product/backups" "/etc/systemd/system/$product.service.d"
  cp "$TEST_ROOT/$product-$previous.bin" "$native"
  cp "$native" "$native.backup"
  touch "$native.backup.version" "/etc/$product/config.yaml" "/var/lib/$product/backups/data" "/etc/systemd/system/$product.service" "/etc/systemd/system/$product.service.d/local.conf"
  if [ "$product" = captain ]; then
    id captain >/dev/null 2>&1 || useradd --system --home /var/lib/captain --shell /usr/sbin/nologin captain
    chown -R captain:captain /var/lib/captain
    cat > /etc/captain/config.yaml <<'YAML'
listen: 127.0.0.1:8080
base_url: http://localhost:8080
data_dir: /var/lib/captain
database: {driver: sqlite, dsn: /var/lib/captain/captain.db}
tls: {auto: false}
YAML
  else
    cat > /etc/bosun/config.yaml <<'YAML'
data_dir: /var/lib/bosun
panel: {driver: local}
web: {listen: '127.0.0.1:2053'}
cores:
  order: [singbox]
  singbox: {binary: /bin/true}
YAML
  fi
  original=$(sha256sum "/etc/$product/config.yaml" | cut -d' ' -f1)
  unshare --net sh -c 'ip link set lo up; exec sh "$@"' sh "$TEST_ROOT/$product-install.sh" upgrade --mode binary --version "$version"
  [ "$(sha256sum "/etc/$product/config.yaml" | cut -d' ' -f1)" = "$original" ]
  [ -f "/var/lib/$product/backups/data" ]
  [ -f "/etc/systemd/system/$product.service.d/local.conf" ]
  echo "$product binary upgrade preserved configuration and data"
  # Real installer/CLI, with a private network namespace for nft/tc cleanup.
  unshare --net sh "$TEST_ROOT/$product-install.sh" uninstall --yes --version "$version"
  [ ! -e "$native" ] && [ ! -e "$native.backup" ] && [ ! -e "/etc/$product" ] && [ ! -e "/var/lib/$product" ] && [ ! -e "/etc/systemd/system/$product.service.d" ]
  echo "$product binary full uninstall passed"
done
