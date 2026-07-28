#!/bin/sh
set -eu

log() {
  echo "[entrypoint] $*"
}

detect_iface_for_gateway() {
  gw_ip="$1"
  ip route get "$gw_ip" 2>/dev/null | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev") {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

wait_for_gateway_resolution() {
  gw_name="${GATEWAY_NAME:?missing GATEWAY_NAME}"
  tries=0
  while :; do
    gw_ip="$(getent hosts "$gw_name" | awk '{print $1; exit}')"
    if [ -n "${gw_ip:-}" ]; then
      printf '%s\n' "$gw_ip"
      return 0
    fi
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo "ERROR: could not resolve gateway $gw_name" >&2
      return 1
    fi
    sleep 1
  done
}

write_hosts_from_docker() {
  python3 - <<'PY'
import http.client
import json
import os
import re
import socket
import sys

SOCK = "/var/run/docker.sock"
OUTFILE = "/run/dnsmasq-internal.hosts"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, unix_socket_path, host="docker"):
        super().__init__(host)
        self.unix_socket_path = unix_socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_socket_path)


def docker_get(path: str):
    conn = UnixHTTPConnection(SOCK)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    status = resp.status
    reason = resp.reason
    conn.close()

    if status != 200:
        raise RuntimeError(f"Docker API error on {path}: {status} {reason}")

    return json.loads(body.decode("utf-8"))


def get_self_container_id() -> str:
    # /etc/hostname is NOT reliable here: when this container shares the
    # network namespace of another one (network_mode: container:X /
    # service:X in Compose) and that other container was started with a
    # custom `hostname`, Docker applies that same hostname to us too, so
    # /etc/hostname is no longer our own container ID.
    #
    # The bind-mount Docker sets up for /etc/hostname always exposes
    # /var/lib/docker/containers/<our real id>/hostname, regardless of
    # storage driver or hostname overrides, so read our id from there via
    # /proc/self/mountinfo instead.
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
        for line in f:
            fields = line.strip().split(" - ", 1)[0].split()
            if len(fields) < 5:
                continue
            mount_root, mount_point = fields[3], fields[4]
            if mount_point != "/etc/hostname":
                continue
            match = re.search(r"/containers/([0-9a-f]{12,64})/hostname$", mount_root)
            if match:
                return match.group(1)

    # Fallback for setups without that bind-mount: the hostname is usually
    # the container ID.
    with open("/etc/hostname", "r", encoding="utf-8") as f:
        return f.read().strip()


def resolve_primary_container_id(self_inspect: dict) -> str:
    netmode = ((self_inspect.get("HostConfig") or {}).get("NetworkMode") or "").strip()

    # In net_setup mode we expect something like: container:<odoo_container_id>
    if netmode.startswith("container:"):
        return netmode.split(":", 1)[1].strip()

    # Fallback: if for some reason we are already inspecting the primary container,
    # just use self.
    return self_inspect["Id"]


def get_default_network_names(primary_inspect: dict) -> list[str]:
    networks = (primary_inspect.get("NetworkSettings", {}).get("Networks") or {}).keys()
    default_networks = [name for name in networks if name == "default" or name.endswith("_default")]

    if not default_networks:
        raise RuntimeError(
            "Could not determine the primary default network from the main container"
        )

    return sorted(default_networks)


self_id = get_self_container_id()
# Deliberately unversioned: a hardcoded API version (e.g. /v1.41/) breaks as
# soon as the Docker Engine raises its minimum supported API version past
# it (newer engines reject old versions with 400 Bad Request). Omitting the
# version makes the daemon use its own latest supported version instead.
self_inspect = docker_get(f"/containers/{self_id}/json")
primary_id = resolve_primary_container_id(self_inspect)
primary_inspect = docker_get(f"/containers/{primary_id}/json")

default_network_names = get_default_network_names(primary_inspect)

containers = docker_get("/containers/json")

lines = []
seen = set()

for c in containers:
    inspect = docker_get(f"/containers/{c['Id']}/json")
    labels = inspect.get("Config", {}).get("Labels") or {}
    service = labels.get("com.docker.compose.service")
    cname = inspect.get("Name", "").lstrip("/")
    networks = inspect.get("NetworkSettings", {}).get("Networks") or {}

    for net_name, net_cfg in networks.items():
        if net_name not in default_network_names:
            continue

        ip = (net_cfg or {}).get("IPAddress")
        if not ip:
            continue

        names = set()
        if service:
            names.add(service)
        if cname:
            names.add(cname)

        for alias in (net_cfg.get("Aliases") or []):
            if alias:
                names.add(alias)

        for name in sorted(names):
            key = (ip, name)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"{ip} {name}")

content = "\n".join(sorted(lines)) + ("\n" if lines else "")

old = ""
try:
    with open(OUTFILE, "r", encoding="utf-8") as f:
        old = f.read()
except FileNotFoundError:
    pass

if old != content:
    with open(OUTFILE, "w", encoding="utf-8") as f:
        f.write(content)
PY
}

refresh_hosts_from_docker_loop() {
  : "${DNS_DOCKER_REFRESH_INTERVAL:=5}"
  while :; do
    if ! write_hosts_from_docker; then
      echo "WARN: failed to refresh internal DNS hosts from Docker" >&2
    fi
    if [ -f /run/dnsmasq.pid ]; then
      kill -HUP "$(cat /run/dnsmasq.pid)" 2>/dev/null || true
    fi
    sleep "$DNS_DOCKER_REFRESH_INTERVAL"
  done &
}

extract_domains_from_allowed_hosts() {
  for item in ${ALLOWED_HOSTS:-}; do
    case "$item" in
      "") ;;
      *[!0-9.]*) printf '%s\n' "$item" ;;
    esac
  done | sort -u | xargs
}

start_dnsmasq_local() {
  : "${DNS_UPSTREAMS_LOCAL:=127.0.0.11}"

  mkdir -p /run
  touch /run/dnsmasq-internal.hosts

  log "local dnsmasq: upstreams=$DNS_UPSTREAMS_LOCAL"

  cat > /etc/dnsmasq.conf <<EOF
no-resolv
bogus-priv
cache-size=1000
filter-AAAA
bind-interfaces
listen-address=127.0.0.1
addn-hosts=/run/dnsmasq-internal.hosts
clear-on-reload
EOF

  for ns in $DNS_UPSTREAMS_LOCAL; do
    echo "server=$ns" >> /etc/dnsmasq.conf
  done

  dnsmasq -k -C /etc/dnsmasq.conf -x /run/dnsmasq.pid >/dev/null 2>&1 &
  log "local dnsmasq started on 127.0.0.1:53"
}

net_setup_mode() {
  echo "INFO: net_setup_mode: waiting for gateway DNS..."
  GW_IP="$(wait_for_gateway_resolution)"
  echo "INFO: gateway resolved to $GW_IP"

  echo "INFO: selecting correct iface for gateway..."
  ODOO_DEV="$(detect_iface_for_gateway "$GW_IP")"
  if [ -z "${ODOO_DEV:-}" ]; then
    echo "ERROR: could not determine iface for gateway $GW_IP" >&2
    exit 1
  fi
  echo "INFO: chosen iface=$ODOO_DEV"

  ip route replace default via "$GW_IP" dev "$ODOO_DEV"

  if [ "${DNS_LOCAL:-0}" = "1" ]; then
    if [ "${DNS_INTERNAL_FROM_DOCKER:-0}" = "1" ]; then
      echo "INFO: generating internal DNS hosts from Docker..."
      if ! write_hosts_from_docker; then
        echo "ERROR: failed to generate internal DNS hosts from Docker" >&2
        exit 1
      fi
    fi

    start_dnsmasq_local

    if [ "${DNS_INTERNAL_FROM_DOCKER:-0}" = "1" ]; then
      refresh_hosts_from_docker_loop
    fi

    {
      echo "nameserver 127.0.0.1"
      echo "options ndots:0"
    } > /etc/resolv.conf

    echo "INFO: default route configured and local DNS enabled"
  else
    {
      echo "nameserver $GW_IP"
      echo "options ndots:0"
    } > /etc/resolv.conf

    echo "INFO: default route and gateway DNS configured successfully"
  fi

  tail -f /dev/null
}

proxy_mode() {
  # La imagen tiene CMD ["proxy"], así que quitamos ese argumento
  # para no pasarlo dos veces al script Python.
  if [ "${1:-}" = "proxy" ]; then
    shift
  fi

  exec /usr/local/bin/proxy "$@"
}

main() {
  case "${MODE_RUN:-gateway}" in
    net_setup)
      net_setup_mode
      ;;
    gateway|"")
      proxy_mode "$@"
      ;;
    legacy|tcp|proxy)
      proxy_mode "$@"
      ;;
    *)
      echo "Unknown MODE_RUN=${MODE_RUN:-}" >&2
      exit 1
      ;;
  esac
}

main "$@"
