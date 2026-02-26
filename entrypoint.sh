#!/bin/sh
set -eu

log() { echo "[entrypoint] $*"; }


ip_for_iface() {
  ip -4 addr show "$1" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true
}

detect_inside_iface() {
  outside="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

  ip -o -4 addr show | awk '$2!="lo"{print $2}' | while read -r dev; do
    [ "$dev" = "$outside" ] && continue
    echo "$dev"
    exit 0
  done

  # Fallback
  echo "eth0"
}

extract_domains_from_allowed_hosts() {
  python3 - <<'PY'
import ipaddress, os
raw = os.environ.get("ALLOWED_HOSTS","").strip()
out=[]
for tok in raw.split():
    try:
        ipaddress.ip_address(tok)
    except Exception:
        out.append(tok)
print(" ".join(out))
PY
}

write_hosts_for_internal_names() {
  names="${1:-}"
  [ -n "$names" ] || return 0

  for name in $names; do
    ip="$(getent hosts "$name" 2>/dev/null | awk '{print $1}' | head -n 1 || true)"
    if [ -n "$ip" ]; then
      if ! grep -qE "^[[:space:]]*$ip[[:space:]]+$name([[:space:]]|$)" /etc/hosts; then
        echo "$ip $name" >> /etc/hosts
      fi
    fi
  done
}

start_dnsmasq() {
  : "${DNS_UPSTREAMS:=1.1.1.1 8.8.8.8}"
  : "${DNS_INTERNAL_NAMES:=db smtp wdb pgweb odoo proxy_general}"
  : "${DNS_ALLOWED_DOMAINS:=}"
  : "${DNS_LISTEN_IFACE:=}"

  # Default listen iface: INSIDE_IFACE if present, else eth0
    # Auto-detect listen iface (inside) if not provided
  if [ -z "$DNS_LISTEN_IFACE" ]; then
    DNS_LISTEN_IFACE="$(detect_inside_iface)"
  fi

  # If not provided, derive allowed domains from ALLOWED_HOSTS (filter IP literals out)
  if [ -z "$DNS_ALLOWED_DOMAINS" ]; then
    DNS_ALLOWED_DOMAINS="$(extract_domains_from_allowed_hosts)"
  fi

  log "dnsmasq: listen iface=$DNS_LISTEN_IFACE (ip=$(ip_for_iface "$DNS_LISTEN_IFACE"))"
  log "dnsmasq: upstreams=$DNS_UPSTREAMS"
  log "dnsmasq: allowed domains=$DNS_ALLOWED_DOMAINS"
  log "dnsmasq: internal names=$DNS_INTERNAL_NAMES"

  # Ensure internal docker service names are resolvable via /etc/hosts (dnsmasq reads hosts)
  write_hosts_for_internal_names "$DNS_INTERNAL_NAMES"

  cat > /etc/dnsmasq.conf <<EOF
no-resolv
domain-needed
bogus-priv
cache-size=1000

# Default: block everything NXDOMAIN
EOF

  for domain in $DNS_ALLOWED_DOMAINS; do
    for ns in $DNS_UPSTREAMS; do
      echo "server=/$domain/$ns" >> /etc/dnsmasq.conf
    done
  done

  dnsmasq -k -C /etc/dnsmasq.conf >/dev/null 2>&1 &
  log "dnsmasq started"
}

net_setup_mode() {
  : "${GATEWAY_NAME:=proxy_general}"

  log "MODE_RUN=net_setup"
  log "GATEWAY_NAME=$GATEWAY_NAME"

  # Pick Odoo interface: first non-lo iface with an IPv4
  DEFAULT_DEV="$(ip -o -4 addr show | awk '$2!="lo"{print $2; exit}' || true)"
  if [ -z "$DEFAULT_DEV" ]; then
    log "ERROR: cannot determine Odoo iface with IPv4"
    ip -o -4 addr show || true
    exit 1
  fi

  # CIDR of that iface (e.g. 172.28.0.7/16)
  ODOO_CIDR="$(ip -o -4 addr show dev "$DEFAULT_DEV" | awk '{print $4}' | head -n1 || true)"
  if [ -z "$ODOO_CIDR" ]; then
    log "ERROR: cannot determine Odoo IPv4 CIDR on dev=$DEFAULT_DEV"
    ip -o -4 addr show dev "$DEFAULT_DEV" || true
    exit 1
  fi

  log "ODOO_DEV=$DEFAULT_DEV"
  log "ODOO_CIDR=$ODOO_CIDR"

  GW_IP=""
  for i in $(seq 1 60); do
    GW_IP="$(
      getent hosts "$GATEWAY_NAME" 2>/dev/null | awk '{print $1}' | \
      python3 -c '
import ipaddress, sys

net = ipaddress.ip_network(sys.argv[1], strict=False)

for line in sys.stdin:
    ip = line.strip()
    if not ip:
        continue
    try:
        if ipaddress.ip_address(ip) in net:
            print(ip)
            break
    except Exception:
        pass
' "$ODOO_CIDR"
    )"

    if [ -n "$GW_IP" ]; then
      log "Gateway resolved (same subnet) to $GW_IP"
      break
    fi

    log "Waiting for $GATEWAY_NAME DNS..."
    sleep 1
  done

  if [ -z "$GW_IP" ]; then
    log "ERROR: $GATEWAY_NAME not resolvable in Odoo subnet $ODOO_CIDR"
    log "DEBUG getent:"
    getent hosts "$GATEWAY_NAME" || true
    log "DEBUG ip addr:"
    ip -o -4 addr show || true
    exit 1
  fi

  ip route replace default via "$GW_IP"
  log "Default route set via $GW_IP"

  printf "nameserver %s\noptions ndots:0\n" "$GW_IP" > /etc/resolv.conf
  log "DNS set to $GW_IP"
  cat /etc/resolv.conf || true

  sleep infinity
}

: "${MODE_RUN:=gateway}"

if [ "$MODE_RUN" = "net_setup" ]; then
  net_setup_mode
fi

# Gateway mode: optionally start dnsmasq before running proxy
: "${DNS_ENABLED:=1}"
if [ "$DNS_ENABLED" != "0" ]; then
  start_dnsmasq
fi

exec "$@"
