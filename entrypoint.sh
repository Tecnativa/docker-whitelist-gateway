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
filter-aaaa

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
  set -eu
  : "${GATEWAY_NAME:?Missing GATEWAY_NAME}"

  echo "INFO: net_setup_mode: waiting for gateway DNS..."

  # Wait until gateway resolves
  for i in $(seq 1 30); do
    GW_IP="$(getent ahostsv4 "$GATEWAY_NAME" | awk '{print $1; exit}' || true)"
    [ -n "$GW_IP" ] && break
    sleep 3
  done

  if [ -z "${GW_IP:-}" ]; then
    echo "ERROR: cannot resolve $GATEWAY_NAME"
    exit 1
  fi

  echo "INFO: gateway resolved to $GW_IP"

  # Wait until gateway answers ping (network ready)
  for i in $(seq 1 30); do
    if ping -c1 -W1 "$GW_IP" >/dev/null 2>&1; then
      break
    fi
    echo "INFO: waiting for gateway network readiness..."
    sleep 3
  done

  echo "INFO: selecting correct iface for gateway..."

  # Detect iface used to reach gateway
  ODOO_DEV="$(ip -4 route get "$GW_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"

  if [ -z "${ODOO_DEV:-}" ]; then
    echo "ERROR: could not detect interface to reach gateway"
    exit 1
  fi

  echo "INFO: chosen iface=$ODOO_DEV"

  ip route replace default via "$GW_IP" dev "$ODOO_DEV"

  {
  echo "nameserver $GW_IP"
  echo "options ndots:0"
  } > /etc/resolv.conf

  echo "INFO: default route and DNS configured successfully"

  # Keep container alive without busy looping
  tail -f /dev/null
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
