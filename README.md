# Docker Whitelist Gateway (Multi-Destination Edition)

A transparent outbound firewall + DNS gateway for Docker internal networks.

This project allows containers attached to **internal (isolated) Docker networks** to
reach selected external destinations while keeping all other outbound traffic blocked.

Unlike classic single-target whitelist proxies, this implementation supports:

-   Multiple external destinations (multi-destination)
-   Dynamic DNS resolution
-   Automatic subnet detection (no fixed IP configuration)
-   Internal service resolution preservation
-   Transparent TCP forwarding using iptables + asyncio

---

## Architecture Overview

The gateway is designed for environments where:

-   The main service runs in a Docker **internal network**
-   Outbound internet access must be restricted
-   Only specific domains/IPs should be reachable
-   Internal service discovery must keep working

The architecture typically uses two containers:

1.  **gateway container**
    -   Runs iptables rules
    -   Runs async TCP forwarder
    -   Runs controlled DNS (dnsmasq)
    -   Whitelists allowed destinations
2.  **net_setup sidecar (optional but recommended)**
    -   Shares network namespace with the main service
    -   Rewrites default route to gateway
    -   Rewrites /etc/resolv.conf to use gateway DNS

---

## How It Works

### Traffic Redirection

The gateway:

-   Installs NAT REDIRECT rules
-   Captures outbound TCP traffic
-   Recovers original destination using `SO_ORIGINAL_DST`
-   Forwards only if destination is allowed

All other outbound traffic is dropped.

---

### Controlled DNS

When the main container switches its resolver to the gateway:

-   Internal Docker names must still resolve
-   External domains must be filtered

The gateway:

-   Uses Docker DNS to resolve internal services
-   Runs dnsmasq for controlled external resolution
-   Returns `0.0.0.0` for non-allowed domains

Allowed example:

    transfer.einsamobile.de → 194.26.180.120

Blocked example:

    www.google.com → 0.0.0.0

---

## Required Capability

```yaml
cap_add:
    - NET_ADMIN
```

---

## Environment Variables

### ALLOWED_HOSTS (Required)

Space-separated list of domains or IPs allowed for outbound access.

```yaml
environment:
    ALLOWED_HOSTS: "api.example.com smtp.example.com 1.2.3.4"
```

---

### PORT

Default: `*`

Defines allowed TCP ports.

Examples:

```yaml
PORT: "443"
PORT: "80 443 8080"
PORT: "21 50000-51000"
```

---

### PRE_RESOLVE

Default: `0`

When enabled (`1`):

-   The gateway resolves allowed domains itself
-   Refreshes periodically
-   Avoids dependency on system DNS

---

### RESOLVE_INTERVAL

Default: `60`

DNS refresh interval in seconds when `PRE_RESOLVE=1`.

---

### DNS_UPSTREAMS

Default: `1.1.1.1 8.8.8.8`

Upstream DNS servers used by dnsmasq.

---

### DNS_INTERNAL_NAMES

Optional.

Defines internal Docker service names that must always resolve.

Example:

```yaml
DNS_INTERNAL_NAMES: "db smtp redis backend gateway"
```

Only required if the gateway replaces Docker's default resolver and you want
deterministic internal resolution.

---

## Multi-Destination Example (Generic Service)

```yaml
services:
    app:
        image: my-app
        networks:
            - internal
        cap_add:
            - NET_ADMIN
        depends_on:
            - gateway

    net_setup:
        image: docker-whitelist-gateway:latest
        network_mode: "service:app"
        cap_add:
            - NET_ADMIN
        environment:
            MODE_RUN: net_setup
            GATEWAY_NAME: gateway

    gateway:
        image: docker-whitelist-gateway:latest
        cap_add:
            - NET_ADMIN
        networks:
            - internal
            - public
        environment:
            ALLOWED_HOSTS: "api.stripe.com smtp.mailgun.org ftp.partner.com"
            PRE_RESOLVE: 1

networks:
    internal:
        internal: true
    public:
```

---

## Summary

Docker Whitelist Gateway provides:

-   Transparent outbound filtering
-   DNS-level control
-   Multi-destination support
-   Automatic dynamic routing
-   Clean separation between service and firewall logic

It is designed for secure containerized environments where outbound access must be
explicitly controlled.
