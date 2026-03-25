#!/usr/bin/env python3
"""
docker-whitelist-gateway-service

Two modes (auto-selected):

1) Legacy TCP forwarder mode (backwards compatible):
   - Requires: TARGET
   - Optional: PORT (e.g. "80 443" or "*" or "21 1024-65535")
   - Optional: PRE_RESOLVE=1
   - Uses iptables NAT REDIRECT to a local TCP server that forwards to TARGET:original_port.

2) Gateway/whitelist mode (multi-destination, no ports needed):
   - Requires: ALLOWED_HOSTS (space-separated hostnames / IPs)
   - Optional: RESOLVE_INTERVAL (seconds)
   - Optional: NAMESERVERS ("8.8.8.8 1.1.1.1")
   - Optional: OUTSIDE_IFACE / INSIDE_IFACE (auto-detected if not set)
   - Optional: FORWARD_DNS=1 to allow inside containers to query external DNS directly.
                Default is 0 (recommended when running dnsmasq inside this gateway).
   - Sets up:
       * net.ipv4.ip_forward=1
       * NAT MASQUERADE out of OUTSIDE_IFACE
       * FORWARD rules allowing only dst IPs in ipset "whitelist"
   - Periodically resolves ALLOWED_HOSTS -> IPs and refreshes ipset.

Notes:
- Gateway mode does NOT start any TCP server. It's pure routing/NAT/firewall.
- You must route traffic through this container (e.g. set default route in Odoo).
"""

import asyncio
import ipaddress
import logging
import os
import random
import socket
import struct
import subprocess
from typing import Iterable, List, Optional, Sequence, Set

from dns.resolver import Resolver

logging.root.setLevel(logging.INFO)
_LOG = logging.getLogger("whitelist")


def _iface_base(name: str) -> str:
    return name.split("@", 1)[0].strip()


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _run(
    cmd: List[str], *, check: bool = True, capture: bool = False
) -> subprocess.CompletedProcess:
    verbose = os.environ.get("VERBOSE", "0") not in {"0", "", "false", "False"}
    if verbose:
        _LOG.info("Executing: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
        text=True,
    )


def _expand_ports(port_tokens: Iterable[str]) -> List[int]:
    ports: List[int] = []
    for token in port_tokens:
        token = token.strip()
        if not token:
            continue
        if token == "*":
            ports.append(-1)
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if end < start:
                raise ValueError(f"Invalid port range: {token}")
            ports.extend(list(range(start, end + 1)))
        else:
            ports.append(int(token))
    return ports


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _unique(seq: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


_SO_ORIGINAL_DST = 80


class TargetResolver:
    def __init__(self, target: str, pre_resolve: bool, resolve_interval: int):
        self.target = target
        self._resolver: Optional[Resolver] = None
        if pre_resolve:
            r = Resolver()
            r.nameservers = os.environ.get("NAMESERVERS", "8.8.8.8").split()
            self._resolver = r
        self.current_ip: Optional[str] = None
        self._pre_resolve = pre_resolve
        self._resolve_interval = resolve_interval

    def resolve_once(self) -> str:
        if not self._resolver:
            return socket.gethostbyname(self.target)
        answers = self._resolver.resolve(self.target)
        ips = [a.address for a in answers]
        if not ips:
            raise RuntimeError(f"No A records for {self.target}")
        return random.choice(ips)

    async def keep_fresh(self) -> None:
        while self.current_ip is None:
            try:
                self.current_ip = self.resolve_once()
                _LOG.info("Resolved %s to %s", self.target, self.current_ip)
            except Exception as e:
                _LOG.warning("DNS resolve failed for %s: %s", self.target, e)
                await asyncio.sleep(2)

        if not self._pre_resolve:
            return

        while True:
            await asyncio.sleep(max(1, self._resolve_interval))
            try:
                new_ip = self.resolve_once()
                if new_ip != self.current_ip:
                    _LOG.info(
                        "DNS changed for %s: %s -> %s",
                        self.target,
                        self.current_ip,
                        new_ip,
                    )
                    self.current_ip = new_ip
            except Exception as e:
                _LOG.warning("DNS refresh failed for %s: %s", self.target, e)


def _iptables_prepare_chain_nat(chain: str) -> None:
    _run(["iptables", "-t", "nat", "-N", chain], check=False)
    _run(["iptables", "-t", "nat", "-F", chain], check=True)

    if (
        _run(
            ["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "-j", chain],
            check=False,
        ).returncode
        != 0
    ):
        _run(
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", chain],
            check=True,
        )

    if (
        _run(
            [
                "iptables",
                "-t",
                "nat",
                "-C",
                "OUTPUT",
                "-o",
                "lo",
                "-p",
                "tcp",
                "-j",
                chain,
            ],
            check=False,
        ).returncode
        != 0
    ):
        _run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-p",
                "tcp",
                "-j",
                chain,
            ],
            check=True,
        )


def _setup_iptables_redirect(
    listen_port: int, ports: List[int], any_port: bool
) -> None:
    chain = "WHITELIST_REDIRECT"
    _iptables_prepare_chain_nat(chain)

    if any_port:
        _run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                chain,
                "-p",
                "tcp",
                "!",
                "--dport",
                str(listen_port),
                "-j",
                "REDIRECT",
                "--to-ports",
                str(listen_port),
            ],
            check=True,
        )
        _LOG.info("iptables: redirecting ALL tcp ports -> %s", listen_port)
        return

    for p in ports:
        if p <= 0 or p == listen_port:
            continue
        _run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                chain,
                "-p",
                "tcp",
                "--dport",
                str(p),
                "-j",
                "REDIRECT",
                "--to-ports",
                str(listen_port),
            ],
            check=True,
        )

    _LOG.info(
        "iptables: redirecting tcp ports %s -> %s",
        " ".join(str(p) for p in ports if p > 0),
        listen_port,
    )


def _get_original_dst_port(conn: socket.socket) -> int:
    data = conn.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
    _family, port = struct.unpack_from("!HH", data, 0)
    return port


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _handle_redirected(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    resolver: TargetResolver,
    target: str,
    listen_port: int,
    any_port: bool,
) -> None:
    sock = writer.get_extra_info("socket")
    if sock is None or not hasattr(sock, "getsockopt"):
        writer.close()
        return

    try:
        dst_port = _get_original_dst_port(sock)
    except Exception as e:
        _LOG.error("Failed to read original destination (SO_ORIGINAL_DST): %s", e)
        writer.close()
        return

    if dst_port == listen_port and not any_port:
        writer.close()
        return

    target_ip = resolver.current_ip or target
    try:
        r2, w2 = await asyncio.open_connection(target_ip, dst_port)
    except Exception as e:
        _LOG.info("Connect failed to %s:%s: %s", target_ip, dst_port, e)
        writer.close()
        return

    await asyncio.gather(_pipe(reader, w2), _pipe(r2, writer))


async def _run_legacy_forwarder_mode() -> None:
    mode = os.environ.get("MODE", "tcp")
    if mode != "tcp":
        raise SystemExit("This image supports MODE=tcp only (no socat).")

    target = os.environ["TARGET"]
    pre_resolve = _env_bool("PRE_RESOLVE", False)
    listen_port = _env_int("LISTEN_PORT", 15000)
    resolve_interval = _env_int("RESOLVE_INTERVAL", 60)

    ports = _expand_ports(os.environ.get("PORT", "80 443").split())
    any_port = -1 in ports

    resolver = TargetResolver(
        target, pre_resolve=pre_resolve, resolve_interval=resolve_interval
    )
    asyncio.create_task(resolver.keep_fresh())

    try:
        _setup_iptables_redirect(listen_port, ports, any_port)
    except Exception as e:
        raise SystemExit(
            "Failed to setup iptables NAT REDIRECT. You likely need CAP_NET_ADMIN "
            "(docker-compose: cap_add: [NET_ADMIN]). "
            f"Original error: {e}"
        )

    server = await asyncio.start_server(
        lambda r, w: _handle_redirected(
            r,
            w,
            resolver=resolver,
            target=target,
            listen_port=listen_port,
            any_port=any_port,
        ),
        host="0.0.0.0",
        port=listen_port,
        backlog=1024,
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    if any_port:
        _LOG.info(
            "Legacy forwarder listening on %s (redirect: ALL tcp ports -> %s; TARGET=%s)",
            addrs,
            listen_port,
            target,
        )
    else:
        _LOG.info(
            "Legacy forwarder listening on %s (redirect: %s -> %s; TARGET=%s)",
            addrs,
            " ".join(str(p) for p in ports if p > 0),
            listen_port,
            target,
        )

    async with server:
        await server.serve_forever()


def _detect_outside_iface() -> str:
    p = _run(["ip", "route", "show", "default"], check=False, capture=True)
    out = (p.stdout or "").strip()
    parts = out.split()
    if "dev" in parts:
        idx = parts.index("dev")
        if idx + 1 < len(parts):
            return _iface_base(parts[idx + 1])
    return "eth1"


def _detect_inside_iface(outside: str) -> str:
    outside = _iface_base(outside)

    p = _run(["ip", "-o", "link", "show"], check=False, capture=True)
    lines = (p.stdout or "").splitlines()

    candidates: List[str] = []
    for ln in lines:
        try:
            raw = ln.split(":", 2)[1].strip()
        except Exception:
            continue

        name = _iface_base(raw)
        if name == "lo" or name == outside:
            continue

        if name not in candidates:
            candidates.append(name)

    return candidates[0] if candidates else "eth0"


def _iptables_prepare_chain_filter(chain: str) -> None:
    _run(["iptables", "-t", "filter", "-N", chain], check=False)
    _run(["iptables", "-t", "filter", "-F", chain], check=True)

    if (
        _run(
            ["iptables", "-t", "filter", "-C", "FORWARD", "-j", chain], check=False
        ).returncode
        != 0
    ):
        _run(["iptables", "-t", "filter", "-A", "FORWARD", "-j", chain], check=True)


def _iptables_prepare_chain_postrouting(chain: str) -> None:
    _run(["iptables", "-t", "nat", "-N", chain], check=False)
    _run(["iptables", "-t", "nat", "-F", chain], check=True)

    if (
        _run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING", "-j", chain], check=False
        ).returncode
        != 0
    ):
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", chain], check=True)


def _ensure_ip_forward() -> None:
    try:
        out = _run(
            ["sysctl", "-n", "net.ipv4.ip_forward"], check=True, capture=True
        ).stdout.strip()
        if out == "1":
            return
    except Exception:
        pass

    p = _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, capture=True)
    if p.returncode != 0:
        raise RuntimeError(
            "Cannot enable net.ipv4.ip_forward from inside container. "
            "Set it in docker-compose with: sysctls: { net.ipv4.ip_forward: '1' }"
        )


def _ipset_create(name: str) -> None:
    _run(["ipset", "create", name, "hash:ip", "-exist"], check=True)


def _ipset_add(name: str, ip: str) -> None:
    _run(["ipset", "add", name, ip, "-exist"], check=True)


def _ipset_swap(tmp: str, main: str) -> None:
    _run(["ipset", "swap", tmp, main], check=True)


def _ipset_destroy(name: str) -> None:
    _run(["ipset", "destroy", name], check=False)


def _resolve_allowed_hosts(
    hosts: Sequence[str], *, nameservers: Optional[List[str]] = None
) -> Set[str]:
    ips: Set[str] = set()

    r: Optional[Resolver] = None
    if nameservers:
        r = Resolver()
        r.nameservers = nameservers

    for h in hosts:
        h = h.strip()
        if not h:
            continue
        if _is_ip_literal(h):
            ips.add(h)
            continue

        try:
            if r:
                answers = r.resolve(h, "A")
                for a in answers:
                    ips.add(a.address)
            else:
                infos = socket.getaddrinfo(
                    h, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                )
                for info in infos:
                    ips.add(info[4][0])
        except Exception as e:
            _LOG.warning("Resolve failed for %s: %s", h, e)

    return ips


def _install_gateway_rules(*, outside: str, ipset_name: str) -> None:
    """
    Rules:
    - NAT: MASQUERADE traffic leaving outside iface
    - FILTER/FORWARD:
        * accept ESTABLISHED,RELATED
        * optionally accept DNS to outside (FORWARD_DNS=1)
        * accept any non-outside -> outside if dst in ipset whitelist
        * reject any non-outside -> outside otherwise
    """
    nat_chain = "WHITELIST_NAT"
    _iptables_prepare_chain_postrouting(nat_chain)
    _run(
        ["iptables", "-t", "nat", "-A", nat_chain, "-o", outside, "-j", "MASQUERADE"],
        check=True,
    )

    fwd_chain = "WHITELIST_FWD"
    _iptables_prepare_chain_filter(fwd_chain)

    _run(
        [
            "iptables",
            "-t",
            "filter",
            "-A",
            fwd_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        check=True,
    )

    forward_dns = _env_bool("FORWARD_DNS", False)
    if forward_dns:
        _run(
            [
                "iptables",
                "-t",
                "filter",
                "-A",
                fwd_chain,
                "!",
                "-i",
                outside,
                "-o",
                outside,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            check=True,
        )
        _run(
            [
                "iptables",
                "-t",
                "filter",
                "-A",
                fwd_chain,
                "!",
                "-i",
                outside,
                "-o",
                outside,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            check=True,
        )
        _LOG.info(
            "FORWARD_DNS=1 -> allowing non-outside -> outside DNS queries directly"
        )

    _run(
        [
            "iptables",
            "-t",
            "filter",
            "-A",
            fwd_chain,
            "!",
            "-i",
            outside,
            "-o",
            outside,
            "-m",
            "set",
            "--match-set",
            ipset_name,
            "dst",
            "-j",
            "ACCEPT",
        ],
        check=True,
    )

    _run(
        [
            "iptables",
            "-t",
            "filter",
            "-A",
            fwd_chain,
            "!",
            "-i",
            outside,
            "-o",
            outside,
            "-j",
            "REJECT",
        ],
        check=True,
    )

    _LOG.info(
        "iptables gateway rules installed (outside=%s ipset=%s)",
        outside,
        ipset_name,
    )


async def _gateway_refresh_loop(
    hosts: List[str], *, interval: int, ipset_name: str
) -> None:
    nameservers = os.environ.get("NAMESERVERS")
    ns_list = nameservers.split() if nameservers else None

    _ipset_create(ipset_name)

    while True:
        try:
            ips = _resolve_allowed_hosts(hosts, nameservers=ns_list)

            for ip in sorted(ips):
                _ipset_add(ipset_name, ip)

            _LOG.info(
                "Gateway whitelist refreshed: added %d IPs for %d hosts",
                len(ips),
                len(hosts),
            )
        except Exception as e:
            _LOG.warning("Gateway whitelist refresh failed: %s", e)

        await asyncio.sleep(max(1, interval))


async def _run_gateway_mode() -> None:
    raw_hosts = os.environ.get("ALLOWED_HOSTS", "").strip()
    if not raw_hosts:
        raise SystemExit("Gateway mode requires ALLOWED_HOSTS.")

    hosts = _unique(raw_hosts.split())
    interval = _env_int("RESOLVE_INTERVAL", 60)
    ipset_name = os.environ.get("IPSET_NAME", "whitelist")

    outside = os.environ.get("OUTSIDE_IFACE") or _detect_outside_iface()

    try:
        _ensure_ip_forward()
        _ipset_create(ipset_name)
        _install_gateway_rules(outside=outside, ipset_name=ipset_name)
    except Exception as e:
        raise SystemExit(
            "Failed to setup gateway mode (iptables/ipset/sysctl). "
            "You likely need CAP_NET_ADMIN and ipset installed in the image. "
            f"Original error: {e}"
        )

    _LOG.info(
        "Gateway mode enabled: %d allowed hosts; RESOLVE_INTERVAL=%ss",
        len(hosts),
        interval,
    )
    _LOG.info("Allowed hosts: %s", " ".join(hosts))
    _LOG.info("Detected iface: outside=%s", outside)

    asyncio.create_task(
        _gateway_refresh_loop(hosts, interval=interval, ipset_name=ipset_name)
    )
    await asyncio.Event().wait()


async def _main() -> None:
    target = os.environ.get("TARGET")
    allowed_hosts = os.environ.get("ALLOWED_HOSTS", "").strip()

    if target:
        await _run_legacy_forwarder_mode()
        return

    if allowed_hosts:
        await _run_gateway_mode()
        return

    raise SystemExit("Set TARGET (legacy forwarder) or ALLOWED_HOSTS (gateway mode).")


if __name__ == "__main__":
    asyncio.run(_main())
