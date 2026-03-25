#!/usr/bin/env python3

import logging
import os
import socket
import subprocess

logger = logging.getLogger("healthcheck")


def error(message, exception=None):
    logger.error(message)
    if exception is None:
        raise SystemExit(1)
    raise exception


def _run(cmd, check=True):
    return subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _is_truthy(val: str) -> bool:
    return val.strip().lower() in {"1", "true", "yes", "on"}


def http_healthcheck():
    """Use pycurl to check if the target server is still responding via proxy (legacy mode)."""
    import re

    import pycurl

    check_url = os.environ.get("HTTP_HEALTHCHECK_URL", "http://$TARGET/")
    check_timeout_ms = int(os.environ.get("HTTP_HEALTHCHECK_TIMEOUT_MS", 2000))
    target = os.environ.get("TARGET", "localhost")
    if not target:
        error("HTTP_HEALTHCHECK enabled but TARGET is empty")

    check_url_with_target = check_url.replace("$TARGET", target)

    port = re.search(r"https?://[^:]*(?::([^/]+))?", check_url_with_target)[1]
    if not port:
        port = "80" if check_url_with_target.startswith("http://") else "443"
        ports = os.environ.get("PORT", "80 443").split()
        if port not in ports and "*" not in ports:
            port = ports[0]
            check_url_with_target = re.sub(
                r"(https?://[^/]+)", rf"\1:{port}", check_url_with_target
            )

    logger.info("checking %s via 127.0.0.1:%s", target, port)
    try:
        request = pycurl.Curl()
        request.setopt(pycurl.URL, check_url_with_target)
        # Route target:port to loopback so iptables OUTPUT (-o lo) REDIRECT applies.
        request.setopt(pycurl.RESOLVE, [f"{target}:{port}:127.0.0.1"])
        request.setopt(pycurl.CONNECTTIMEOUT_MS, check_timeout_ms)
        request.setopt(pycurl.TIMEOUT_MS, check_timeout_ms)
        request.perform()
        request.close()
    except pycurl.error as e:
        error("error while checking http connection", e)


def smtp_healthcheck():
    """Use pycurl to check if the target server is still responding via proxy (legacy mode)."""
    import re

    import pycurl

    check_url = os.environ.get("SMTP_HEALTHCHECK_URL", "smtp://$TARGET/")
    check_command = os.environ.get("SMTP_HEALTHCHECK_COMMAND", "HELP")
    check_timeout_ms = int(os.environ.get("SMTP_HEALTHCHECK_TIMEOUT_MS", 2000))
    target = os.environ.get("TARGET", "localhost")
    if not target:
        error("SMTP_HEALTHCHECK enabled but TARGET is empty")

    check_url_with_target = check_url.replace("$TARGET", target)

    port = re.search(r"smtp://[^:]*(?::([^/]+))?", check_url_with_target)[1]
    if not port:
        port = "25"
        ports = os.environ.get("PORT", "25").split()
        if port not in ports and "*" not in ports:
            port = ports[0]
            check_url_with_target = re.sub(
                r"(smtp://[^/]+)", rf"\1:{port}", check_url_with_target
            )

    logger.info("checking %s via 127.0.0.1:%s", target, port)
    try:
        request = pycurl.Curl()
        request.setopt(pycurl.URL, check_url_with_target)
        request.setopt(pycurl.CUSTOMREQUEST, check_command)
        request.setopt(pycurl.RESOLVE, [f"{target}:{port}:127.0.0.1"])
        request.setopt(pycurl.CONNECTTIMEOUT_MS, check_timeout_ms)
        request.setopt(pycurl.TIMEOUT_MS, check_timeout_ms)
        request.perform()
        request.close()
    except pycurl.error as e:
        error("error while checking smtp connection", e)


def legacy_process_healthcheck():
    """Legacy mode: check proxy listens and REDIRECT chain exists."""
    listen_port = int(os.environ.get("LISTEN_PORT", "15000"))

    try:
        with socket.create_connection(("127.0.0.1", listen_port), timeout=1.0):
            pass
    except OSError as e:
        error(f"proxy is not listening on 127.0.0.1:{listen_port}", e)

    try:
        _run(["iptables", "-t", "nat", "-S", "WHITELIST_REDIRECT"], check=True)
    except Exception as e:
        error(
            "missing iptables nat chain WHITELIST_REDIRECT (CAP_NET_ADMIN required?)", e
        )


def preresolve_healthcheck():
    """Legacy mode only: if PRE_RESOLVE=1, ensure TARGET resolves via configured NAMESERVERS."""
    if not _is_truthy(os.environ.get("PRE_RESOLVE", "0")):
        return

    from dns.resolver import Resolver

    target = os.environ.get("TARGET", "")
    if not target:
        error("PRE_RESOLVE=1 but TARGET is empty")

    r = Resolver()
    r.nameservers = os.environ.get("NAMESERVERS", "8.8.8.8").split()
    try:
        answers = r.resolve(target)
        ips = [a.address for a in answers]
        if not ips:
            error(f"{target} resolved to empty set")
    except Exception as e:
        error(f"failed to resolve {target} with NAMESERVERS", e)


def gateway_process_healthcheck():
    """Gateway mode: verify forwarding/NAT + ipset whitelist are present."""
    ipset_name = os.environ.get("IPSET_NAME", "whitelist")

    # 1) ip_forward enabled
    try:
        out = _run(["sysctl", "-n", "net.ipv4.ip_forward"], check=True).stdout.strip()
        if out != "1":
            error(f"net.ipv4.ip_forward is {out}, expected 1")
    except Exception as e:
        error("failed to read net.ipv4.ip_forward", e)

    # 2) ipset exists and has entries
    try:
        p = _run(["ipset", "list", ipset_name], check=True)
        txt = p.stdout
        found_count = False
        for line in txt.splitlines():
            if line.lower().startswith("number of entries:"):
                found_count = True
                n = int(line.split(":", 1)[1].strip())
                if n <= 0:
                    error(
                        f"ipset {ipset_name} exists but is empty (resolver not populated yet?)"
                    )
                break
        if not found_count:
            error(f"could not determine number of entries for ipset {ipset_name}")
    except Exception as e:
        error(f"ipset {ipset_name} missing (did you install ipset in the image?)", e)

    # 3) FORWARD must jump to WHITELIST_FWD
    try:
        out = _run(["iptables", "-t", "filter", "-S", "FORWARD"], check=True).stdout
        expected = "-A FORWARD -j WHITELIST_FWD"
        if expected not in out:
            error(
                f"missing jump from FORWARD to WHITELIST_FWD " f"(expected: {expected})"
            )
    except Exception as e:
        error("failed to inspect iptables filter/FORWARD rules", e)

    # 4) WHITELIST_FWD must allow established/related
    try:
        out = _run(
            ["iptables", "-t", "filter", "-S", "WHITELIST_FWD"], check=True
        ).stdout
        expected_fragment = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        if expected_fragment not in out:
            error(
                "missing RELATED,ESTABLISHED rule in WHITELIST_FWD "
                f"(expected fragment: {expected_fragment})"
            )
    except Exception as e:
        error("failed to inspect WHITELIST_FWD chain", e)

    # 5) WHITELIST_FWD must allow whitelist ipset destinations
    try:
        out = _run(
            ["iptables", "-t", "filter", "-S", "WHITELIST_FWD"], check=True
        ).stdout
        expected_fragment = f"-m set --match-set {ipset_name} dst -j ACCEPT"
        if expected_fragment not in out:
            error(
                f"missing whitelist ACCEPT rule in WHITELIST_FWD "
                f"(expected fragment: {expected_fragment})"
            )
    except Exception as e:
        error("failed to inspect whitelist ACCEPT rule in WHITELIST_FWD", e)

    # 6) POSTROUTING must jump to WHITELIST_NAT
    try:
        out = _run(["iptables", "-t", "nat", "-S", "POSTROUTING"], check=True).stdout
        expected = "-A POSTROUTING -j WHITELIST_NAT"
        if expected not in out:
            error(
                f"missing jump from POSTROUTING to WHITELIST_NAT "
                f"(expected: {expected})"
            )
    except Exception as e:
        error("failed to inspect iptables nat/POSTROUTING rules", e)

    # 7) WHITELIST_NAT must contain MASQUERADE
    try:
        out = _run(["iptables", "-t", "nat", "-S", "WHITELIST_NAT"], check=True).stdout
        expected_fragment = "-j MASQUERADE"
        if expected_fragment not in out:
            error(
                f"missing MASQUERADE rule in WHITELIST_NAT "
                f"(expected fragment: {expected_fragment})"
            )
    except Exception as e:
        error("failed to inspect WHITELIST_NAT chain", e)


def main():
    logging.basicConfig(level=logging.INFO)

    target = os.environ.get("TARGET", "").strip()
    allowed_hosts = os.environ.get("ALLOWED_HOSTS", "").strip()

    # If explicit healthchecks enabled, keep them legacy-only (they rely on loopback REDIRECT).
    if os.environ.get("HTTP_HEALTHCHECK", "0") == "1":
        http_healthcheck()
        print("OK")
        return
    if os.environ.get("SMTP_HEALTHCHECK", "0") == "1":
        smtp_healthcheck()
        print("OK")
        return

    # Auto-select mode
    if target:
        legacy_process_healthcheck()
        preresolve_healthcheck()
    elif allowed_hosts:
        gateway_process_healthcheck()
    else:
        error("Neither TARGET nor ALLOWED_HOSTS set; cannot determine mode")

    print("OK")


if __name__ == "__main__":
    main()
