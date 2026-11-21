#!/usr/bin/env python3
"""Validate Docker's routed IPv6 DNS publication without false-green results."""
import ipaddress
import json
import sys


def _canonical_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return str(value)


def _valid_ephemeral_port(value):
    if not isinstance(value, (str, int)):
        return False
    raw = str(value)
    if not raw.isdigit():
        return False
    port = int(raw)
    return 1 <= port <= 65535


def _single_default_route(raw, gateway):
    routes = [line.strip() for line in str(raw).splitlines() if line.strip()]
    if len(routes) != 1:
        return False
    fields = routes[0].split()
    if not fields or fields[0] != "default" or fields.count("via") != 1:
        return False
    try:
        expected = ipaddress.ip_address(gateway)
        via_index = fields.index("via")
        if via_index + 1 >= len(fields):
            return False
        observed = ipaddress.ip_address(fields[via_index + 1])
    except (TypeError, ValueError):
        return False
    return observed == expected


def evaluate_routed_ipv6_publication(inspect_json, routes4, routes6):
    errors = []
    try:
        inspected = json.loads(inspect_json)
        if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
            raise ValueError("docker inspect must contain exactly one container")
        container = inspected[0]
    except (TypeError, json.JSONDecodeError, ValueError) as exc:
        return [f"invalid Docker inspect output: {exc}"], {}, "", ""

    network_settings = container.get("NetworkSettings") or {}
    ports = network_settings.get("Ports") or {}
    networks = network_settings.get("Networks") or {}
    bridge = networks.get("bridge") or {}
    gateway4 = bridge.get("Gateway", "")
    gateway6 = bridge.get("IPv6Gateway", "")

    expected_hosts = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    for proto in ("udp", "tcp"):
        entries = ports.get(f"6055/{proto}") or []
        if not isinstance(entries, list):
            errors.append(f"{proto}: Docker port bindings are not a list")
            continue
        if len(entries) != 4 or any(not isinstance(item, dict) for item in entries):
            errors.append(f"{proto}: unexpected 6055 host bindings: {entries!r}")
            continue
        actual = [
            (_canonical_ip(item.get("HostIp", "")), item.get("HostPort", ""))
            for item in entries
        ]
        if len(actual) != 4 or {host for host, _ in actual} != expected_hosts:
            errors.append(f"{proto}: unexpected 6055 host bindings: {actual!r}")
            continue
        for host, port in actual:
            if host in ("127.0.0.1", "::1"):
                if not _valid_ephemeral_port(port):
                    errors.append(f"{proto}: loopback mapping {host} has no valid ephemeral host port")
            elif port not in ("", None):
                errors.append(f"{proto}: non-loopback mapping {host} allocated public host port {port!r}")

    if not gateway4 or not _single_default_route(routes4, gateway4):
        errors.append(f"IPv4 default route is not uniquely preserved via bridge gateway {gateway4!r}")
    if not gateway6 or not _single_default_route(routes6, gateway6):
        errors.append(f"IPv6 default route is not uniquely preserved via bridge gateway {gateway6!r}")

    return errors, ports, gateway4, gateway6


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3:
        print("usage: ipv6_routed_probe.py <docker-inspect-json> <ipv4-default-routes> <ipv6-default-routes>", file=sys.stderr)
        return 2
    errors, ports, gateway4, gateway6 = evaluate_routed_ipv6_publication(*args)
    print("6055 port mappings:", json.dumps(ports, sort_keys=True))
    print("default bridge IPv4 gateway:", gateway4, "routes:", [x.strip() for x in args[1].splitlines() if x.strip()])
    print("default bridge IPv6 gateway:", gateway6, "routes:", [x.strip() for x in args[2].splitlines() if x.strip()])
    if errors:
        for error in errors:
            print("FAIL:", error, file=sys.stderr)
        print("PROBE_RESULT=UNSAFE", file=sys.stderr)
        return 1
    print("PROBE_RESULT=SAFE_LOOPBACK_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
