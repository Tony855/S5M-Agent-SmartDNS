#!/usr/bin/env python3
"""Send UDP and TCP packets to port 6055 from a real LAN client.

No DNS listener is required. The host verifier later confirms that each packet
arrived at both the physical host interface and the Agent network namespace
with the same source address and source port.
"""
import argparse
import errno
import ipaddress
import json
import os
import secrets
import socket
import stat
import sys
import time


def append_result(path, record):
    path = os.path.abspath(path)
    flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError("result file must be a regular file owned by this user and not group/world writable")
        os.fchmod(fd, 0o600)
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", help="routed Agent ingress IPv4 or IPv6 address")
    parser.add_argument("--port", type=int, default=6055)
    parser.add_argument("--source", help="optional local source IP")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--result-file", help="append JSONL probe evidence to this file")
    args = parser.parse_args()
    if args.port != 6055 or not 0.1 <= args.timeout <= 15:
        parser.error("this acceptance probe is restricted to port 6055 and timeout 0.1..15s")
    try:
        target = ipaddress.ip_address(args.server)
        source = ipaddress.ip_address(args.source) if args.source else None
    except ValueError as exc:
        parser.error(str(exc))
    if target.is_unspecified or target.is_loopback or target.is_link_local or target.is_multicast:
        parser.error("server must be a routed unicast ingress address")
    if source and (source.version != target.version or source.is_unspecified or source.is_loopback or source.is_link_local or source.is_multicast):
        parser.error("--source must be a routed unicast address in the same family")
    family = socket.AF_INET if target.version == 4 else socket.AF_INET6
    destination = (str(target), args.port) if family == socket.AF_INET else (str(target), args.port, 0, 0)
    bind_address = None
    if source:
        bind_address = (str(source), 0) if family == socket.AF_INET else (str(source), 0, 0, 0)

    records = []
    nonce = secrets.token_hex(12)
    marker = ("S5M-INGRESS-PROBE:" + nonce).encode()
    udp_started_at = int(time.time())
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        if bind_address:
            sock.bind(bind_address)
        sock.sendto(marker, destination)
        local = sock.getsockname()
        records.append({
            "version": 1, "transport": "udp", "source_addr": local[0],
            "source_port": local[1], "destination": str(target),
            "destination_port": args.port, "nonce": nonce, "observed_at": udp_started_at, "result": "sent",
        })

    tcp_result = "connected"
    tcp_started_at = int(time.time())
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(args.timeout)
        if bind_address:
            sock.bind(bind_address)
        code = sock.connect_ex(destination)
        local = sock.getsockname()
        if code == 0:
            sock.sendall(marker)
            tcp_result = "connected"
        elif code == errno.ECONNREFUSED:
            tcp_result = "connection-refused"
        elif code in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            tcp_result = "timeout-or-unreachable"
        else:
            raise OSError(code, os.strerror(code))
        records.append({
            "version": 1, "transport": "tcp", "source_addr": local[0],
            "source_port": local[1], "destination": str(target),
            "destination_port": args.port, "nonce": nonce, "observed_at": tcp_started_at, "result": tcp_result,
        })

    for record in records:
        if args.result_file:
            append_result(args.result_file, record)
        else:
            print(json.dumps(record, sort_keys=True))
    print(f"PROBE_SENT source={records[0]['source_addr']} destination={target}:6055 udp=sent tcp={tcp_result}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
