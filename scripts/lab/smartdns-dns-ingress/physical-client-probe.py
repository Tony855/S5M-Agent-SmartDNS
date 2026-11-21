#!/usr/bin/env python3
"""Send a real DNS query directly to a SmartDNS per-client ingress address.

Run this on a physical LAN client (not on the Docker host). The printed
SOURCE_ADDR is the address the host/container packet captures must observe.
"""
import argparse
import ipaddress
import socket
import struct
import sys
import random


def encode_name(name):
    labels = name.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode("idna")) > 63 for label in labels):
        raise ValueError("invalid DNS query name")
    wire = b"".join(bytes([len(label.encode("idna"))]) + label.encode("idna") for label in labels) + b"\0"
    if len(wire) > 255:
        raise ValueError("DNS query name is too long")
    return wire


def make_query(name, qtype):
    qid = random.randrange(0, 65536)
    types = {"A": 1, "AAAA": 28}
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    packet += encode_name(name) + struct.pack("!HH", types[qtype], 1)
    return qid, packet


def skip_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("invalid DNS label encoding")
        offset += 1
        if length == 0:
            return offset
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        offset += length


def parse_response(packet, qid):
    if len(packet) < 12:
        raise ValueError("DNS response is shorter than its header")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    if rid != qid or not (flags & 0x8000):
        raise ValueError("DNS response ID or QR flag does not match")
    if qdcount != 1:
        raise ValueError(f"unexpected DNS question count: {qdcount}")
    offset = skip_name(packet, 12) + 4
    if offset > len(packet):
        raise ValueError("truncated DNS question")
    answers = []
    for _ in range(ancount):
        offset = skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS resource record")
        rtype, rclass, ttl, size = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + size > len(packet):
            raise ValueError("truncated DNS resource data")
        data = packet[offset:offset + size]
        offset += size
        if rclass == 1 and rtype == 1 and size == 4:
            answers.append(socket.inet_ntop(socket.AF_INET, data))
        elif rclass == 1 and rtype == 28 and size == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, data))
    return flags & 0x000F, answers


def recv_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ValueError("truncated DNS-over-TCP response")
        chunks.extend(chunk)
    return bytes(chunks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", help="numeric IPv4 or IPv6 SmartDNS ingress address")
    parser.add_argument("name", help="DNS name to query")
    parser.add_argument("--port", type=int, default=6055)
    parser.add_argument("--transport", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--qtype", choices=("A", "AAAA"), default="A")
    parser.add_argument("--source", help="optional local source IP to bind")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0.1 <= args.timeout <= 30:
        parser.error("port or timeout is outside the permitted range")
    try:
        target = ipaddress.ip_address(args.server)
        source = ipaddress.ip_address(args.source) if args.source else None
    except ValueError as exc:
        parser.error(str(exc))
    if source and source.version != target.version:
        parser.error("--source and server must use the same address family")
    family = socket.AF_INET if target.version == 4 else socket.AF_INET6
    destination = (str(target), args.port) if family == socket.AF_INET else (str(target), args.port, 0, 0)
    bind_address = None
    if source:
        bind_address = (str(source), 0) if family == socket.AF_INET else (str(source), 0, 0, 0)
    qid, query = make_query(args.name, args.qtype)
    try:
        with socket.socket(family, socket.SOCK_DGRAM if args.transport == "udp" else socket.SOCK_STREAM) as sock:
            sock.settimeout(args.timeout)
            if bind_address:
                sock.bind(bind_address)
            if args.transport == "udp":
                sock.sendto(query, destination)
                response, peer = sock.recvfrom(65535)
            else:
                sock.connect(destination)
                sock.sendall(struct.pack("!H", len(query)) + query)
                header = recv_exact(sock, 2)
                length = struct.unpack("!H", header)[0]
                if length < 12:
                    raise ValueError("invalid DNS-over-TCP response length")
                response, peer = recv_exact(sock, length), destination
            rcode, answers = parse_response(response, qid)
            source_ip = sock.getsockname()[0]
            print(f"SOURCE_ADDR={source_ip}")
            print(f"DESTINATION={peer[0]}:{args.port}")
            print(f"TRANSPORT={args.transport} QTYPE={args.qtype} RCODE={rcode}")
            print("ANSWERS=" + (",".join(answers) if answers else "<none>"))
            if rcode != 0:
                raise ValueError(f"DNS server returned RCODE={rcode}")
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
