#!/usr/bin/env python3
import socket
import struct
import sys
import time

HOST, PORT = "172.31.0.10", 6055
NAME, TRANSPORT = sys.argv[1], sys.argv[2]
qid = b"\x6b\x2c"
qname = b"".join(bytes([len(x)]) + x.encode() for x in NAME.split(".")) + b"\0"
question = qid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
if TRANSPORT == "udp":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(question, (HOST, PORT))
        time.sleep(0.25)
else:
    with socket.create_connection((HOST, PORT), timeout=2) as sock:
        sock.sendall(struct.pack("!H", len(question)) + question)
        time.sleep(0.25)
print(f"SENT {TRANSPORT} {NAME}")
