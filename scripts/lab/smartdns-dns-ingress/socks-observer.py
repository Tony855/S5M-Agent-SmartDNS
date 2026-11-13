#!/usr/bin/env python3
import socket
import socketserver
import struct
import sys
import threading

PORT = int(sys.argv[1])
LOG_PATH = sys.argv[2]
LOG_LOCK = threading.Lock()

def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data.extend(chunk)
    return bytes(data)

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        try:
            version, count = read_exact(sock, 2)
            if version != 5:
                return
            read_exact(sock, count)
            sock.sendall(b"\x05\x00")
            version, command, reserved, atyp = read_exact(sock, 4)
            if version != 5 or command != 1:
                return
            if atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, read_exact(sock, 4))
            elif atyp == 3:
                length = read_exact(sock, 1)[0]
                host = read_exact(sock, length).decode("ascii", "replace")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
            else:
                return
            port = struct.unpack("!H", read_exact(sock, 2))[0]
            with LOG_LOCK, open(LOG_PATH, "a", encoding="utf-8") as log:
                log.write(f"CONNECT {host}:{port}\n")
                log.flush()
            # Deliberately refuse the tunnel after recording which named
            # SOCKS listener SmartDNS selected. The test only verifies routing.
            sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        except Exception:
            return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", PORT), Handler) as server:
    server.serve_forever()
