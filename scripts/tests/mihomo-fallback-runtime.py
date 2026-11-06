#!/usr/bin/env python3
"""Exercise Mihomo fallback selection against controllable local HTTP proxy nodes."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "s5m-agent-smartdns:test"
NAME = "mihomo-fallback-runtime-" + str(os.getpid())
states = {"a": 204, "b": 204}
delays = {"a": 0.005, "b": 0.005}
servers = []
threads = []


class SocksProxyServer:
    """Minimal SOCKS5 proxy that returns a controllable HTTP probe response."""

    def __init__(self, node):
        self.node = node
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.server.settimeout(0.2)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        self.port = self.server.getsockname()[1]

    def serve(self):
        while True:
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client):
        with client:
            client.settimeout(3)
            try:
                greeting = client.recv(2)
                if len(greeting) != 2 or greeting[0] != 5:
                    return
                methods = client.recv(greeting[1])
                if not methods or 0 not in methods:
                    return
                client.sendall(b"\x05\x00")
                request = client.recv(4)
                if len(request) != 4 or request[0] != 5 or request[1] != 1:
                    return
                atyp = request[3]
                if atyp == 1:
                    client.recv(4)
                elif atyp == 3:
                    size = client.recv(1)
                    if not size:
                        return
                    client.recv(size[0])
                elif atyp == 4:
                    client.recv(16)
                else:
                    return
                client.recv(2)
                client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                data = client.recv(65536)
                if not data:
                    return
                time.sleep(delays[self.node])
                status = states[self.node]
                reason = b"No Content" if status == 204 else b"Service Unavailable"
                client.sendall(
                    b"HTTP/1.1 " + str(status).encode() + b" " + reason
                    + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except (OSError, IndexError):
                return

    def close(self):
        self.server.close()
        self.thread.join(timeout=1)


class HealthTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


def serve(handler, node=None):
    if node:
        handler = type("Node" + node.upper() + "Handler", (handler,), {"node": node})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    servers.append(server)
    threads.append(thread)
    return server.server_address[1]


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def api(controller):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{controller}/proxies/SMARTDNS-PROXY", timeout=2
    ) as response:
        return json.loads(response.read())


def wait_for(controller, predicate, label, timeout=25):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = api(controller)
            if predicate(last):
                print(f"PASS: {label}: now={last.get('now')}")
                return last
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"timeout waiting for {label}; last group state={last!r}")


def request_via_mihomo(mixed_port, target_port):
    conn = http.client.HTTPConnection("127.0.0.1", mixed_port, timeout=8)
    try:
        conn.request("GET", f"http://127.0.0.1:{target_port}/probe")
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def main():
    proxy_a = SocksProxyServer("a")
    proxy_b = SocksProxyServer("b")
    node_a = proxy_a.port
    node_b = proxy_b.port
    target = serve(HealthTargetHandler)
    controller = free_port()
    mixed = free_port()

    with tempfile.TemporaryDirectory(prefix="mihomo-fallback-") as temp:
        config = f"""\
mixed-port: {mixed}
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:{controller}
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: {node_a}
  - name: node-b
    type: socks5
    server: 127.0.0.1
    port: {node_b}
proxy-groups:
  - name: SMARTDNS-PROXY
    type: fallback
    proxies:
      - node-a
      - node-b
    # Use a non-loopback hostname so Mihomo cannot short-circuit the health
    # probe as local traffic; the HTTP proxy receives the absolute-form URL.
    url: http://mihomo-health-check.invalid/generate_204
    interval: 1
    timeout: 1000
    lazy: false
    expected-status: 204
rules:
  - MATCH,SMARTDNS-PROXY
"""
        Path(temp, "config.yaml").write_text(config, encoding="utf-8")
        command = [
            "docker", "run", "-d", "--rm", "--name", NAME, "--network", "host",
            "-v", f"{temp}:/tmp/mihomo:ro",
            "--entrypoint", "/usr/local/bin/mihomo", IMAGE,
            "-d", "/tmp/mihomo", "-f", "/tmp/mihomo/config.yaml",
        ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        try:
            first = wait_for(
                controller, lambda state: state.get("now") == "node-a",
                "fallback initially selects first healthy node",
            )
            members = first.get("all", [])
            if members != ["node-a", "node-b"]:
                raise RuntimeError(f"unexpected fallback members: {members!r}")

            states["a"] = 503
            wait_for(
                controller, lambda state: state.get("now") == "node-b",
                "primary outage switches to secondary",
            )

            states["a"] = 204
            wait_for(
                controller, lambda state: state.get("now") == "node-a",
                "recovered primary regains priority",
            )

            states["a"] = 503
            states["b"] = 503
            time.sleep(3)
            state = api(controller)
            if "DIRECT" in state.get("all", []) or state.get("now") == "DIRECT":
                raise RuntimeError(f"fallback exposed DIRECT when all nodes failed: {state!r}")
            status = request_via_mihomo(mixed, target)
            if status == 204:
                raise RuntimeError(
                    "request succeeded directly while both upstream proxy nodes were unhealthy"
                )
            print(
                "PASS: all upstream nodes failed; Mihomo did not fall through to DIRECT "
                f"(proxied request status={status})"
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-f", NAME],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            proxy_a.close()
            proxy_b.close()




def url_test_main():
    """Verify url-test chooses the fastest healthy proxy and adapts to latency changes."""
    proxy_a = SocksProxyServer("a")
    proxy_b = SocksProxyServer("b")
    node_a, node_b = proxy_a.port, proxy_b.port
    controller = free_port()
    mixed = free_port()
    states["a"], states["b"] = 204, 204
    delays["a"], delays["b"] = 0.18, 0.01

    with tempfile.TemporaryDirectory(prefix="mihomo-url-test-") as temp:
        config = f"""\
mixed-port: {mixed}
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:{controller}
proxies:
  - name: node-a
    type: socks5
    server: 127.0.0.1
    port: {node_a}
  - name: node-b
    type: socks5
    server: 127.0.0.1
    port: {node_b}
proxy-groups:
  - name: SMARTDNS-PROXY
    type: url-test
    proxies: [node-a, node-b]
    url: http://mihomo-health-check.invalid/generate_204
    interval: 1
    timeout: 1500
    tolerance: 0
    lazy: false
    expected-status: 204
rules:
  - MATCH,SMARTDNS-PROXY
"""
        Path(temp, "config.yaml").write_text(config, encoding="utf-8")
        name = NAME + "-url-test"
        command = [
            "docker", "run", "-d", "--rm", "--name", name, "--network", "host",
            "-v", f"{temp}:/tmp/mihomo:ro",
            "--entrypoint", "/usr/local/bin/mihomo", IMAGE,
            "-d", "/tmp/mihomo", "-f", "/tmp/mihomo/config.yaml",
        ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        try:
            wait_for(controller, lambda state: state.get("now") == "node-b",
                     "url-test initially chooses the lower-latency proxy")
            delays["a"], delays["b"] = 0.005, 0.18
            wait_for(controller, lambda state: state.get("now") == "node-a",
                     "url-test dynamically switches when another proxy becomes faster")
            state = api(controller)
            if "DIRECT" in state.get("all", []) or state.get("now") == "DIRECT":
                raise RuntimeError(f"url-test unexpectedly exposed DIRECT: {state!r}")
            print("PASS: dynamic SmartDNS upstream selection remains proxy-only")
        finally:
            subprocess.run(
                ["docker", "rm", "-f", name],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            proxy_a.close()
            proxy_b.close()



def ipv6_socks_atyp_main():
    """Verify Mihomo sends IPv6 CONNECT targets through an IPv4 SOCKS5 endpoint."""
    upstream = socket.socket()
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream.settimeout(20)
    upstream_port = upstream.getsockname()[1]
    mixed = free_port()
    observed = {}

    def read_exact(conn, size):
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise RuntimeError("unexpected EOF in SOCKS5 exchange")
            data += chunk
        return data

    def fake_socks_server():
        try:
            conn, _ = upstream.accept()
            with conn:
                conn.settimeout(5)
                greeting = read_exact(conn, 2)
                if greeting[0] != 5:
                    raise RuntimeError(f"unexpected SOCKS greeting: {greeting!r}")
                read_exact(conn, greeting[1])
                conn.sendall(b"\x05\x00")
                header = read_exact(conn, 4)
                if header[:3] != b"\x05\x01\x00":
                    raise RuntimeError(f"unexpected SOCKS CONNECT header: {header!r}")
                atyp = header[3]
                if atyp == 4:
                    address = socket.inet_ntop(socket.AF_INET6, read_exact(conn, 16))
                elif atyp == 1:
                    address = socket.inet_ntop(socket.AF_INET, read_exact(conn, 4))
                elif atyp == 3:
                    length = read_exact(conn, 1)[0]
                    address = read_exact(conn, length).decode("ascii")
                else:
                    raise RuntimeError(f"unsupported SOCKS ATYP: {atyp}")
                port = int.from_bytes(read_exact(conn, 2), "big")
                observed.update(atyp=atyp, address=address, port=port)
                # A successful CONNECT response is enough to test the upstream
                # SOCKS address encoding; no external IPv6 network is required.
                conn.sendall(b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + b"\x00\x00")
        except Exception as exc:
            observed["error"] = str(exc)

    server_thread = threading.Thread(target=fake_socks_server, daemon=True)
    name = NAME + "-ipv6-atyp"
    with tempfile.TemporaryDirectory(prefix="mihomo-ipv6-atyp-") as temp:
        config = f"""\
mixed-port: {mixed}
allow-lan: false
mode: rule
log-level: debug
proxies:
  - name: ipv4-socks-ingress
    type: socks5
    server: 127.0.0.1
    port: {upstream_port}
rules:
  - MATCH,ipv4-socks-ingress
"""
        Path(temp, "config.yaml").write_text(config, encoding="utf-8")
        command = [
            "docker", "run", "-d", "--rm", "--name", name, "--network", "host",
            "-v", f"{temp}:/tmp/mihomo:ro",
            "--entrypoint", "/usr/local/bin/mihomo", IMAGE,
            "-d", "/tmp/mihomo", "-f", "/tmp/mihomo/config.yaml",
        ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", mixed), timeout=0.5):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("Mihomo mixed-port did not become ready")

            # Start the fake upstream only after the emulated ARM64 daemon is
            # ready. QEMU startup can exceed a short accept timeout, which
            # otherwise expires before the first SOCKS CONNECT is sent.
            server_thread.start()
            with socket.create_connection(("127.0.0.1", mixed), timeout=10) as client:
                client.settimeout(10)
                client.sendall(b"\x05\x01\x00")
                if read_exact(client, 2) != b"\x05\x00":
                    raise RuntimeError("Mihomo SOCKS listener rejected no-auth method")
                target = socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
                client.sendall(b"\x05\x01\x00\x04" + target + (853).to_bytes(2, "big"))
                reply = read_exact(client, 4)
                if reply[:2] != b"\x05\x00":
                    raise RuntimeError(f"Mihomo CONNECT failed: {reply!r}")
                atyp = reply[3]
                if atyp == 4:
                    read_exact(client, 16)
                elif atyp == 1:
                    read_exact(client, 4)
                elif atyp == 3:
                    read_exact(client, read_exact(client, 1)[0])
                read_exact(client, 2)

            server_thread.join(timeout=10)
            if observed.get("error"):
                raise RuntimeError(f"fake SOCKS5 upstream failed: {observed['error']}")
            expected = {"atyp": 4, "address": "2606:4700:4700::1111", "port": 853}
            if observed != expected:
                raise RuntimeError(f"IPv6 destination was not preserved as SOCKS5 ATYP=4: {observed!r}")
            print("PASS: IPv4 SOCKS5 ingress carries IPv6 CONNECT destination as ATYP=4 to TCP/853")
        finally:
            subprocess.run(
                ["docker", "rm", "-f", name],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            upstream.close()
            server_thread.join(timeout=1)


if __name__ == "__main__":
    try:
        main()
        url_test_main()
        ipv6_socks_atyp_main()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
