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
servers = []
threads = []


class ProxyHandler(BaseHTTPRequestHandler):
    node = ""

    def do_GET(self):
        status = states[self.node]
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, *_args):
        pass


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
    node_a = serve(ProxyHandler, "a")
    node_b = serve(ProxyHandler, "b")
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
    type: http
    server: 127.0.0.1
    port: {node_a}
  - name: node-b
    type: http
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


if __name__ == "__main__":
    try:
        main()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
