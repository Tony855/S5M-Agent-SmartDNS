#!/usr/bin/env python3
"""Restricted host-side nftables reconciler for S5M Agent DNS ingress.

This component manages only its own inet table. It never creates Docker
networks, changes routes, or claims physical source-IP preservation.
"""
from __future__ import annotations
import argparse, fcntl, ipaddress, json, os, re, stat, subprocess, sys, tempfile, time
from pathlib import Path

CONFIG = Path(os.environ.get("S5M_INGRESS_CONFIG", "/etc/s5m-agent-ingress/config.json"))
ATTEST = Path(os.environ.get("S5M_INGRESS_ATTESTATION", "/run/s5m-agent-ingress/ingress.json"))
LOCK = Path("/run/lock/s5m-agent-ingress.lock")
TABLE = "s5m_agent_ingress"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")

class ConfigError(ValueError): pass

def _secure_regular(path: Path, *, max_bytes: int = 16384, require_root: bool = True) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or (require_root and st.st_uid != 0) or st.st_mode & 0o022:
        raise ConfigError(f"{path} must be a root-owned regular file and not group/world writable")
    if st.st_size > max_bytes:
        raise ConfigError(f"{path} exceeds {max_bytes} bytes")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (require_root and fst.st_uid != 0) or fst.st_mode & 0o022 or fst.st_size > max_bytes:
            raise ConfigError(f"{path} changed while opening")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ConfigError(f"{path} exceeds {max_bytes} bytes")
        return data
    finally:
        os.close(fd)

def _address(value: object, field: str):
    if not isinstance(value, str): raise ConfigError(f"{field} must be a string")
    try: ip = ipaddress.ip_address(value)
    except ValueError as e: raise ConfigError(f"invalid {field}") from e
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or getattr(ip, "ipv4_mapped", None):
        raise ConfigError(f"{field} must be a unicast non-link-local address")
    if str(ip) != value: raise ConfigError(f"{field} must use canonical address notation")
    return ip

def load_config(path: Path = CONFIG, *, require_root: bool = True) -> dict:
    raw = _secure_regular(path, require_root=require_root)
    try: cfg = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e: raise ConfigError("config must be valid UTF-8 JSON") from e
    if not isinstance(cfg, dict) or set(cfg) != {"version", "interface", "ipv4_address", "ipv6_address", "client_cidrs"}:
        raise ConfigError("config keys must be exactly version, interface, ipv4_address, ipv6_address, client_cidrs")
    if cfg["version"] != 1: raise ConfigError("unsupported config version")
    iface = cfg["interface"]
    if not isinstance(iface, str) or not IFACE_RE.fullmatch(iface) or iface in {".", ".."}:
        raise ConfigError("invalid ingress interface name")
    addresses = []
    for key, version in (("ipv4_address", 4), ("ipv6_address", 6)):
        value = cfg[key]
        if value is not None:
            ip = _address(value, key)
            if ip.version != version: raise ConfigError(f"{key} has wrong address family")
            addresses.append(ip)
    if not addresses: raise ConfigError("at least one ingress address is required")
    cidr_values = cfg["client_cidrs"]
    if not isinstance(cidr_values, list) or not cidr_values or len(cidr_values) > 128:
        raise ConfigError("client_cidrs must contain 1..128 entries")
    networks = []
    for value in cidr_values:
        if not isinstance(value, str): raise ConfigError("each client CIDR must be a string")
        try: net = ipaddress.ip_network(value, strict=True)
        except ValueError as e: raise ConfigError(f"invalid or non-canonical client CIDR: {value}") from e
        if net.prefixlen == 0 or net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified or net.is_reserved:
            raise ConfigError(f"client CIDR is not an allowed unicast network: {value}")
        networks.append(net)
    if len(set(networks)) != len(networks): raise ConfigError("duplicate client CIDR")
    for i, left in enumerate(networks):
        for right in networks[i+1:]:
            if left.version == right.version and left.overlaps(right): raise ConfigError("overlapping client CIDRs")
    if {n.version for n in networks} - {a.version for a in addresses}:
        raise ConfigError("the client CIDR family needs an address")
    return {"interface": iface, "addresses": addresses, "networks": networks}

def render_nft(cfg: dict) -> str:
    iface = cfg["interface"]
    lines = [f"table inet {TABLE} {{", "  chain forward_guard {", "    type filter hook forward priority -5; policy accept;"]
    for addr in cfg["addresses"]:
        family = "ip" if addr.version == 4 else "ip6"
        nets = [n for n in cfg["networks"] if n.version == addr.version]
        for proto in ("udp", "tcp"):
            if nets:
                set_text = ", ".join(str(n) for n in nets)
                lines.append(f'    iifname "{iface}" {family} daddr {addr} {family} saddr {{ {set_text} }} {proto} dport 6055 accept')
            lines.append(f'    {family} daddr {addr} {proto} dport 6055 drop')
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"

def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_st = path.parent.lstat()
    if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != 0 or parent_st.st_mode & 0o022:
        raise ConfigError("attestation directory must be root-owned, non-writable by group/world, and not a symlink")
    fd, tmp = tempfile.mkstemp(prefix=".ingress.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, separators=(",", ":")); f.write("\n")
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("check", "render", "apply"))
    p.add_argument("--config", type=Path, default=CONFIG)
    p.add_argument("--attestation", type=Path, default=ATTEST)
    a = p.parse_args(argv)
    try:
        if os.geteuid() != 0: raise ConfigError("must run as root")
        cfg = load_config(a.config)
        rules = render_nft(cfg)
        if a.command == "check":
            print("configuration valid; no host state changed")
            return 0
        if a.command == "render":
            sys.stdout.write(rules)
            return 0
        if subprocess.run(["ip", "link", "show", "dev", cfg["interface"]], text=True, capture_output=True).returncode:
            raise ConfigError(f"ingress interface does not exist: {cfg['interface']}")
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(lock_fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            exists = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
            transaction = (f"delete table inet {TABLE}\n" if exists.returncode == 0 else "") + rules
            check = subprocess.run(["nft", "-c", "-f", "-"], input=transaction, text=True, capture_output=True)
            if check.returncode: raise ConfigError(f"nft validation failed: {check.stderr.strip()}")
            applied = subprocess.run(["nft", "-f", "-"], input=transaction, text=True, capture_output=True)
            if applied.returncode: raise ConfigError(f"nft apply failed: {applied.stderr.strip()}")
            now = int(time.time())
            timer_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            timer_active = subprocess.run(["systemctl", "is-active", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            payload = {"version": 1, "updated_at": now, "interface": cfg["interface"],
                "ipv4_address": next((str(x) for x in cfg["addresses"] if x.version == 4), None),
                "ipv6_address": next((str(x) for x in cfg["addresses"] if x.version == 6), None),
                "client_cidrs": [str(x) for x in cfg["networks"]],
                "source_ip_preserved": False, "firewall_ready": True, "firewall_persistent": bool(timer_enabled and timer_active), "udp_ready": False, "tcp_ready": False}
            atomic_json(a.attestation, payload)
        print("nftables ingress allowlist reconciled; routed readiness and source-IP proof remain false")
        return 0
    except (ConfigError, OSError) as e:
        print(f"s5m-ingress-controller: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__": raise SystemExit(main())
