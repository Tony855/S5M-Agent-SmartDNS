#!/usr/bin/env python3
"""Restricted host-side nftables reconciler for S5M Agent DNS ingress.

This component manages only its own inet table. It never creates Docker
networks, changes routes, or claims physical source-IP preservation.
"""
from __future__ import annotations
import argparse, fcntl, hashlib, ipaddress, json, os, re, stat, subprocess, sys, tempfile, time
from contextlib import contextmanager
from pathlib import Path

CONFIG = Path(os.environ.get("S5M_INGRESS_CONFIG", "/etc/s5m-agent-ingress/config.json"))
ATTEST = Path(os.environ.get("S5M_INGRESS_ATTESTATION", "/run/s5m-agent-ingress/ingress.json"))
EVIDENCE = Path(os.environ.get("S5M_INGRESS_EVIDENCE", "/etc/s5m-agent-ingress/physical-evidence.json"))
LOCK = Path("/run/s5m-agent-ingress/controller.lock")
TABLE = "s5m_agent_ingress"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")

class ConfigError(ValueError): pass

def _secure_regular(path: Path, *, max_bytes: int = 16384, require_root: bool = True) -> bytes:
    if require_root:
        parent_st = path.parent.lstat()
        if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != 0 or parent_st.st_mode & 0o022:
            raise ConfigError(f"{path.parent} must be a root-owned directory and not group/world writable")
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
    if type(cfg["version"]) is not int or cfg["version"] != 1: raise ConfigError("unsupported config version")
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
        if net.prefixlen == 0 or net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified or net.is_reserved or getattr(net.network_address, "ipv4_mapped", None):
            raise ConfigError(f"client CIDR is not an allowed unicast network: {value}")
        networks.append(net)
    if len(set(networks)) != len(networks): raise ConfigError("duplicate client CIDR")
    for i, left in enumerate(networks):
        for right in networks[i+1:]:
            if left.version == right.version and left.overlaps(right): raise ConfigError("overlapping client CIDRs")
    if {n.version for n in networks} != {a.version for a in addresses}:
        raise ConfigError("ingress address families must exactly match client CIDR families")
    for address in addresses:
        if any(network.version == address.version and address in network for network in networks):
            raise ConfigError("an ingress address must not overlap a client source CIDR")
    return {"interface": iface, "addresses": addresses, "networks": networks}

def physical_evidence_payload_valid(evidence: object, config_raw: bytes, cfg: dict, now: int | None = None) -> bool:
    required = {
        "version", "verified_at", "config_sha256", "client_cidrs", "ipv4_address",
        "ipv6_address", "coverage", "verified_client_sources", "source_ip_preserved",
        "udp_ready", "tcp_ready", "host_pcap_sha256", "container_pcap_sha256",
        "probe_results_sha256", "capture_manifest_sha256",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        return False
    if type(evidence["version"]) is not int or evidence["version"] != 1:
        return False
    if type(evidence["verified_at"]) is not int:
        return False
    current = int(time.time()) if now is None else now
    age = current - evidence["verified_at"]
    if age < -30 or age > 7 * 24 * 60 * 60:
        return False
    if evidence["config_sha256"] != hashlib.sha256(config_raw).hexdigest():
        return False
    expected_cidrs = sorted(str(net) for net in cfg["networks"])
    expected_v4 = next((str(ip) for ip in cfg["addresses"] if ip.version == 4), None)
    expected_v6 = next((str(ip) for ip in cfg["addresses"] if ip.version == 6), None)
    if evidence["client_cidrs"] != expected_cidrs or evidence["ipv4_address"] != expected_v4 or evidence["ipv6_address"] != expected_v6:
        return False
    expected_coverage = [{"cidr": cidr, "transports": ["tcp", "udp"]} for cidr in expected_cidrs]
    if evidence["coverage"] != expected_coverage:
        return False
    sources = evidence["verified_client_sources"]
    if not isinstance(sources, list) or not sources or any(not isinstance(value, str) for value in sources):
        return False
    try:
        parsed_sources = [ipaddress.ip_address(value) for value in sources]
    except ValueError:
        return False
    if any(str(source) != raw for source, raw in zip(parsed_sources, sources)) or len(set(parsed_sources)) != len(parsed_sources):
        return False
    for source in parsed_sources:
        if sum(source.version == network.version and source in network for network in cfg["networks"]) != 1:
            return False
    for network in cfg["networks"]:
        if not any(source.version == network.version and source in network for source in parsed_sources):
            return False
    if evidence["source_ip_preserved"] is not True or evidence["udp_ready"] is not True or evidence["tcp_ready"] is not True:
        return False
    for key in ("host_pcap_sha256", "container_pcap_sha256", "probe_results_sha256", "capture_manifest_sha256"):
        value = evidence[key]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            return False
    return True


def physical_evidence_valid(path: Path, config_path: Path, cfg: dict, now: int | None = None) -> bool:
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            return False
        raw = _secure_regular(path, max_bytes=16384)
        evidence = json.loads(raw)
        config_raw = _secure_regular(config_path)
    except (OSError, ConfigError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return physical_evidence_payload_valid(evidence, config_raw, cfg, now)


def render_nft(cfg: dict) -> str:
    iface = cfg["interface"]
    lines = [f'table inet {TABLE} {{ comment "managed-by:s5m-agent-ingress-v1";', "  chain forward_guard {", "    type filter hook forward priority -5; policy accept;"]
    for addr in cfg["addresses"]:
        family = "ip" if addr.version == 4 else "ip6"
        nets = [n for n in cfg["networks"] if n.version == addr.version]
        for proto in ("udp", "tcp"):
            if nets:
                set_text = ", ".join(str(n) for n in nets)
                lines.append(f'    iifname "{iface}" {family} daddr {addr} {family} saddr {{ {set_text} }} {proto} dport 6055 accept')
        # Docker trusted_host_interfaces can make other container ports directly
        # reachable. The ingress address is DNS-only: drop every other forwarded
        # packet to it, regardless of protocol, port, or source interface.
        lines.append(f'    {family} daddr {addr} drop')
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"

@contextmanager
def controller_lock():
    LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_st = LOCK.parent.lstat()
    if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != 0 or parent_st.st_mode & 0o022:
        raise ConfigError("controller lock directory must be root-owned and not group/world writable")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(LOCK, flags, 0o600)
    try:
        lock_st = os.fstat(fd)
        if not stat.S_ISREG(lock_st.st_mode) or lock_st.st_uid != 0 or lock_st.st_mode & 0o022:
            raise ConfigError("controller lock must be a root-owned regular file and not group/world writable")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fd = -1
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
    finally:
        if fd >= 0:
            os.close(fd)

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
    p.add_argument("command", choices=("check", "render", "apply", "remove"))
    p.add_argument("--config", type=Path, default=CONFIG)
    p.add_argument("--attestation", type=Path, default=ATTEST)
    p.add_argument("--evidence", type=Path, default=EVIDENCE)
    a = p.parse_args(argv)
    try:
        if os.geteuid() != 0: raise ConfigError("must run as root")
        if a.command == "remove":
            with controller_lock():
                exists = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
                if exists.returncode == 0:
                    if "managed-by:s5m-agent-ingress-v1" not in exists.stdout:
                        raise ConfigError("refusing to remove an nftables table not owned by this controller")
                    removed = subprocess.run(["nft", "delete", "table", "inet", TABLE], text=True, capture_output=True)
                    if removed.returncode: raise ConfigError(f"nft table removal failed: {removed.stderr.strip()}")
                if a.attestation.parent.exists():
                    parent_st = a.attestation.parent.lstat()
                    if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != 0 or parent_st.st_mode & 0o022:
                        raise ConfigError("attestation directory is not trusted")
                    a.attestation.unlink(missing_ok=True)
                    dfd = os.open(a.attestation.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try: os.fsync(dfd)
                    finally: os.close(dfd)
            print("owned ingress firewall table and attestation removed; Docker networks/routes were not changed")
            return 0
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
        with controller_lock():
            exists = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
            if exists.returncode == 0 and "managed-by:s5m-agent-ingress-v1" not in exists.stdout:
                raise ConfigError("refusing to replace an nftables table not owned by this controller")
            transaction = (f"delete table inet {TABLE}\n" if exists.returncode == 0 else "") + rules
            check = subprocess.run(["nft", "-c", "-f", "-"], input=transaction, text=True, capture_output=True)
            if check.returncode: raise ConfigError(f"nft validation failed: {check.stderr.strip()}")
            applied = subprocess.run(["nft", "-f", "-"], input=transaction, text=True, capture_output=True)
            if applied.returncode: raise ConfigError(f"nft apply failed: {applied.stderr.strip()}")
            now = int(time.time())
            timer_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            timer_active = subprocess.run(["systemctl", "is-active", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            physical_ok = physical_evidence_valid(a.evidence, a.config, cfg, now)
            payload = {"version": 1, "updated_at": now, "interface": cfg["interface"],
                "ipv4_address": next((str(x) for x in cfg["addresses"] if x.version == 4), None),
                "ipv6_address": next((str(x) for x in cfg["addresses"] if x.version == 6), None),
                "client_cidrs": [str(x) for x in cfg["networks"]],
                "source_ip_preserved": physical_ok, "firewall_ready": True, "firewall_persistent": bool(timer_enabled and timer_active), "udp_ready": physical_ok, "tcp_ready": physical_ok}
            atomic_json(a.attestation, payload)
        if physical_ok:
            print("nftables ingress allowlist reconciled; fresh physical UDP/TCP source-IP evidence accepted")
        else:
            print("nftables ingress allowlist reconciled; physical source-IP evidence missing/stale/mismatched, ingress remains fail-closed")
        return 0
    except (ConfigError, OSError) as e:
        print(f"s5m-ingress-controller: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__": raise SystemExit(main())
