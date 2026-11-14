#!/usr/bin/env python3
"""Restricted host-side nftables reconciler for S5M Agent DNS ingress.

This component manages only its own inet table. It never creates Docker
networks, changes routes, or claims physical source-IP preservation.
"""
from __future__ import annotations
import argparse, fcntl, hashlib, hmac, ipaddress, json, os, re, stat, subprocess, sys, tempfile, time
from contextlib import contextmanager
from pathlib import Path

CONFIG = Path(os.environ.get("S5M_INGRESS_CONFIG", "/etc/s5m-agent-ingress/config.json"))
ATTEST = Path(os.environ.get("S5M_INGRESS_ATTESTATION", "/run/s5m-agent-ingress/ingress.json"))
EVIDENCE = Path(os.environ.get("S5M_INGRESS_EVIDENCE", "/etc/s5m-agent-ingress/physical-evidence.json"))
EVIDENCE_KEY = Path(os.environ.get("S5M_INGRESS_EVIDENCE_KEY", "/etc/s5m-agent-ingress/evidence.key"))
LOCK = Path(os.environ.get("S5M_INGRESS_LOCK", "/run/s5m-agent-ingress/controller.lock"))
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

def read_evidence_key(path: Path = EVIDENCE_KEY) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise ConfigError("physical evidence HMAC key must be a root-owned regular file with mode 0600")
    raw = _secure_regular(path, max_bytes=128)
    if not re.fullmatch(rb"[0-9a-f]{64}", raw.strip()):
        raise ConfigError("physical evidence HMAC key must contain exactly 32 bytes encoded as lowercase hex")
    return bytes.fromhex(raw.strip().decode("ascii"))


def physical_evidence_signature(evidence: dict, key: bytes) -> str:
    unsigned = dict(evidence)
    unsigned.pop("evidence_hmac_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def physical_evidence_payload_valid(evidence: object, config_raw: bytes, cfg: dict, now: int | None = None, evidence_key: bytes | None = None) -> bool:
    required = {
        "version", "verified_at", "config_sha256", "client_cidrs", "ipv4_address",
        "ipv6_address", "coverage", "verified_client_sources", "source_ip_preserved",
        "udp_ready", "tcp_ready", "host_pcap_sha256", "container_pcap_sha256",
        "probe_results_sha256", "capture_manifest_sha256", "container", "container_id", "network", "network_id", "evidence_hmac_sha256",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        return False
    if not isinstance(evidence_key, bytes) or len(evidence_key) != 32:
        return False
    signature = evidence.get("evidence_hmac_sha256")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        return False
    if not hmac.compare_digest(signature, physical_evidence_signature(evidence, evidence_key)):
        return False
    if not isinstance(evidence["container"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", evidence["container"]):
        return False
    if not isinstance(evidence["container_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", evidence["container_id"]):
        return False
    if not isinstance(evidence["network"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", evidence["network"]):
        return False
    if not isinstance(evidence["network_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", evidence["network_id"]):
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


def interface_state_matches(cfg: dict, output: str) -> bool:
    try:
        records = json.loads(output)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        return False
    record = records[0]
    if record.get("ifname") != cfg["interface"] or not isinstance(record.get("flags"), list) or "UP" not in record["flags"]:
        return False
    required_families = {network.version for network in cfg["networks"]}
    observed_families = set()
    addresses = record.get("addr_info")
    if not isinstance(addresses, list):
        return False
    for item in addresses:
        if not isinstance(item, dict) or item.get("scope") != "global":
            continue
        family = item.get("family")
        local = item.get("local")
        try:
            address = ipaddress.ip_address(local)
        except (TypeError, ValueError):
            continue
        if (family == "inet" and address.version != 4) or (family == "inet6" and address.version != 6):
            continue
        if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or getattr(address, "ipv4_mapped", None):
            continue
        observed_families.add(address.version)
    return required_families.issubset(observed_families)


def physical_evidence_valid(path: Path, config_path: Path, cfg: dict, now: int | None = None) -> bool:
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            return False
        raw = _secure_regular(path, max_bytes=16384)
        evidence = json.loads(raw)
        config_raw = _secure_regular(config_path)
        evidence_key = read_evidence_key()
    except (OSError, ConfigError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not physical_evidence_payload_valid(evidence, config_raw, cfg, now, evidence_key=evidence_key):
        return False
    # A signed packet capture is tied to the Docker container that was actually
    # observed. Do not keep source-preservation readiness after redeploy has
    # replaced that container, even if the configured IP/CIDRs are unchanged.
    try:
        current = subprocess.run(
            ["docker", "inspect", evidence["container"]],
            text=True, capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    if not physical_evidence_container_matches_current(evidence, current.stdout):
        return False
    try:
        network = subprocess.run(
            ["docker", "network", "inspect", evidence["network"]],
            text=True, capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return physical_evidence_network_matches_current(evidence, cfg, network.stdout, current.stdout)


def physical_evidence_container_matches_current(evidence: dict, inspect_output: str) -> bool:
    try:
        containers = json.loads(inspect_output)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], dict):
        return False
    current = containers[0]
    state = current.get("State")
    return (
        current.get("Id") == evidence.get("container_id")
        and str(current.get("Name", "")).lstrip("/") == evidence.get("container")
        and isinstance(state, dict)
        and state.get("Running") is True
    )


def physical_evidence_network_matches_current(evidence: dict, cfg: dict, network_output: str, container_output: str) -> bool:
    try:
        networks = json.loads(network_output)
        containers = json.loads(container_output)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(networks, list) or len(networks) != 1 or not isinstance(networks[0], dict):
        return False
    if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], dict):
        return False
    network = networks[0]
    container = containers[0]
    if network.get("Id") != evidence.get("network_id") or network.get("Name") != evidence.get("network"):
        return False
    if network.get("Driver") != "bridge":
        return False
    labels = network.get("Labels")
    if not isinstance(labels, dict) or labels.get("com.s5m.managed") != "s5m-agent-dns-ingress":
        return False
    options = network.get("Options")
    if not isinstance(options, dict):
        return False
    if options.get("com.docker.network.bridge.gateway_mode_ipv4") != "routed":
        return False
    if options.get("com.docker.network.bridge.trusted_host_interfaces") != cfg.get("interface"):
        return False
    if any(address.version == 6 for address in cfg.get("addresses", [])) and options.get("com.docker.network.bridge.gateway_mode_ipv6") != "routed":
        return False
    ipam_state = network.get("IPAM")
    if not isinstance(ipam_state, dict):
        return False
    ipam = ipam_state.get("Config") or []
    if not isinstance(ipam, list):
        return False
    for address in cfg.get("addresses", []):
        if not any(
            isinstance(item, dict)
            and _network_contains_address(item.get("Subnet"), address)
            for item in ipam
        ):
            return False
    network_settings = container.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        return False
    attached_networks = network_settings.get("Networks")
    if not isinstance(attached_networks, dict):
        return False
    attached = attached_networks.get(evidence.get("network"))
    if not isinstance(attached, dict) or attached.get("NetworkID") != evidence.get("network_id"):
        return False
    expected4 = next((str(address) for address in cfg.get("addresses", []) if address.version == 4), "")
    expected6 = next((str(address) for address in cfg.get("addresses", []) if address.version == 6), "")
    return attached.get("IPAddress", "") == expected4 and attached.get("GlobalIPv6Address", "") == expected6


def _network_contains_address(raw_subnet: object, address) -> bool:
    if not isinstance(raw_subnet, str):
        return False
    try:
        subnet = ipaddress.ip_network(raw_subnet, strict=True)
    except ValueError:
        return False
    return subnet.version == address.version and address in subnet


def build_nft_transaction(table_exists: bool, rules: str) -> str:
    prefix = f"delete table inet {TABLE}\n" if table_exists else ""
    return prefix + rules

def live_nft_table_matches(cfg: dict, output: str) -> bool:
    """Attest the entire owned table, not just rules that look like our allowlist.

    Ignoring unknown nft statements is unsafe: an extra broad accept rule could
    bypass the source-CIDR allowlist while the old prefix-filtered comparison
    still reported the table as ready.
    """
    if not isinstance(output, str):
        return False

    table_header = f"table inet {TABLE} {{"
    table_comment = 'comment "managed-by:s5m-agent-ingress-v1"'
    allowed_hooks = {
        "type filter hook forward priority -5; policy accept;",
        "type filter hook forward priority filter -5; policy accept;",
        # nft list renders numeric priority -5 as the named base priority
        # plus an offset on current Ubuntu nftables builds.
        "type filter hook forward priority filter - 5; policy accept;",
    }

    def normalize_rule(value: str) -> str:
        value = re.sub(r"\{\s*([^{}]+?)\s*\}", r"\1", value)
        return re.sub(r"\s+", " ", value).strip()

    expected = []
    for line in render_nft(cfg).splitlines():
        value = line.strip()
        if value.startswith(("iifname ", "ip daddr ", "ip6 daddr ")):
            expected.append(normalize_rule(value))
    if not expected:
        return False

    table_seen = False
    table_comment_seen = False
    chain_seen = False
    chain_open = False
    table_closed = False
    hook_count = 0
    actual = []

    for raw_line in output.splitlines():
        value = raw_line.strip()
        if not value:
            continue
        value = re.sub(r"\s+# handle [0-9]+$", "", value).strip()

        if not table_seen:
            if not value.startswith(table_header):
                return False
            table_seen = True
            remainder = value[len(table_header):].strip()
            if remainder:
                if remainder.rstrip(";") != table_comment:
                    return False
                table_comment_seen = True
            continue

        if table_closed:
            # The command must return exactly the one table we own.
            return False

        if chain_open:
            if value == "}":
                chain_open = False
            elif value in allowed_hooks:
                hook_count += 1
                if hook_count > 1:
                    return False
            else:
                # Include every statement. Unknown rules must make the exact
                # comparison fail rather than silently escaping inspection.
                actual.append(normalize_rule(value))
            continue

        if value in (table_comment, table_comment + ";"):
            if table_comment_seen:
                return False
            table_comment_seen = True
        elif value == "chain forward_guard {":
            if chain_seen:
                return False
            chain_seen = True
            chain_open = True
        elif value == "}":
            table_closed = True
        else:
            # Reject extra chains, sets, maps, counters and unknown table-level
            # statements; this table has one chain and no auxiliary objects.
            return False

    return (
        table_seen
        and table_comment_seen
        and chain_seen
        and not chain_open
        and table_closed
        and hook_count == 1
        and actual == expected
    )


def validate_firewall_attestation(cfg: dict, path: Path = ATTEST, now: int | None = None, require_root: bool = True) -> dict:
    """Require a fresh controller-written attestation for this exact firewall config."""
    try:
        raw = _secure_regular(path, max_bytes=8192, require_root=require_root)
        attestation = json.loads(raw)
    except (OSError, ConfigError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ConfigError(f"fresh firewall attestation is unavailable: {e}") from e
    required = {
        "version", "updated_at", "interface", "ipv4_address", "ipv6_address",
        "client_cidrs", "source_ip_preserved", "firewall_ready", "firewall_persistent",
        "udp_ready", "tcp_ready",
    }
    if not isinstance(attestation, dict) or set(attestation) != required:
        raise ConfigError("firewall attestation schema mismatch")
    if type(attestation["version"]) is not int or attestation["version"] != 1:
        raise ConfigError("unsupported firewall attestation version")
    if type(attestation["updated_at"]) is not int:
        raise ConfigError("firewall attestation timestamp is invalid")
    current = int(time.time()) if now is None else now
    age = current - attestation["updated_at"]
    if age < -30 or age > 90:
        raise ConfigError("firewall attestation is stale")
    expected_v4 = next((str(ip) for ip in cfg["addresses"] if ip.version == 4), None)
    expected_v6 = next((str(ip) for ip in cfg["addresses"] if ip.version == 6), None)
    expected_cidrs = sorted(str(network) for network in cfg["networks"])
    if (
        attestation["interface"] != cfg["interface"]
        or attestation["ipv4_address"] != expected_v4
        or attestation["ipv6_address"] != expected_v6
        or not isinstance(attestation["client_cidrs"], list)
        or any(not isinstance(value, str) for value in attestation["client_cidrs"])
        or sorted(attestation["client_cidrs"]) != expected_cidrs
    ):
        raise ConfigError("firewall attestation does not match the exact ingress interface/address/CIDR contract")
    for key in ("source_ip_preserved", "firewall_ready", "firewall_persistent", "udp_ready", "tcp_ready"):
        if type(attestation[key]) is not bool:
            raise ConfigError(f"firewall attestation field {key} is not boolean")
    if attestation["firewall_ready"] is not True or attestation["firewall_persistent"] is not True:
        raise ConfigError("live source-CIDR firewall and persistent refresh timer are not ready")
    return attestation


def verify_live_firewall(
    cfg: dict,
    interface_output: str,
    nft_output: str,
    timer_enabled: bool,
    timer_active: bool,
    attestation_path: Path = ATTEST,
    now: int | None = None,
    require_root: bool = True,
) -> None:
    if not interface_state_matches(cfg, interface_output):
        raise ConfigError("trusted ingress interface is down or lacks a global address for every configured family")
    if not live_nft_table_matches(cfg, nft_output):
        raise ConfigError("live nftables table does not exactly match the source-CIDR allowlist")
    if timer_enabled is not True or timer_active is not True:
        raise ConfigError("firewall refresh timer must be both enabled and active before routed ingress provisioning")
    validate_firewall_attestation(cfg, attestation_path, now, require_root=require_root)


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

def invalidate_attestation(path: Path, *, require_root: bool = True) -> None:
    """Remove readiness before changing firewall state; stale proof must never survive a failed reconcile."""
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent_st = path.parent.lstat()
    if not stat.S_ISDIR(parent_st.st_mode) or (require_root and parent_st.st_uid != 0) or parent_st.st_mode & 0o022:
        raise ConfigError("attestation directory must be trusted and not group/world writable")
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

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
    p.add_argument("command", choices=("check", "render", "verify", "apply", "remove"))
    p.add_argument("--config", type=Path, default=CONFIG)
    p.add_argument("--attestation", type=Path, default=ATTEST)
    p.add_argument("--evidence", type=Path, default=EVIDENCE)
    a = p.parse_args(argv)
    try:
        if os.geteuid() != 0: raise ConfigError("must run as root")
        if a.command == "remove":
            with controller_lock():
                # Invalidate readiness first. If nft deletion fails, the host remains
                # fail-closed from the Agent/Master perspective rather than advertising
                # a firewall that may no longer exist.
                invalidate_attestation(a.attestation)
                exists = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
                if exists.returncode == 0:
                    if "managed-by:s5m-agent-ingress-v1" not in exists.stdout:
                        raise ConfigError("refusing to remove an nftables table not owned by this controller")
                    removed = subprocess.run(["nft", "delete", "table", "inet", TABLE], text=True, capture_output=True)
                    if removed.returncode: raise ConfigError(f"nft table removal failed: {removed.stderr.strip()}")
            print("owned ingress firewall table and attestation removed; Docker networks/routes were not changed")
            return 0
        if a.command == "check":
            load_config(a.config)
            print("configuration valid; no host state changed")
            return 0
        if a.command == "render":
            sys.stdout.write(render_nft(load_config(a.config)))
            return 0
        if a.command == "verify":
            cfg = load_config(a.config)
            iface = subprocess.run(["ip", "-j", "addr", "show", "dev", cfg["interface"]], text=True, capture_output=True)
            nft = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
            timer_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            timer_active = subprocess.run(["systemctl", "is-active", "--quiet", "s5m-agent-ingress.timer"]).returncode == 0
            verify_live_firewall(
                cfg,
                iface.stdout if iface.returncode == 0 else "",
                nft.stdout if nft.returncode == 0 else "",
                timer_enabled,
                timer_active,
                a.attestation,
            )
            print("live ingress interface, exact nftables allowlist, persistent timer and fresh attestation verified")
            return 0
        with controller_lock():
            # Invalidate first on every reconcile. Missing interface, invalid
            # config, ownership conflict, nft check/apply failure, or attestation
            # write failure must never leave stale readiness advertised.
            invalidate_attestation(a.attestation)
            cfg = load_config(a.config)
            rules = render_nft(cfg)
            iface = subprocess.run(["ip", "-j", "addr", "show", "dev", cfg["interface"]], text=True, capture_output=True)
            if iface.returncode or not interface_state_matches(cfg, iface.stdout):
                raise ConfigError(f"ingress interface is down or lacks a global address for every configured client family: {cfg['interface']}")
            exists = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
            if exists.returncode == 0 and "managed-by:s5m-agent-ingress-v1" not in exists.stdout:
                raise ConfigError("refusing to replace an nftables table not owned by this controller")
            transaction = build_nft_transaction(exists.returncode == 0, rules)
            check = subprocess.run(["nft", "-c", "-f", "-"], input=transaction, text=True, capture_output=True)
            if check.returncode: raise ConfigError(f"nft validation failed: {check.stderr.strip()}")
            applied = subprocess.run(["nft", "-f", "-"], input=transaction, text=True, capture_output=True)
            if applied.returncode: raise ConfigError(f"nft apply failed: {applied.stderr.strip()}")
            live = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
            if live.returncode or not live_nft_table_matches(cfg, live.stdout):
                raise ConfigError("live nftables table does not exactly match the configured source-CIDR UDP/TCP allowlist")
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
