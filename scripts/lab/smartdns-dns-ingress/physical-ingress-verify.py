#!/usr/bin/env python3
"""Verify real LAN source-IP preservation from paired host/container pcaps."""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import stat
import struct
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "host-ingress"))
from controller import load_config, _secure_regular, EVIDENCE_KEY, read_evidence_key, physical_evidence_signature, physical_evidence_network_matches_current


def secure_read(path, require_root=True, max_bytes=2 * 1024 * 1024 * 1024):
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or (require_root and (st.st_uid != 0 or st.st_mode & 0o077)) or (not require_root and st.st_mode & 0o022):
        raise ValueError(f"{path}: expected a safe regular capture/evidence file")
    if require_root:
        parent_st = path.parent.lstat()
        if not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != 0 or parent_st.st_mode & 0o022:
            raise ValueError(f"{path.parent}: expected a root-owned non-writable directory")
    if st.st_size > max_bytes:
        raise ValueError(f"{path}: file exceeds the size limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_dev != st.st_dev or current.st_ino != st.st_ino:
            raise ValueError(f"{path}: file changed during secure open")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError(f"{path}: file exceeds the size limit")
            return data
    finally:
        if fd >= 0:
            os.close(fd)


def pcap_packets(path, data=None, require_root=True):
    if data is None:
        data = secure_read(path, require_root=require_root)
    if len(data) < 24:
        raise ValueError(f"{path}: truncated pcap global header")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise ValueError(f"{path}: unsupported pcap format")
    endian, fraction_scale = formats[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    packets = []
    while offset + 16 <= len(data):
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        if fraction >= fraction_scale:
            raise ValueError(f"{path}: invalid pcap packet timestamp fraction")
        timestamp = seconds + fraction / fraction_scale
        offset += 16
        if captured > original or offset + captured > len(data):
            raise ValueError(f"{path}: truncated pcap packet")
        frame = data[offset:offset + captured]
        offset += captured
        packet = decode_frame(frame, linktype)
        if packet:
            packet["timestamp"] = timestamp
            packets.append(packet)
    if offset != len(data):
        raise ValueError(f"{path}: malformed trailing pcap bytes")
    return packets


def decode_frame(frame, linktype):
    offset = 0
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        protocol = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        while protocol in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
    elif linktype == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None
        protocol = struct.unpack("!H", frame[14:16])[0]
        offset = 16
    elif linktype == 276:  # Linux cooked capture v2
        if len(frame) < 20:
            return None
        protocol = struct.unpack("!H", frame[0:2])[0]
        offset = 20
    elif linktype == 101:  # Raw IP
        if not frame:
            return None
        protocol = 0x0800 if frame[0] >> 4 == 4 else 0x86DD if frame[0] >> 4 == 6 else 0
    else:
        raise ValueError(f"unsupported pcap link type {linktype}")

    if protocol == 0x0800:
        if len(frame) < offset + 20:
            return None
        ip = frame[offset:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl:
            return None
        fragment = struct.unpack("!H", ip[6:8])[0]
        if fragment & 0x1FFF:
            return None
        proto = ip[9]
        src = str(ipaddress.ip_address(ip[12:16]))
        dst = str(ipaddress.ip_address(ip[16:20]))
        transport = ip[ihl:]
    elif protocol == 0x86DD:
        if len(frame) < offset + 40:
            return None
        ip = frame[offset:]
        if ip[0] >> 4 != 6:
            return None
        proto = ip[6]
        src = str(ipaddress.ip_address(ip[8:24]))
        dst = str(ipaddress.ip_address(ip[24:40]))
        pos = 40
        while proto in (0, 43, 44, 51, 60):
            if len(ip) < pos + 2:
                return None
            next_proto = ip[pos]
            if proto == 44:
                if len(ip) < pos + 8:
                    return None
                fragment = struct.unpack("!H", ip[pos + 2:pos + 4])[0]
                if fragment & 0xFFF8:
                    return None
                size = 8
            elif proto == 51:
                size = (ip[pos + 1] + 2) * 4
            else:
                size = (ip[pos + 1] + 1) * 8
            if len(ip) < pos + size:
                return None
            pos += size
            proto = next_proto
        transport = ip[pos:]
    else:
        return None

    if proto == 17:  # UDP
        if len(transport) < 8:
            return None
        sport, dport, length = struct.unpack("!HHH", transport[:6])
        if length < 8 or len(transport) < length:
            return None
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "udp", "flags": 0, "payload": transport[8:length - 0]}
    if proto == 6:  # TCP
        if len(transport) < 20:
            return None
        sport, dport, seq, ack = struct.unpack("!HHII", transport[:12])
        header_len = (transport[12] >> 4) * 4
        if header_len < 20 or len(transport) < header_len:
            return None
        flags = transport[13]
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "tcp", "seq": seq, "ack": ack, "flags": flags, "payload": transport[header_len:]}
    return None


def append_result(path, record):
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("evidence directory must be root-owned and not group/world writable")
    fd, tmp = tempfile.mkstemp(prefix=".physical-evidence.", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def correlate_probe_packets(host_packets, container_packets, key, transport, marker, result, started_at, finished_at, label="probe"):
    def matching_packet(packets):
        for packet in packets:
            if (packet["src"],packet["sport"],packet["dst"],packet["dport"],packet["proto"]) != key:
                continue
            if not started_at-5 <= packet["timestamp"] <= finished_at+5:
                continue
            if transport=="udp" and marker not in packet["payload"]:
                continue
            if transport=="tcp":
                if result=="connected":
                    if marker not in packet["payload"]:
                        continue
                elif not (packet["flags"] & 0x02):
                    continue
            return packet
        return None
    host_match=matching_packet(host_packets)
    container_match=matching_packet(container_packets)
    if not host_match or not container_match:
        raise ValueError(f"{label}: {transport} probe packet was not observed on both host LAN and Agent namespace")
    if abs(host_match["timestamp"]-container_match["timestamp"])>2:
        raise ValueError(f"{label}: {transport} host/container packet timestamps do not correlate")
    if transport=="udp" and host_match["payload"]!=container_match["payload"]:
        raise ValueError(f"{label}: UDP payload differs between host and Agent captures")
    if transport=="tcp" and (host_match.get("seq"),host_match.get("ack"))!=(container_match.get("seq"),container_match.get("ack")):
        raise ValueError(f"{label}: TCP sequence tuple differs between host and Agent captures")
    return host_match,container_match


def validate_capture_container(manifest: dict, cfg: dict) -> None:
    try:
        result=subprocess.run(["docker","inspect",manifest["container"]],check=True,capture_output=True,text=True)
        item=json.loads(result.stdout)[0]
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, IndexError, KeyError) as exc:
        raise ValueError(f"cannot verify current Agent container identity: {exc}") from exc
    if item.get("Id")!=manifest["container_id"]:
        raise ValueError("capture manifest container ID does not match the current Agent container")
    state=item.get("State")
    if not isinstance(state, dict) or state.get("Running") is not True or type(state.get("Pid")) is not int or state["Pid"]!=manifest["container_pid"]:
        raise ValueError("Agent container restarted or stopped after capture; recapture physical ingress")
    observed=set()
    for endpoint in (item.get("NetworkSettings",{}).get("Networks") or {}).values():
        for field in ("IPAddress","GlobalIPv6Address"):
            value=endpoint.get(field)
            if value:
                try: observed.add(ipaddress.ip_address(value))
                except ValueError: raise ValueError("Docker reports a noncanonical container ingress address")
    missing=set(cfg["addresses"])-observed
    if missing:
        raise ValueError("current Agent container is not attached to all configured ingress addresses: "+", ".join(sorted(map(str,missing))))
    if not isinstance(manifest.get("network"), str) or not isinstance(manifest.get("network_id"), str):
        raise ValueError("capture manifest is missing the routed Docker network identity")
    try:
        network_result=subprocess.run(["docker","network","inspect",manifest["network"]],check=True,capture_output=True,text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot verify current routed Docker network: {exc}") from exc
    if not physical_evidence_network_matches_current(manifest, cfg, network_result.stdout, result.stdout):
        raise ValueError("capture manifest routed Docker network ID/options/endpoint no longer match the current Agent")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/s5m-agent-ingress/config.json"))
    parser.add_argument("--host-pcap", type=Path, required=True)
    parser.add_argument("--container-pcap", type=Path, required=True)
    parser.add_argument("--probe-results", type=Path, required=True, help="JSONL copied from all physical clients")
    parser.add_argument("--output", type=Path, default=Path("/etc/s5m-agent-ingress/physical-evidence.json"))
    parser.add_argument("--key", type=Path, default=EVIDENCE_KEY, help="root-only per-host evidence HMAC key")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("run verifier as root on the Docker host")
    if args.host_pcap.parent.resolve() != args.container_pcap.parent.resolve():
        raise ValueError("host and Agent pcaps must be from the same capture directory")
    manifest_path = args.host_pcap.parent / "capture-manifest.json"
    manifest_raw = secure_read(manifest_path, require_root=True, max_bytes=16384)
    host_pcap_raw = secure_read(args.host_pcap, require_root=True)
    container_pcap_raw = secure_read(args.container_pcap, require_root=True)
    probe_results_raw = secure_read(args.probe_results, require_root=False, max_bytes=8 * 1024 * 1024)
    manifest = json.loads(manifest_raw)
    manifest_keys = {"version", "container", "container_id", "network", "network_id", "container_pid", "host_interface", "started_at", "finished_at", "host_pcap", "container_pcap"}
    if not isinstance(manifest, dict) or set(manifest) != manifest_keys or type(manifest.get("version")) is not int or manifest["version"] != 1:
        raise ValueError("capture manifest schema is invalid")
    if manifest["host_interface"] == "" or type(manifest["started_at"]) is not int or type(manifest["finished_at"]) is not int or type(manifest["container_pid"]) is not int or manifest["container_pid"] <= 0:
        raise ValueError("capture manifest fields are invalid")
    if manifest["host_pcap"] != args.host_pcap.name or manifest["container_pcap"] != args.container_pcap.name:
        raise ValueError("capture manifest does not match the supplied pcap files")
    if not isinstance(manifest["container"], str) or not manifest["container"] or not isinstance(manifest["container_id"], str) or len(manifest["container_id"]) != 64 or any(ch not in "0123456789abcdef" for ch in manifest["container_id"]):
        raise ValueError("capture manifest container identity is invalid")
    if not isinstance(manifest["network"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", manifest["network"]) or not isinstance(manifest["network_id"], str) or len(manifest["network_id"]) != 64 or any(ch not in "0123456789abcdef" for ch in manifest["network_id"]):
        raise ValueError("capture manifest routed Docker network identity is invalid")
    now = int(time.time())
    if manifest["finished_at"] < manifest["started_at"] or manifest["finished_at"] - manifest["started_at"] > 610 or manifest["finished_at"] > now + 30 or now - manifest["finished_at"] > 3600:
        raise ValueError("capture manifest is outside the accepted time window")
    cfg = load_config(args.config)
    if manifest["host_interface"] != cfg["interface"]:
        raise ValueError("capture host interface does not match the configured physical ingress interface")
    validate_capture_container(manifest,cfg)
    config_bytes = _secure_regular(args.config)
    host_packets = pcap_packets(args.host_pcap, host_pcap_raw)
    container_packets = pcap_packets(args.container_pcap, container_pcap_raw)
    results = []
    for line_no, line in enumerate(probe_results_raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"probe result line {line_no} is invalid JSON") from exc
        if not isinstance(item, dict) or type(item.get("version")) is not int or item.get("version") != 1:
            raise ValueError(f"probe result line {line_no} has an unsupported schema")
        results.append(item)
    if not results:
        raise ValueError("no physical client probe results supplied")

    addresses = {str(ip) for ip in cfg["addresses"]}
    coverage = {str(net): set() for net in cfg["networks"]}
    verified_sources = set()
    for item in results:
        transport = item.get("transport")
        if transport not in ("udp", "tcp") or item.get("destination_port") != 6055:
            raise ValueError("probe results may only attest UDP/TCP destination port 6055")
        if not isinstance(item.get("source_addr"), str) or not isinstance(item.get("destination"), str):
            raise ValueError("probe result source/destination must be IP strings")
        source = ipaddress.ip_address(item["source_addr"])
        destination = ipaddress.ip_address(item["destination"])
        sport = item.get("source_port")
        if str(source) != item["source_addr"] or str(destination) != item["destination"] or type(sport) is not int or not 1 <= sport <= 65535 or str(destination) not in addresses:
            raise ValueError("probe result has a non-canonical address, invalid source port, or unconfigured ingress address")
        if type(item.get("destination_port")) is not int or item["destination_port"] != 6055:
            raise ValueError("probe results may only attest destination port 6055")
        if not isinstance(item.get("nonce"), str) or len(item["nonce"]) != 24 or any(ch not in "0123456789abcdef" for ch in item["nonce"]):
            raise ValueError("probe result nonce is invalid")
        if type(item.get("observed_at")) is not int or item["observed_at"] < manifest["started_at"] - 5 or item["observed_at"] > manifest["finished_at"] + 5:
            raise ValueError("probe result timestamp is outside the capture window")
        if (transport == "udp" and item.get("result") != "sent") or (transport == "tcp" and item.get("result") not in ("connected", "connection-refused", "timeout-or-unreachable")):
            raise ValueError("probe result status is invalid")
        matching_networks = [net for net in cfg["networks"] if source.version == net.version and source in net]
        if len(matching_networks) != 1:
            raise ValueError(f"source address {source} does not belong to exactly one configured client CIDR")
        network = matching_networks[0]
        if destination.version != source.version:
            raise ValueError("probe source and ingress destination address families differ")
        key = (str(source), sport, str(destination), 6055, transport)
        correlate_probe_packets(host_packets,container_packets,key,transport,
            b"S5M-INGRESS-PROBE:"+item["nonce"].encode(),item["result"],
            manifest["started_at"],manifest["finished_at"],network)
        coverage[str(network)].add(transport)
        verified_sources.add(str(source))

    missing = {cidr: sorted({"udp", "tcp"} - transports) for cidr, transports in coverage.items() if transports != {"udp", "tcp"}}
    if missing:
        raise ValueError("each configured client CIDR needs a captured UDP and TCP probe: " + json.dumps(missing, sort_keys=True))
    now = int(time.time())
    evidence = {
        "version": 1,
        "verified_at": now,
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "client_cidrs": sorted(str(net) for net in cfg["networks"]),
        "ipv4_address": next((str(ip) for ip in cfg["addresses"] if ip.version == 4), None),
        "ipv6_address": next((str(ip) for ip in cfg["addresses"] if ip.version == 6), None),
        "coverage": [{"cidr": cidr, "transports": ["tcp", "udp"]} for cidr in sorted(coverage)],
        "verified_client_sources": sorted(verified_sources),
        "source_ip_preserved": True,
        "udp_ready": True,
        "tcp_ready": True,
        "host_pcap_sha256": hashlib.sha256(host_pcap_raw).hexdigest(),
        "container_pcap_sha256": hashlib.sha256(container_pcap_raw).hexdigest(),
        "probe_results_sha256": hashlib.sha256(probe_results_raw).hexdigest(),
        "capture_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "container": manifest["container"],
        "container_id": manifest["container_id"],
        "network": manifest["network"],
        "network_id": manifest["network_id"],
    }
    evidence_key = read_evidence_key(args.key)
    evidence["evidence_hmac_sha256"] = physical_evidence_signature(evidence, evidence_key)
    append_result(args.output, evidence)
    print("PHYSICAL_INGRESS_VERIFIED")
    print(f"evidence={args.output}")
    print(f"client_cidrs={len(cfg['networks'])} transports=udp,tcp")
    print("source_ip_preserved=true (identical source tuple observed in host and Agent namespace captures; evidence HMAC verified by host controller)")
    print("This verifies ingress packet delivery only; SmartDNS listener and proxy egress are separate checks.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
