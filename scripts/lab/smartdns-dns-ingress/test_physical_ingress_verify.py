import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("physical_ingress_verify", HERE / "physical-ingress-verify.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def ipv4_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return ip + udp


def ethernet(ip_packet):
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + ip_packet


def sll2(ip_packet, protocol=0x0800):
    header = struct.pack("!HHI HBB8s", protocol, 0, 2, 1, 0, 6, b"\x00" * 8)
    return header + ip_packet


def pcap(linktype, frames):
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
    for frame in frames:
        data += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    return data


class PhysicalIngressVerifierTests(unittest.TestCase):
    def test_reads_ethernet_udp_probe_tuple_and_marker(self):
        marker = b"S5M-INGRESS-PROBE:0123456789abcdef01234567"
        frame = ethernet(ipv4_udp("192.168.50.10", "172.31.0.10", 42000, 6055, marker))
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "host.pcap"
            path.write_bytes(pcap(1, [frame]))
            packets = VERIFY.pcap_packets(path, require_root=False)
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual((packet["src"], packet["dst"], packet["sport"], packet["dport"], packet["proto"]),
                         ("192.168.50.10", "172.31.0.10", 42000, 6055, "udp"))
        self.assertIn(marker, packet["payload"])
        self.assertEqual(packet["timestamp"], 1.0)

    def test_reads_linux_sll2_tcp_syn(self):
        tcp = struct.pack("!HHIIHHHH", 43000, 6055, 123, 0, (5 << 12) | 0x02, 65535, 0, 0)
        total = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 2, 0, 64, 6, 0,
                         bytes((192, 168, 50, 20)), bytes((172, 31, 0, 10))) + tcp
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "container.pcap"
            path.write_bytes(pcap(276, [sll2(ip)]))
            packets = VERIFY.pcap_packets(path, require_root=False)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["proto"], "tcp")
        self.assertEqual(packets[0]["flags"] & 0x02, 0x02)
        self.assertEqual(packets[0]["dport"], 6055)
        self.assertEqual(packets[0]["seq"], 123)
        self.assertEqual(packets[0]["ack"], 0)

    def test_rejects_invalid_pcap_timestamp_fraction(self):
        frame = ethernet(ipv4_udp("192.168.50.10", "172.31.0.10", 42000, 6055, b"probe"))
        data = bytearray(pcap(1, [frame]))
        data[24:28] = struct.pack("<I", 1)
        data[28:32] = struct.pack("<I", 1_000_000)
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "bad-time.pcap"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "timestamp fraction"):
                VERIFY.pcap_packets(path, require_root=False)

    def test_packet_correlation_requires_same_udp_payload_and_close_timestamps(self):
        key=("192.168.50.10",42000,"172.31.0.10",6055,"udp")
        packet={"src":key[0],"sport":key[1],"dst":key[2],"dport":key[3],"proto":"udp",
            "payload":b"S5M-INGRESS-PROBE:nonce","timestamp":10.0}
        VERIFY.correlate_probe_packets([packet],[dict(packet)],key,"udp",b"S5M-INGRESS-PROBE:nonce","sent",9,11)
        altered=dict(packet); altered["payload"]=b"S5M-INGRESS-PROBE:other"
        with self.assertRaisesRegex(ValueError,"payload differs"):
            VERIFY.correlate_probe_packets([packet],[altered],key,"udp",b"S5M-INGRESS-PROBE:nonce","sent",9,11)
        late=dict(packet); late["timestamp"]=20
        with self.assertRaisesRegex(ValueError,"timestamps"):
            VERIFY.correlate_probe_packets([packet],[late],key,"udp",b"S5M-INGRESS-PROBE:nonce","sent",9,21)

    def test_packet_correlation_requires_same_tcp_sequence_and_probe_marker(self):
        key=("192.168.50.10",42000,"172.31.0.10",6055,"tcp")
        packet={"src":key[0],"sport":key[1],"dst":key[2],"dport":key[3],"proto":"tcp",
            "payload":b"S5M-INGRESS-PROBE:nonce","timestamp":10.0,"flags":0x18,"seq":100,"ack":200}
        VERIFY.correlate_probe_packets([packet],[dict(packet)],key,"tcp",b"S5M-INGRESS-PROBE:nonce","connected",9,11)
        altered=dict(packet); altered["seq"]=101
        with self.assertRaisesRegex(ValueError,"sequence tuple"):
            VERIFY.correlate_probe_packets([packet],[altered],key,"tcp",b"S5M-INGRESS-PROBE:nonce","connected",9,11)
        syn=dict(packet); syn["payload"]=b""; syn["flags"]=0x02
        VERIFY.correlate_probe_packets([syn],[dict(syn)],key,"tcp",b"S5M-INGRESS-PROBE:nonce","connection-refused",9,11)

    def test_capture_must_match_current_container_id_pid_and_ingress_ip(self):
        manifest={"container":"s5m-agent","container_id":"a"*64,"container_pid":123}
        cfg={"addresses":[VERIFY.ipaddress.ip_address("172.31.0.10")]}
        inspected={"Id":"a"*64,"State":{"Running":True,"Pid":123},
            "NetworkSettings":{"Networks":{"ingress":{"IPAddress":"172.31.0.10","GlobalIPv6Address":""}}}}
        fake=SimpleNamespace(stdout=json.dumps([inspected]))
        with mock.patch.object(VERIFY.subprocess,"run",return_value=fake):
            VERIFY.validate_capture_container(manifest,cfg)
        inspected["Id"]="b"*64
        fake=SimpleNamespace(stdout=json.dumps([inspected]))
        with mock.patch.object(VERIFY.subprocess,"run",return_value=fake):
            with self.assertRaisesRegex(ValueError,"container ID"):
                VERIFY.validate_capture_container(manifest,cfg)

    def test_capture_rejects_restarted_container_or_missing_ingress_address(self):
        manifest={"container":"s5m-agent","container_id":"a"*64,"container_pid":123}
        cfg={"addresses":[VERIFY.ipaddress.ip_address("172.31.0.10")]}
        inspected={"Id":"a"*64,"State":{"Running":True,"Pid":124},
            "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2","GlobalIPv6Address":""}}}}
        fake=SimpleNamespace(stdout=json.dumps([inspected]))
        with mock.patch.object(VERIFY.subprocess,"run",return_value=fake):
            with self.assertRaisesRegex(ValueError,"restarted"):
                VERIFY.validate_capture_container(manifest,cfg)
        inspected["State"]["Pid"]=123
        fake=SimpleNamespace(stdout=json.dumps([inspected]))
        with mock.patch.object(VERIFY.subprocess,"run",return_value=fake):
            with self.assertRaisesRegex(ValueError,"not attached"):
                VERIFY.validate_capture_container(manifest,cfg)

    def test_rejects_truncated_capture(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "bad.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
            with self.assertRaisesRegex(ValueError, "truncated pcap global header"):
                VERIFY.pcap_packets(path, require_root=False)




if __name__ == "__main__":
    unittest.main()
