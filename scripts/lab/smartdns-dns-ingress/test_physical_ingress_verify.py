import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest

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

    def test_rejects_truncated_capture(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "bad.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
            with self.assertRaisesRegex(ValueError, "truncated pcap global header"):
                VERIFY.pcap_packets(path, require_root=False)


if __name__ == "__main__":
    unittest.main()

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
