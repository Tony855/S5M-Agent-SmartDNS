import importlib.util
import pathlib
import socket
import struct
import unittest

SCRIPT = pathlib.Path(__file__).with_name("physical-client-probe.py")
SPEC = importlib.util.spec_from_file_location("physical_client_probe", SCRIPT)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class PhysicalClientProbeTests(unittest.TestCase):
    def response(self, name, qtype, address):
        qid, query = PROBE.make_query(name, qtype)
        if qtype == "A":
            rtype, packed = 1, socket.inet_pton(socket.AF_INET, address)
        else:
            rtype, packed = 28, socket.inet_pton(socket.AF_INET6, address)
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        question = query[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(packed)) + packed
        return qid, header + question + answer

    def test_parses_ipv4_answer(self):
        qid, packet = self.response("example.com", "A", "192.0.2.44")
        rcode, answers = PROBE.parse_response(packet, qid)
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, ["192.0.2.44"])

    def test_parses_ipv6_answer(self):
        qid, packet = self.response("example.com", "AAAA", "2001:db8::44")
        rcode, answers = PROBE.parse_response(packet, qid)
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, ["2001:db8::44"])

    def test_rejects_wrong_transaction_id(self):
        qid, packet = self.response("example.com", "A", "192.0.2.44")
        with self.assertRaisesRegex(ValueError, "ID or QR"):
            PROBE.parse_response(packet, (qid + 1) & 0xffff)

    def test_rejects_truncated_header(self):
        with self.assertRaisesRegex(ValueError, "shorter than its header"):
            PROBE.parse_response(b"short", 1)

    def test_tcp_recv_exact_handles_fragmented_reads(self):
        class FragmentedSocket:
            def __init__(self): self.parts = [b"\x00", b"\x03", b"abc"]
            def recv(self, size):
                part = self.parts.pop(0)
                result, rest = part[:size], part[size:]
                if rest: self.parts.insert(0, rest)
                return result
        self.assertEqual(PROBE.recv_exact(FragmentedSocket(), 2), b"\x00\x03")
    def test_tcp_recv_exact_rejects_eof(self):
        class ClosedSocket:
            def recv(self, size): return b""
        with self.assertRaisesRegex(ValueError, "truncated DNS-over-TCP"):
            PROBE.recv_exact(ClosedSocket(), 2)
    def test_encodes_idna_names(self):
        wire = PROBE.encode_name("例子.测试")
        self.assertTrue(wire.endswith(b"\0"))
        self.assertLessEqual(len(wire), 255)


if __name__ == "__main__":
    unittest.main()
