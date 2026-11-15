import json
import unittest

from ipv6_routed_probe import evaluate_routed_ipv6_publication


def safe_inspect():
    ports = {
        "6055/udp": [
            {"HostIp": "127.0.0.1", "HostPort": "32768"},
            {"HostIp": "::1", "HostPort": "32768"},
            {"HostIp": "0.0.0.0", "HostPort": ""},
            {"HostIp": "::", "HostPort": ""},
        ],
        "6055/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "32769"},
            {"HostIp": "::1", "HostPort": "32769"},
            {"HostIp": "0.0.0.0", "HostPort": ""},
            {"HostIp": "::", "HostPort": ""},
        ],
    }
    return json.dumps({
        "NetworkSettings": {
            "Ports": ports,
            "Networks": {
                "bridge": {
                    "Gateway": "172.17.0.1",
                    "IPv6Gateway": "fd00:172:17::1",
                }
            },
        }
    })


class RoutedIPv6PublicationTests(unittest.TestCase):
    def test_loopback_only_ephemeral_mappings_and_default_routes_pass(self):
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            safe_inspect(),
            "default via 172.17.0.1 dev eth0\n",
            "default via fd00:172:17::1 dev eth0 metric 1024\n",
        )
        self.assertEqual(errors, [])

    def test_allocated_non_loopback_ipv6_host_port_fails(self):
        inspect = json.loads(safe_inspect())
        inspect[0]["NetworkSettings"]["Ports"]["6055/udp"][3]["HostPort"] = "32770"
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            json.dumps(inspect),
            "default via 172.17.0.1 dev eth0\n",
            "default via fd00:172:17::1 dev eth0\n",
        )
        self.assertTrue(any("non-loopback mapping :: allocated public host port" in item for item in errors))

    def test_allocated_non_loopback_ipv4_host_port_fails(self):
        inspect = json.loads(safe_inspect())
        inspect[0]["NetworkSettings"]["Ports"]["6055/tcp"][2]["HostPort"] = "32771"
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            json.dumps(inspect),
            "default via 172.17.0.1 dev eth0\n",
            "default via fd00:172:17::1 dev eth0\n",
        )
        self.assertTrue(any("non-loopback mapping 0.0.0.0 allocated public host port" in item for item in errors))

    def test_missing_or_duplicate_host_binding_fails(self):
        inspect = json.loads(safe_inspect())
        inspect[0]["NetworkSettings"]["Ports"]["6055/tcp"].pop()
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            json.dumps(inspect),
            "default via 172.17.0.1 dev eth0\n",
            "default via fd00:172:17::1 dev eth0\n",
        )
        self.assertTrue(any("unexpected 6055 host bindings" in item for item in errors))

    def test_ambiguous_or_changed_default_route_fails(self):
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            safe_inspect(),
            "default via 172.17.0.1 dev eth0\ndefault via 172.31.0.1 dev eth1\n",
            "default via fd00:172:17::1 dev eth0\n",
        )
        self.assertTrue(any("IPv4 default route" in item for item in errors))

    def test_missing_ipv6_default_route_fails(self):
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            safe_inspect(),
            "default via 172.17.0.1 dev eth0\n",
            "",
        )
        self.assertTrue(any("IPv6 default route" in item for item in errors))

    def test_malformed_inspect_fails_closed(self):
        errors, _, _, _ = evaluate_routed_ipv6_publication(
            "not-json",
            "default via 172.17.0.1 dev eth0\n",
            "default via fd00:172:17::1 dev eth0\n",
        )
        self.assertTrue(any("invalid Docker inspect output" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
