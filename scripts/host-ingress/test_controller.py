import importlib.util, json, pathlib, tempfile, unittest
spec = importlib.util.spec_from_file_location("controller", pathlib.Path(__file__).with_name("controller.py"))
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "config.json"
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, obj, mode=0o600):
        self.path.write_text(json.dumps(obj)); self.path.chmod(mode)
    def valid(self):
        return {"version":1,"interface":"eth1","ipv4_address":"172.31.10.2","ipv6_address":"2001:db8:31::2","client_cidrs":["192.168.50.0/24","2001:db8:50::/64"]}
    def test_valid_config_and_rules_are_scoped(self):
        self.write(self.valid()); cfg=mod.load_config(self.path, require_root=False); rules=mod.render_nft(cfg)
        self.assertIn('iifname "eth1" ip daddr 172.31.10.2', rules)
        self.assertIn('ip daddr 172.31.10.2 udp dport 6055 drop', rules)
        self.assertIn('ip6 daddr 2001:db8:31::2 tcp dport 6055 drop', rules)
        self.assertIn("managed-by:s5m-agent-ingress-v1", rules)
        self.assertNotIn("dport 53", rules)
    def test_rejects_boolean_version_and_mapped_ipv6_cidr(self):
        x=self.valid(); x["version"]=True; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
        x=self.valid(); x["client_cidrs"]=["::ffff:192.0.2.0/120"]; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
    def test_rejects_extra_keys_and_noncanonical_cidr(self):
        x=self.valid(); x["source_ip_preserved"]=True; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
        x=self.valid(); x["client_cidrs"]=["192.168.50.1/24"]; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
    def test_rejects_overlap_and_missing_family_address(self):
        x=self.valid(); x["client_cidrs"] += ["192.168.50.0/25"]; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
        x=self.valid(); x["ipv6_address"]=None; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
    def test_production_loader_requires_root_owner(self):
        import os
        self.write(self.valid())
        if os.geteuid() != 0:
            with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
    def test_rejects_unsafe_permissions_and_symlink(self):
        self.write(self.valid(),0o666)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
        link=self.path.with_name("link.json"); link.symlink_to(self.path)
        with self.assertRaises(mod.ConfigError): mod.load_config(link, require_root=False)

    def test_physical_evidence_requires_matching_config_and_fresh_dual_transport_proof(self):
        import hashlib
        import ipaddress
        cfg = {
            "addresses": [ipaddress.ip_address("172.31.10.2")],
            "networks": [ipaddress.ip_network("192.168.50.0/24")],
        }
        raw = b'{"version":1,"interface":"eth1"}\\n'
        evidence = {
            "version": 1, "verified_at": 1000,
            "config_sha256": hashlib.sha256(raw).hexdigest(),
            "client_cidrs": ["192.168.50.0/24"],
            "ipv4_address": "172.31.10.2", "ipv6_address": None,
            "coverage": [{"cidr": "192.168.50.0/24", "transports": ["tcp", "udp"]}],
            "verified_client_sources": ["192.168.50.10"],
            "source_ip_preserved": True, "udp_ready": True, "tcp_ready": True,
            "host_pcap_sha256": "a" * 64, "container_pcap_sha256": "b" * 64,
            "probe_results_sha256": "c" * 64, "capture_manifest_sha256": "e" * 64,
        }
        self.assertTrue(mod.physical_evidence_payload_valid(evidence, raw, cfg, now=1001))
        stale = dict(evidence); stale["verified_at"] = 0
        self.assertFalse(mod.physical_evidence_payload_valid(stale, raw, cfg, now=1000 + 8 * 24 * 60 * 60))
        wrong = dict(evidence); wrong["config_sha256"] = "d" * 64
        self.assertFalse(mod.physical_evidence_payload_valid(wrong, raw, cfg, now=1001))
        incomplete = dict(evidence); incomplete["udp_ready"] = False
        self.assertFalse(mod.physical_evidence_payload_valid(incomplete, raw, cfg, now=1001))
    def test_systemd_preserves_attestation_directory_after_oneshot_exit(self):
        unit = pathlib.Path(__file__).with_name("s5m-agent-ingress.service").read_text()
        self.assertIn("RuntimeDirectory=s5m-agent-ingress", unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)

if __name__ == "__main__": unittest.main()
