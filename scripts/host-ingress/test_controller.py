import importlib.util, ipaddress, json, pathlib, tempfile, unittest
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

    def test_nft_transaction_uses_real_newline_when_replacing_table(self):
        rules = mod.render_nft({
            "interface": "eth1",
            "addresses": [ipaddress.ip_address("172.31.10.2")],
            "networks": [ipaddress.ip_network("192.168.50.0/24")],
        })
        transaction = mod.build_nft_transaction(True, rules)
        self.assertTrue(transaction.startswith("delete table inet s5m_agent_ingress\n"))
        self.assertNotIn("\\n", transaction)

    def test_valid_config_and_rules_are_scoped(self):
        self.write(self.valid()); cfg=mod.load_config(self.path, require_root=False); rules=mod.render_nft(cfg)
        self.assertIn('iifname "eth1" ip daddr 172.31.10.2', rules)
        self.assertIn('ip daddr 172.31.10.2 drop', rules)
        self.assertIn('ip6 daddr 2001:db8:31::2 drop', rules)
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
    def test_rejects_ingress_address_overlap_and_extra_family(self):
        x = self.valid()
        x["client_cidrs"] = ["172.31.10.0/24", "2001:db8:50::/64"]
        self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path, require_root=False)
        x = self.valid()
        x["client_cidrs"] = ["192.168.50.0/24"]
        self.write(x)
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
        raw = b'{"version":1,"interface":"eth1"}\n'
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
        key = bytes.fromhex("ab" * 32)
        evidence["evidence_hmac_sha256"] = mod.physical_evidence_signature(evidence, key)
        self.assertTrue(mod.physical_evidence_payload_valid(evidence, raw, cfg, now=1001, evidence_key=key))
        stale = dict(evidence); stale["verified_at"] = 0
        stale["evidence_hmac_sha256"] = mod.physical_evidence_signature(stale, key)
        self.assertFalse(mod.physical_evidence_payload_valid(stale, raw, cfg, now=1000 + 8 * 24 * 60 * 60, evidence_key=key))
        wrong = dict(evidence); wrong["config_sha256"] = "d" * 64
        wrong["evidence_hmac_sha256"] = mod.physical_evidence_signature(wrong, key)
        self.assertFalse(mod.physical_evidence_payload_valid(wrong, raw, cfg, now=1001, evidence_key=key))
        incomplete = dict(evidence); incomplete["udp_ready"] = False
        incomplete["evidence_hmac_sha256"] = mod.physical_evidence_signature(incomplete, key)
        self.assertFalse(mod.physical_evidence_payload_valid(incomplete, raw, cfg, now=1001, evidence_key=key))
        unsigned = dict(evidence); unsigned.pop("evidence_hmac_sha256")
        self.assertFalse(mod.physical_evidence_payload_valid(unsigned, raw, cfg, now=1001, evidence_key=key))
        tampered = dict(evidence); tampered["source_ip_preserved"] = False
        self.assertFalse(mod.physical_evidence_payload_valid(tampered, raw, cfg, now=1001, evidence_key=key))
        self.assertFalse(mod.physical_evidence_payload_valid(evidence, raw, cfg, now=1001, evidence_key=bytes.fromhex("cd" * 32)))
    def test_systemd_preserves_attestation_directory_after_oneshot_exit(self):
        unit = pathlib.Path(__file__).with_name("s5m-agent-ingress.service").read_text()
        self.assertIn("RuntimeDirectory=s5m-agent-ingress", unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)


    def test_invalidate_attestation_removes_stale_readiness_and_fsyncs_parent(self):
        path = pathlib.Path(self.tmp.name) / "ingress.json"
        path.write_text('{"source_ip_preserved":true}')
        path.chmod(0o600)
        mod.invalidate_attestation(path, require_root=False)
        self.assertFalse(path.exists())

    def test_invalidate_attestation_rejects_untrusted_parent(self):
        parent = pathlib.Path(self.tmp.name) / "unsafe"
        parent.mkdir()
        parent.chmod(0o777)
        with self.assertRaises(mod.ConfigError):
            mod.invalidate_attestation(parent / "ingress.json")

    def test_live_nft_table_attestation_requires_exact_applied_rules(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        expected = mod.render_nft(cfg)
        self.assertTrue(mod.live_nft_table_matches(cfg, expected))
        normalized_singleton = expected.replace("{ 192.168.50.0/24 }", "192.168.50.0/24").replace("{ 2001:db8:50::/64 }", "2001:db8:50::/64")
        self.assertTrue(mod.live_nft_table_matches(cfg, normalized_singleton))
        self.assertFalse(mod.live_nft_table_matches(cfg, expected.replace("udp dport 6055 accept", "udp dport 53 accept", 1)))
        self.assertFalse(mod.live_nft_table_matches(cfg, expected.replace("tcp dport 6055 accept", "", 1)))
        self.assertFalse(mod.live_nft_table_matches(cfg, expected + '    ip daddr 172.31.10.2 tcp dport 80 accept\n'))

    def test_live_nft_table_rejects_unscoped_accept_and_extra_chains(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        expected = mod.render_nft(cfg)
        unscoped = expected.replace("  }\n}", "    tcp dport 6055 accept\n  }\n}")
        self.assertFalse(mod.live_nft_table_matches(cfg, unscoped))
        extra_chain = expected.replace("  }\n}", '  }\n  chain bypass {\n    type filter hook forward priority 0; policy accept;\n    tcp dport 6055 accept\n  }\n}')
        self.assertFalse(mod.live_nft_table_matches(cfg, extra_chain))
        extra_object = expected.replace("  }\n}", "  set bypass { type ipv4_addr; elements = { 0.0.0.0 }; }\n  }\n}")
        self.assertFalse(mod.live_nft_table_matches(cfg, extra_object))

    def test_interface_attestation_requires_up_nic_and_global_addresses_for_all_client_families(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        valid = json.dumps([{
            "ifname": "eth1", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "192.168.1.2", "scope": "global"},
                {"family": "inet6", "local": "2001:db8:1::2", "scope": "global"},
                {"family": "inet6", "local": "fe80::2", "scope": "link"},
            ],
        }])
        self.assertTrue(mod.interface_state_matches(cfg, valid))
        self.assertFalse(mod.interface_state_matches(cfg, valid.replace('"UP", ', "")))
        no_global_ipv6 = json.loads(valid)
        no_global_ipv6[0]["addr_info"][1]["local"] = "fe80::2"
        no_global_ipv6[0]["addr_info"][1]["scope"] = "link"
        self.assertFalse(mod.interface_state_matches(cfg, json.dumps(no_global_ipv6)))
        self.assertFalse(mod.interface_state_matches(cfg, valid.replace('"ifname": "eth1"', '"ifname": "eth2"')))

if __name__ == "__main__": unittest.main()
