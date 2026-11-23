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
            "version": 4, "verified_at": 1000,
            "config_sha256": hashlib.sha256(raw).hexdigest(),
            "client_cidrs": ["192.168.50.0/24"],
            "ipv4_address": "172.31.10.2", "ipv6_address": None,
            "coverage": [{"cidr": "192.168.50.0/24", "transports": ["tcp", "udp"]}],
            "verified_client_sources": ["192.168.50.10"],
            "host_interface_addresses": ["192.168.1.2"],
            "host_interface_ifindex": 7, "host_interface_mac": "02:00:00:00:00:01",
            "source_ip_preserved": True, "udp_ready": True, "tcp_ready": True,
            "host_pcap_sha256": "a" * 64, "container_pcap_sha256": "b" * 64,
            "probe_results_sha256": "c" * 64, "capture_manifest_sha256": "e" * 64,
            "container": "s5m-agent", "container_id": "f" * 64,
            "container_pid": 123, "container_started_at": "2026-11-20T02:00:00.000000000Z",
            "network": "s5m-agent-ingress", "network_id": "9" * 64,
        }
        key = bytes.fromhex("ab" * 32)
        evidence["evidence_hmac_sha256"] = mod.physical_evidence_signature(evidence, key)
        self.assertTrue(mod.physical_evidence_payload_valid(evidence, raw, cfg, now=1001, evidence_key=key))
        legacy = dict(evidence); legacy["version"] = 2
        legacy["evidence_hmac_sha256"] = mod.physical_evidence_signature(legacy, key)
        self.assertFalse(mod.physical_evidence_payload_valid(legacy, raw, cfg, now=1001, evidence_key=key))
        missing_runtime_identity = dict(evidence); missing_runtime_identity.pop("container_started_at")
        missing_runtime_identity["evidence_hmac_sha256"] = mod.physical_evidence_signature(missing_runtime_identity, key)
        self.assertFalse(mod.physical_evidence_payload_valid(missing_runtime_identity, raw, cfg, now=1001, evidence_key=key))
        stale = dict(evidence); stale["verified_at"] = 0
        stale["evidence_hmac_sha256"] = mod.physical_evidence_signature(stale, key)
        self.assertFalse(mod.physical_evidence_payload_valid(stale, raw, cfg, now=1000 + 8 * 24 * 60 * 60, evidence_key=key))
        wrong = dict(evidence); wrong["config_sha256"] = "d" * 64
        wrong["evidence_hmac_sha256"] = mod.physical_evidence_signature(wrong, key)
        self.assertFalse(mod.physical_evidence_payload_valid(wrong, raw, cfg, now=1001, evidence_key=key))
        invalid_ifindex = dict(evidence); invalid_ifindex["host_interface_ifindex"] = True
        invalid_ifindex["evidence_hmac_sha256"] = mod.physical_evidence_signature(invalid_ifindex, key)
        self.assertFalse(mod.physical_evidence_payload_valid(invalid_ifindex, raw, cfg, now=1001, evidence_key=key))
        invalid_mac = dict(evidence); invalid_mac["host_interface_mac"] = "01:00:00:00:00:01"
        invalid_mac["evidence_hmac_sha256"] = mod.physical_evidence_signature(invalid_mac, key)
        self.assertFalse(mod.physical_evidence_payload_valid(invalid_mac, raw, cfg, now=1001, evidence_key=key))
        incomplete = dict(evidence); incomplete["udp_ready"] = False
        incomplete["evidence_hmac_sha256"] = mod.physical_evidence_signature(incomplete, key)
        self.assertFalse(mod.physical_evidence_payload_valid(incomplete, raw, cfg, now=1001, evidence_key=key))
        unsigned = dict(evidence); unsigned.pop("evidence_hmac_sha256")
        self.assertFalse(mod.physical_evidence_payload_valid(unsigned, raw, cfg, now=1001, evidence_key=key))
        tampered = dict(evidence); tampered["source_ip_preserved"] = False
        self.assertFalse(mod.physical_evidence_payload_valid(tampered, raw, cfg, now=1001, evidence_key=key))
        self.assertFalse(mod.physical_evidence_payload_valid(evidence, raw, cfg, now=1001, evidence_key=bytes.fromhex("cd" * 32)))
    def test_physical_evidence_is_bound_to_the_current_docker_container(self):
        evidence = {
            "container": "s5m-agent", "container_id": "a" * 64,
            "container_pid": 123, "container_started_at": "2026-11-20T02:00:00.000000000Z",
        }
        attestation_mount = [{
            "Type": "bind", "Source": str(mod.ATTEST.parent),
            "Destination": "/run/s5m-agent-ingress", "Mode": "ro", "RW": False,
        }]
        current = json.dumps([{"Id": "a" * 64, "Name": "/s5m-agent", "State": {
            "Running": True, "Pid": 123, "StartedAt": "2026-11-20T02:00:00.000000000Z",
        }, "HostConfig": {"Privileged": False, "CapAdd": ["NET_ADMIN"]}, "Mounts": attestation_mount}])
        replaced = json.dumps([{"Id": "b" * 64, "Name": "/s5m-agent", "State": {
            "Running": True, "Pid": 123, "StartedAt": "2026-11-20T02:00:00.000000000Z",
        }}])
        renamed = json.dumps([{"Id": "a" * 64, "Name": "/other-agent", "State": {
            "Running": True, "Pid": 123, "StartedAt": "2026-11-20T02:00:00.000000000Z",
        }}])
        restarted = json.dumps([{"Id": "a" * 64, "Name": "/s5m-agent", "State": {
            "Running": True, "Pid": 124, "StartedAt": "2026-11-20T02:10:00.000000000Z",
        }}])
        pid_reused = json.dumps([{"Id": "a" * 64, "Name": "/s5m-agent", "State": {
            "Running": True, "Pid": 123, "StartedAt": "2026-11-20T02:10:00.000000000Z",
        }}])
        missing_runtime_identity = json.dumps([{"Id": "a" * 64, "Name": "/s5m-agent", "State": {"Running": True}}])
        self.assertTrue(mod.physical_evidence_container_matches_current(evidence, current))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, replaced))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, renamed))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, restarted))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, pid_reused))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, missing_runtime_identity))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, "not-json"))

        writable_mount = json.loads(current)
        writable_mount[0]["Mounts"][0]["RW"] = True
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(writable_mount)))
        wrong_source = json.loads(current)
        wrong_source[0]["Mounts"][0]["Source"] = "/tmp/attestation"
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(wrong_source)))
        wrong_type = json.loads(current)
        wrong_type[0]["Mounts"][0]["Type"] = "volume"
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(wrong_type)))
        nested_writable = json.loads(current)
        nested_writable[0]["Mounts"].append({
            "Type": "bind", "Source": "/tmp/forged-ingress.json",
            "Destination": "/run/s5m-agent-ingress/ingress.json", "RW": True,
        })
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(nested_writable)))
        duplicate_mount = json.loads(current)
        duplicate_mount[0]["Mounts"].append(dict(duplicate_mount[0]["Mounts"][0]))
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(duplicate_mount)))
        privileged = json.loads(current)
        privileged[0]["HostConfig"]["Privileged"] = True
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(privileged)))
        sys_admin = json.loads(current)
        sys_admin[0]["HostConfig"]["CapAdd"] = ["NET_ADMIN", "SYS_ADMIN"]
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(sys_admin)))
        cap_all = json.loads(current)
        cap_all[0]["HostConfig"]["CapAdd"] = ["ALL"]
        self.assertFalse(mod.physical_evidence_container_matches_current(evidence, json.dumps(cap_all)))
    def test_physical_evidence_is_bound_to_current_routed_docker_network(self):
        evidence = {
            "network": "s5m-agent-ingress", "network_id": "a" * 64,
            "container": "s5m-agent", "container_id": "a" * 64,
        }
        cfg = {"interface": "eth1", "addresses": [ipaddress.ip_address("172.31.10.2")]}
        network = {
            "Id": "a" * 64, "Name": "s5m-agent-ingress", "Driver": "bridge",
            "Labels": {"com.s5m.managed": "s5m-agent-dns-ingress"},
            "Options": {
                "com.docker.network.bridge.gateway_mode_ipv4": "routed",
                "com.docker.network.bridge.trusted_host_interfaces": "eth1",
            },
            "IPAM": {"Config": [{"Subnet": "172.31.10.0/24", "Gateway": "172.31.10.1"}]},
            "Containers": {
                "a" * 64: {
                    "Name": "s5m-agent",
                    "IPv4Address": "172.31.10.2/24",
                    "IPv6Address": "",
                }
            },
        }
        container = {
            "Id": "a" * 64,
            "Name": "/s5m-agent",
            "NetworkSettings": {"Networks": {
                "s5m-agent-ingress": {"NetworkID": "a" * 64, "IPAddress": "172.31.10.2", "GlobalIPv6Address": ""}
            }},
        }
        self.assertTrue(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([network]), json.dumps([container])))
        changed_id = dict(network); changed_id["Id"] = "b" * 64
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([changed_id]), json.dumps([container])))
        changed_mode = dict(network); changed_mode["Options"] = dict(network["Options"], **{"com.docker.network.bridge.gateway_mode_ipv4": "nat"})
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([changed_mode]), json.dumps([container])))
        changed_interface = dict(network); changed_interface["Options"] = dict(network["Options"], **{"com.docker.network.bridge.trusted_host_interfaces": "eth0"})
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([changed_interface]), json.dumps([container])))
        extra_option = dict(network); extra_option["Options"] = dict(network["Options"], **{"com.docker.network.bridge.enable_ip_masquerade": "true"})
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([extra_option]), json.dumps([container])))
        changed_endpoint = {"NetworkSettings": {"Networks": {
            "s5m-agent-ingress": {"NetworkID": "a" * 64, "IPAddress": "172.31.10.99", "GlobalIPv6Address": ""}
        }}}
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([network]), json.dumps([changed_endpoint])))
        extra_same_family = json.loads(json.dumps(network))
        extra_same_family["IPAM"]["Config"].append({"Subnet": "172.32.10.0/24", "Gateway": "172.32.10.1"})
        self.assertFalse(mod.physical_evidence_network_matches_current(evidence, cfg, json.dumps([extra_same_family]), json.dumps([container])))

        # Routed bridge mode exposes every attached endpoint through the
        # trusted host interface. A rogue sidecar must invalidate the proof,
        # even when the Agent endpoint itself is unchanged.
        extra_endpoint = json.loads(json.dumps(network))
        extra_endpoint["Containers"]["b" * 64] = {
            "Name": "unexpected-sidecar",
            "IPv4Address": "172.31.10.3/24",
            "IPv6Address": "",
        }
        self.assertFalse(mod.physical_evidence_network_matches_current(
            evidence, cfg, json.dumps([extra_endpoint]), json.dumps([container])
        ))
        wrong_endpoint_name = json.loads(json.dumps(network))
        wrong_endpoint_name["Containers"]["a" * 64]["Name"] = "renamed-agent"
        self.assertFalse(mod.physical_evidence_network_matches_current(
            evidence, cfg, json.dumps([wrong_endpoint_name]), json.dumps([container])
        ))
        wrong_endpoint_address = json.loads(json.dumps(network))
        wrong_endpoint_address["Containers"]["a" * 64]["IPv4Address"] = "172.31.10.99/24"
        self.assertFalse(mod.physical_evidence_network_matches_current(
            evidence, cfg, json.dumps([wrong_endpoint_address]), json.dumps([container])
        ))
        missing_endpoint = json.loads(json.dumps(network))
        missing_endpoint["Containers"] = {}
        self.assertFalse(mod.physical_evidence_network_matches_current(
            evidence, cfg, json.dumps([missing_endpoint]), json.dumps([container])
        ))
        replaced_container = dict(container, Id="b" * 64)
        self.assertFalse(mod.physical_evidence_network_matches_current(
            evidence, cfg, json.dumps([network]), json.dumps([replaced_container])
        ))
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

    def test_live_nft_table_matches_nft_list_output_format(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        rules = [
            line.strip().replace("{ 192.168.50.0/24 }", "192.168.50.0/24").replace("{ 2001:db8:50::/64 }", "2001:db8:50::/64")
            for line in mod.render_nft(cfg).splitlines()
            if line.strip().startswith(("iifname ", "ip daddr ", "ip6 daddr "))
        ]
        live_output = "\n".join([
            f"table inet {mod.TABLE} {{",
            '    comment "managed-by:s5m-agent-ingress-v1"',
            "    chain forward_guard {",
            "        type filter hook forward priority filter - 5; policy accept;",
            *[f"        {rule}" for rule in rules],
            "    }",
            "}",
        ])
        self.assertTrue(mod.live_nft_table_matches(cfg, live_output))
        wrong_priority = live_output.replace("priority filter - 5", "priority filter - 4")
        self.assertFalse(mod.live_nft_table_matches(cfg, wrong_priority))

    def test_table_ownership_requires_exact_table_level_comment(self):
        header = f"table inet {mod.TABLE} {{"
        marker = 'comment "managed-by:s5m-agent-ingress-v1"'
        owned = "\n".join([header, "    " + marker, "    chain forward_guard {", "    }", "}"])
        self.assertTrue(mod.table_is_owned_by_controller(owned))
        inline_owned = header + " " + marker + ";\n    chain forward_guard {\n    }\n}"
        self.assertTrue(mod.table_is_owned_by_controller(inline_owned))

        # A rule comment is untrusted metadata, not proof that this controller
        # owns the table. apply/remove must never delete a foreign table merely
        # because the marker text appears somewhere in its body.
        rule_only = "\n".join([
            header,
            "    chain input {",
            '        tcp dport 22 accept comment "managed-by:s5m-agent-ingress-v1"',
            "    }",
            "}",
        ])
        self.assertFalse(mod.table_is_owned_by_controller(rule_only))
        self.assertFalse(mod.table_is_owned_by_controller("\n".join([
            header,
            "    set foreign { type ipv4_addr; }",
            "    " + marker,
            "}",
        ])))
        self.assertFalse(mod.table_is_owned_by_controller(header.replace(mod.TABLE, "foreign") + "\n    " + marker + "\n}"))
        self.assertFalse(mod.table_is_owned_by_controller(header + " " + marker + " extra;\n}"))

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

    def test_live_firewall_verify_requires_exact_live_state_and_persistent_attestation(self):
        import time
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        now = int(time.time())
        attestation_path = pathlib.Path(self.tmp.name) / "ingress.json"
        attestation = {
            "version": 1, "updated_at": now, "interface": "eth1",
            "ipv4_address": "172.31.10.2", "ipv6_address": "2001:db8:31::2",
            "client_cidrs": ["192.168.50.0/24", "2001:db8:50::/64"],
            "source_ip_preserved": False, "firewall_ready": True,
            "firewall_persistent": True, "udp_ready": False, "tcp_ready": False,
        }
        attestation_path.write_text(json.dumps(attestation))
        attestation_path.chmod(0o600)
        interface = json.dumps([{
            "ifname": "eth1", "flags": ["UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "192.168.1.2", "scope": "global"},
                {"family": "inet6", "local": "2001:db8:1::2", "scope": "global"},
            ],
        }])
        live = mod.render_nft(cfg)
        mod.verify_live_firewall(cfg, interface, live, True, True, attestation_path, now=now, require_root=False)
        with self.assertRaises(mod.ConfigError):
            mod.verify_live_firewall(cfg, interface, live, True, False, attestation_path, now=now, require_root=False)
        with self.assertRaises(mod.ConfigError):
            mod.verify_live_firewall(cfg, interface, live + "    tcp dport 6055 accept\\n", True, True, attestation_path, now=now, require_root=False)
        stale = dict(attestation)
        stale["updated_at"] = now - 91
        attestation_path.write_text(json.dumps(stale))
        attestation_path.chmod(0o600)
        with self.assertRaises(mod.ConfigError):
            mod.verify_live_firewall(cfg, interface, live, True, True, attestation_path, now=now, require_root=False)

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
        self.assertTrue(mod.interface_state_matches(cfg, valid, ["192.168.1.2", "2001:db8:1::2"]))
        self.assertFalse(mod.interface_state_matches(cfg, valid, ["192.168.1.3", "2001:db8:1::2"]))
        self.assertFalse(mod.interface_state_matches(cfg, valid, ["192.168.1.2"]))
        self.assertFalse(mod.interface_state_matches(cfg, valid.replace('"UP", ', "")))
        self.assertFalse(mod.interface_state_matches(cfg, valid.replace(', "LOWER_UP"', "")))
        no_global_ipv6 = json.loads(valid)
        no_global_ipv6[0]["addr_info"][1]["local"] = "fe80::2"
        no_global_ipv6[0]["addr_info"][1]["scope"] = "link"
        self.assertFalse(mod.interface_state_matches(cfg, json.dumps(no_global_ipv6)))
        self.assertFalse(mod.interface_state_matches(cfg, valid.replace('"ifname": "eth1"', '"ifname": "eth2"')))
        temporary = json.loads(valid)
        temporary[0]["addr_info"].append({"family": "inet6", "local": "2001:db8:1::99", "scope": "global", "flags": ["temporary"]})
        self.assertFalse(mod.interface_state_matches(cfg, json.dumps(temporary), ["192.168.1.2", "2001:db8:1::2", "2001:db8:1::99"]))

    def test_interface_attestation_rejects_duplicate_global_addresses_on_trusted_nic(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        valid = [{
            "ifname": "eth1", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "192.168.1.2", "scope": "global"},
                {"family": "inet6", "local": "2001:db8:1::2", "scope": "global"},
            ],
        }]
        for duplicate in (
            {"family": "inet", "local": "192.168.1.2", "scope": "global"},
            {"family": "inet6", "local": "2001:db8:1::2", "scope": "global"},
        ):
            with self.subTest(address=duplicate["local"]):
                snapshot = json.loads(json.dumps(valid))
                snapshot[0]["addr_info"].append(duplicate)
                self.assertFalse(mod.interface_state_matches(cfg, json.dumps(snapshot)))

    def test_interface_attestation_binds_physical_link_identity(self):
        self.write(self.valid())
        cfg = mod.load_config(self.path, require_root=False)
        snapshot = json.dumps([{
            "ifname": "eth1", "ifindex": 7, "address": "02:00:00:00:00:01",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "addr_info": [
                {"family": "inet", "local": "192.168.1.2", "scope": "global"},
                {"family": "inet6", "local": "2001:db8:1::2", "scope": "global"},
            ],
        }])
        self.assertTrue(mod.interface_state_matches(
            cfg, snapshot, ["192.168.1.2", "2001:db8:1::2"], 7, "02:00:00:00:00:01"
        ))
        self.assertFalse(mod.interface_state_matches(
            cfg, snapshot, ["192.168.1.2", "2001:db8:1::2"], 8, "02:00:00:00:00:01"
        ))
        self.assertFalse(mod.interface_state_matches(
            cfg, snapshot, ["192.168.1.2", "2001:db8:1::2"], 7, "02:00:00:00:00:02"
        ))
        self.assertFalse(mod.interface_state_matches(
            cfg, snapshot, ["192.168.1.2", "2001:db8:1::2"], 7, "01:00:00:00:00:01"
        ))

    def test_firewall_persistence_requires_permanent_timer_enablement(self):
        self.assertTrue(mod.systemd_unit_is_persistently_enabled("enabled\n", 0))
        for state in ("enabled-runtime", "static", "indirect", "generated", "transient",
                      "linked", "linked-runtime", "disabled", "masked", ""):
            with self.subTest(state=state):
                self.assertFalse(mod.systemd_unit_is_persistently_enabled(state, 0))
        self.assertFalse(mod.systemd_unit_is_persistently_enabled("enabled", 1))


if __name__ == "__main__": unittest.main()
