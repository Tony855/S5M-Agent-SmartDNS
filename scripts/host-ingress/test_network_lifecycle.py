import importlib.util, json, os, tempfile, unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).with_name("network-lifecycle.py")
spec = importlib.util.spec_from_file_location("network_lifecycle", MODULE)
nl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nl)

def valid_config():
    return {
        "version": 1, "network": "s5m-agent-ingress", "container": "s5m-agent",
        "interface": "eth1",
        "ipv4_subnet": "172.31.10.0/24", "ipv4_gateway": "172.31.10.1", "ipv4_address": "172.31.10.2",
        "ipv6_subnet": "2001:db8:31::/64", "ipv6_gateway": "2001:db8:31::1", "ipv6_address": "2001:db8:31::2",
        "client_cidrs": ["192.168.50.0/24", "2001:db8:50::/64"],
    }

class ConfigTests(unittest.TestCase):
    def write(self, cfg, mode=0o600):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p=Path(td.name)/"network.json"
        p.write_text(json.dumps(cfg))
        os.chmod(p,mode)
        return p

    def test_valid_dual_stack_config(self):
        cfg=nl.read_config(self.write(valid_config()), require_root=False)
        self.assertEqual(set(cfg["_networks"]),{4,6})

    def test_firewall_contract_must_match_exactly(self):
        td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        path=Path(td.name)/"firewall.json"
        firewall={"version":1,"interface":"eth1","ipv4_address":"172.31.10.2","ipv6_address":"2001:db8:31::2","client_cidrs":["192.168.50.0/24","2001:db8:50::/64"]}
        path.write_text(json.dumps(firewall)); os.chmod(path,0o600)
        cfg=nl.read_config(self.write(valid_config()),require_root=False)
        nl.validate_firewall_contract(cfg,path,require_root=False)
        firewall["ipv4_address"]="172.31.10.99"
        path.write_text(json.dumps(firewall)); os.chmod(path,0o600)
        with self.assertRaises(nl.LifecycleError): nl.validate_firewall_contract(cfg,path)

    def test_unknown_key_rejected(self):
        cfg=valid_config(); cfg["extra"]=True
        with self.assertRaises(nl.LifecycleError): nl.read_config(self.write(cfg), require_root=False)

    def test_world_readable_config_rejected(self):
        with self.assertRaises(nl.LifecycleError): nl.read_config(self.write(valid_config(),0o644), require_root=False)

    def test_noncanonical_or_overlapping_subnet_rejected(self):
        cfg=valid_config(); cfg["ipv4_subnet"]="172.31.10.1/24"
        with self.assertRaises(nl.LifecycleError): nl.read_config(self.write(cfg), require_root=False)

    def test_gateway_address_collision_rejected(self):
        cfg=valid_config(); cfg["ipv4_address"]=cfg["ipv4_gateway"]
        with self.assertRaises(nl.LifecycleError): nl.read_config(self.write(cfg),require_root=False)

    def test_partial_ipv6_config_rejected(self):
        cfg=valid_config(); cfg["ipv6_gateway"]=None
        with self.assertRaises(nl.LifecycleError): nl.read_config(self.write(cfg))

class NetworkSafetyTests(unittest.TestCase):
    def test_dual_stack_provision_still_requires_live_firewall_before_mutation(self):
        cfg=self.write_config()
        firewall=Path("/tmp/firewall.json")
        with patch.object(nl,"host_ingress_lock",return_value=nullcontext()):
            with patch.object(nl,"verify_live_firewall") as verify:
                with patch.object(nl,"_provision_locked") as provision:
                    nl.provision(cfg,firewall)
                    verify.assert_called_once_with(firewall)
                    provision.assert_called_once_with(cfg, None)

    def test_provision_refuses_to_attach_before_live_firewall_verification(self):
        cfg=self.write_config()
        cfg["_networks"].pop(6)
        with patch.object(nl,"host_ingress_lock",return_value=nullcontext()):
            with patch.object(nl,"verify_live_firewall",side_effect=nl.LifecycleError("firewall not ready")) as verify:
                with patch.object(nl,"run") as command:
                    with self.assertRaises(nl.LifecycleError):
                        nl.provision(cfg,Path("/tmp/firewall.json"))
                    verify.assert_called_once_with(Path("/tmp/firewall.json"))
                    command.assert_not_called()

    def test_dns_port_bindings_are_loopback_only(self):
        cfg=self.write_config()
        cfg["_networks"].pop(6)
        container={"NetworkSettings":{"Networks":{},"Ports":{
            "6055/udp":[{"HostIp":"127.0.0.1","HostPort":"32768"}],
            "6055/tcp":[{"HostIp":"127.0.0.1","HostPort":"32769"}]}}}
        nl.validate_dns_port_bindings(container,cfg)
        container["NetworkSettings"]["Ports"]["6055/udp"][0]["HostIp"]="0.0.0.0"
        with self.assertRaises(nl.LifecycleError): nl.validate_dns_port_bindings(container,cfg)

    def test_routed_ipv4_mapping_has_no_public_host_port(self):
        cfg=self.write_config(); cfg["_networks"].pop(6)
        container={"NetworkSettings":{"Networks":{cfg["network"]:{"IPAddress":"172.31.10.2"}},
            "Ports":{"6055/udp":[{"HostIp":"127.0.0.1","HostPort":"32768"},{"HostIp":"0.0.0.0","HostPort":""}],
                     "6055/tcp":[{"HostIp":"127.0.0.1","HostPort":"32769"},{"HostIp":"0.0.0.0","HostPort":""}]}}}
        nl.validate_dns_port_bindings(container,cfg)
        container["NetworkSettings"]["Ports"]["6055/udp"][1]["HostPort"]="32770"
        with self.assertRaises(nl.LifecycleError): nl.validate_dns_port_bindings(container,cfg)

    def test_dual_stack_loopback_mappings_are_required_before_attach(self):
        cfg=self.write_config()
        container={"NetworkSettings":{"Networks":{},"Ports":{}}}
        for proto in ("udp","tcp"):
            container["NetworkSettings"]["Ports"][f"6055/{proto}"]=[
                {"HostIp":"127.0.0.1","HostPort":"32768"},
                {"HostIp":"::1","HostPort":"32768"}]
        nl.validate_dns_port_bindings(container,cfg)
        container["NetworkSettings"]["Ports"]["6055/tcp"][1]={"HostIp":"::","HostPort":"32770"}
        with self.assertRaises(nl.LifecycleError): nl.validate_dns_port_bindings(container,cfg)

    def test_dual_stack_routed_mappings_have_no_public_host_port_after_attach(self):
        cfg=self.write_config()
        container={"NetworkSettings":{"Networks":{},"Ports":{}}}
        for proto in ("udp","tcp"):
            container["NetworkSettings"]["Ports"][f"6055/{proto}"]=[
                {"HostIp":"127.0.0.1","HostPort":"32768"},
                {"HostIp":"::1","HostPort":"32768"},
                {"HostIp":"0.0.0.0","HostPort":""},
                {"HostIp":"::","HostPort":""}]
        container["NetworkSettings"]["Networks"][cfg["network"]]={"IPAddress":"172.31.10.2","GlobalIPv6Address":"2001:db8:31::2"}
        nl.validate_dns_port_bindings(container,cfg)
        container["NetworkSettings"]["Ports"]["6055/tcp"][3]["HostPort"]="32770"
        with self.assertRaises(nl.LifecycleError): nl.validate_dns_port_bindings(container,cfg)

    def test_host_next_hop_requires_global_address_for_each_family(self):
        cfg=self.write_config()
        fake={"stdout":json.dumps([{"addr_info":[
            {"family":"inet","scope":"global","local":"192.168.50.2"},
            {"family":"inet6","scope":"global","local":"2001:db8:50::2"},
            {"family":"inet6","scope":"link","local":"fe80::1"}]}]),"returncode":0}
        with patch.object(nl,"run",return_value=type("Result",(),fake)()):
            self.assertEqual(nl.host_next_hops(cfg),{4:"192.168.50.2",6:"2001:db8:50::2"})
        cfg["_networks"].pop(6)
        fake["stdout"]=json.dumps([{"addr_info":[{"family":"inet","scope":"global","local":"192.168.50.2"}]}])
        with patch.object(nl,"run",return_value=type("Result",(),fake)()):
            self.assertEqual(nl.host_next_hops(cfg),{4:"192.168.50.2"})

    def test_routeros_static_route_command_targets_docker_ingress_subnet(self):
        self.assertEqual(nl.routeros_v7_route("172.31.10.0/24","192.168.1.2"),
            '/ip route add dst-address=172.31.10.0/24 gateway=192.168.1.2 comment="S5M-Agent DNS ingress"')
        self.assertEqual(nl.routeros_v7_route("fd00:172:31::/64","fd00:192:168::2"),
            '/ipv6 route add dst-address=fd00:172:31::/64 gateway=fd00:192:168::2 comment="S5M-Agent DNS ingress"')

    def test_single_default_route_must_use_bridge_gateway_exactly(self):
        self.assertTrue(nl.preserves_single_default_route(["default via 172.17.0.1 dev eth0"],"172.17.0.1"))
        self.assertTrue(nl.preserves_single_default_route(["default via 2001:db8:17::1 dev eth0"],"2001:db8:17::1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.17.0.10 dev eth0"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 2001:db8:17::10 dev eth0"],"2001:db8:17::1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.17.0.1 dev eth0","default via 172.31.10.1 dev eth1"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.31.10.1 dev eth1"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default dev eth0"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.17.0.1 via 172.17.0.2 dev eth0"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["unicast default via 172.17.0.1 dev eth0"],"172.17.0.1"))

    def previous_container(self, cfg, *, running=False):
        networks = {
            "bridge": {"Gateway": "172.17.0.1", "IPv6Gateway": "2001:db8:17::1"},
            cfg["network"]: {"IPAddress": str(cfg["_networks"][4][2]), "GlobalIPv6Address": str(cfg["_networks"][6][2])},
        }
        return {"Id": "old-id", "State": {"Running": running}, "NetworkSettings": {"Networks": networks, "Ports": {}}}

    def test_handoff_accepts_only_stopped_previous_endpoint(self):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        net = {"Containers": {"old-id": {"Name": previous_name}}}
        with patch.object(nl, "inspect_container", return_value=self.previous_container(cfg)), \
             patch.object(nl, "validate_dns_port_bindings") as validate_ports:
            self.assertTrue(nl.validate_network_endpoint_state(net, cfg, {"Id": "new-id"}, False, previous_name))
            validate_ports.assert_called_once()

    def test_handoff_refuses_running_previous_container(self):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        net = {"Containers": {"old-id": {"Name": previous_name}}}
        with patch.object(nl, "inspect_container", return_value=self.previous_container(cfg, running=True)), \
             patch.object(nl, "validate_dns_port_bindings"):
            with self.assertRaises(nl.LifecycleError):
                nl.validate_network_endpoint_state(net, cfg, {"Id": "new-id"}, False, previous_name)

    def test_handoff_refuses_unexpected_or_duplicate_endpoints(self):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        previous = self.previous_container(cfg)
        with patch.object(nl, "inspect_container", return_value=previous), \
             patch.object(nl, "validate_dns_port_bindings"):
            unexpected = {"Containers": {"old-id": {"Name": previous_name}, "other-id": {"Name": "other-agent"}}}
            with self.assertRaises(nl.LifecycleError):
                nl.validate_network_endpoint_state(unexpected, cfg, {"Id": "new-id"}, False, previous_name)
            duplicate = {"Containers": {"old-id": {"Name": previous_name}, "new-id": {"Name": cfg["container"]}}}
            with self.assertRaises(nl.LifecycleError):
                nl.validate_network_endpoint_state(duplicate, cfg, {"Id": "new-id"}, True, previous_name)

    def test_handoff_refuses_address_drift_and_snapshot_mismatch(self):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        previous = self.previous_container(cfg)
        previous["NetworkSettings"]["Networks"][cfg["network"]]["IPAddress"] = "172.31.10.99"
        net = {"Containers": {"old-id": {"Name": previous_name}}}
        with patch.object(nl, "inspect_container", return_value=previous), \
             patch.object(nl, "validate_dns_port_bindings"):
            with self.assertRaises(nl.LifecycleError):
                nl.validate_network_endpoint_state(net, cfg, {"Id": "new-id"}, False, previous_name)
            with self.assertRaises(nl.LifecycleError):
                nl.validate_network_endpoint_state({"Containers": {}}, cfg, {"Id": "new-id"}, False, previous_name)

    def test_restore_previous_endpoint_uses_low_gateway_priority_and_is_idempotent(self):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        detached = {"State": {"Running": False}, "NetworkSettings": {"Networks": {"bridge": {}}, "Ports": {}}}
        attached = self.previous_container(cfg)
        with patch.object(nl, "inspect_container", side_effect=[detached, attached]), \
             patch.object(nl, "run") as command, \
             patch.object(nl, "validate_dns_port_bindings"):
            nl.restore_previous_endpoint(previous_name, cfg)
            args = command.call_args.args[0]
            self.assertIn("--gw-priority", args)
            self.assertEqual(args[args.index("--gw-priority") + 1], "-1")
            self.assertIn(str(cfg["_networks"][4][2]), args)
            self.assertIn(str(cfg["_networks"][6][2]), args)
            self.assertEqual(args[-2:], [cfg["network"], previous_name])
        with patch.object(nl, "inspect_container", return_value=attached), \
             patch.object(nl, "run") as command, \
             patch.object(nl, "validate_dns_port_bindings"):
            nl.restore_previous_endpoint(previous_name, cfg)
            command.assert_not_called()

    def run_handoff(self, *, fail_new_connect=False):
        cfg = self.write_config()
        previous_name = "s5m-agent.rollback.123"
        state = {"previous_attached": True, "target_attached": False}
        calls = []
        events = []
        bridge = {"Gateway": "172.17.0.1", "IPv6Gateway": "2001:db8:17::1"}

        def networks(name):
            result = {"bridge": bridge}
            if name == previous_name and state["previous_attached"]:
                result[cfg["network"]] = {"IPAddress": "172.31.10.2", "GlobalIPv6Address": "2001:db8:31::2"}
            if name == cfg["container"] and state["target_attached"]:
                result[cfg["network"]] = {"IPAddress": "172.31.10.2", "GlobalIPv6Address": "2001:db8:31::2"}
            return result

        def inspect_container(name):
            return {
                "Id": "old-id" if name == previous_name else "new-id",
                "State": {"Running": False if name == previous_name else True},
                "NetworkSettings": {"Networks": networks(name), "Ports": {}},
            }

        def command(args, check=True):
            calls.append(list(args))
            events.append(("command", list(args)))
            result = type("Result", (), {"stdout": "", "stderr": "", "returncode": 0})()
            if args[:3] == ["ip", "link", "show"]:
                return result
            if args[:4] == ["docker", "network", "connect", "--help"]:
                result.stdout = "--gw-priority"
                return result
            if args[:3] == ["docker", "network", "disconnect"]:
                if args[-1] == previous_name:
                    state["previous_attached"] = False
                elif args[-1] == cfg["container"]:
                    state["target_attached"] = False
                return result
            if args[:3] == ["docker", "network", "connect"]:
                if args[-1] == cfg["container"]:
                    state["target_attached"] = True
                    if fail_new_connect:
                        raise nl.LifecycleError("mock new endpoint attach failure")
                elif args[-1] == previous_name:
                    state["previous_attached"] = True
                return result
            raise AssertionError(f"unexpected command: {args}")

        net = {
            "Labels": {nl.OWNER: nl.VALUE}, "Driver": "bridge",
            "IPAM": {"Config": [
                {"Subnet": "172.31.10.0/24", "Gateway": "172.31.10.1"},
                {"Subnet": "2001:db8:31::/64", "Gateway": "2001:db8:31::1"},
            ]},
            "Options": {
                "com.docker.network.bridge.gateway_mode_ipv4": "routed",
                "com.docker.network.bridge.gateway_mode_ipv6": "routed",
                "com.docker.network.bridge.trusted_host_interfaces": "eth1",
            },
            "Containers": {"old-id": {"Name": previous_name}},
        }
        error = None
        with patch.object(nl, "run", side_effect=command), \
             patch.object(nl, "inspect_network", return_value=net), \
             patch.object(nl, "inspect_container", side_effect=inspect_container), \
             patch.object(nl, "container_networks", side_effect=lambda name: networks(name)), \
             patch.object(nl, "validate_existing"), \
             patch.object(nl, "validate_dns_port_bindings"), \
             patch.object(nl, "invalidate_host_attestation", side_effect=lambda: events.append(("invalidate",))), \
             patch.object(nl, "host_next_hops", return_value={4: "192.168.50.2", 6: "2001:db8:50::2"}), \
             patch.object(nl, "default_routes", return_value=(
                 ["default via 172.17.0.1 dev eth0"],
                 ["default via 2001:db8:17::1 dev eth0"],
             )):
            try:
                nl._provision_locked(cfg, previous_name)
            except Exception as exc:
                error = exc
        return state, calls, error, events

    def test_provision_handoff_detaches_old_before_attaching_new(self):
        state, calls, error, events = self.run_handoff()
        self.assertIsNone(error)
        self.assertFalse(state["previous_attached"])
        self.assertTrue(state["target_attached"])
        self.assertEqual(events[0], ("invalidate",))
        old_detach = next(i for i, args in enumerate(calls) if args[:3] == ["docker", "network", "disconnect"] and args[-1] == "s5m-agent.rollback.123")
        new_attach = next(i for i, args in enumerate(calls) if args[:3] == ["docker", "network", "connect"] and args[-1] == "s5m-agent")
        self.assertLess(old_detach, new_attach)

    def test_failed_new_attach_restores_previous_routed_endpoint(self):
        state, calls, error, events = self.run_handoff(fail_new_connect=True)
        self.assertIsInstance(error, nl.LifecycleError)
        self.assertTrue(state["previous_attached"])
        self.assertFalse(state["target_attached"])
        self.assertEqual(events[0], ("invalidate",))
        restored = [args for args in calls if args[:3] == ["docker", "network", "connect"] and args[-1] == "s5m-agent.rollback.123"]
        self.assertEqual(len(restored), 1)
        self.assertIn("--gw-priority", restored[0])
        self.assertEqual(restored[0][restored[0].index("--gw-priority") + 1], "-1")

    def test_provision_refreshes_attestation_only_after_releasing_shared_lock(self):
        cfg = self.write_config()
        events = []

        @contextmanager
        def fake_lock():
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        with patch.object(nl, "host_ingress_lock", side_effect=fake_lock), \
             patch.object(nl, "verify_live_firewall", side_effect=lambda *_args: events.append("verify")), \
             patch.object(nl, "_provision_locked", side_effect=lambda *_args: events.append("provision")), \
             patch.object(nl, "refresh_host_attestation", side_effect=lambda: events.append("refresh")):
            nl.provision(cfg, Path("/tmp/firewall.json"))
        self.assertEqual(events, ["lock-enter", "verify", "provision", "lock-exit", "refresh"])

    def write_config(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p=Path(td.name)/"network.json"
        p.write_text(json.dumps(valid_config()))
        os.chmod(p,0o600)
        return nl.read_config(p, require_root=False)

    def test_unowned_network_never_reused(self):
        cfg=self.write_config()
        net={"Labels":{},"Driver":"bridge"}
        with self.assertRaises(nl.LifecycleError): nl.validate_existing(net,cfg)

    def test_network_option_drift_rejected(self):
        cfg=self.write_config()
        net={"Labels":{nl.OWNER:nl.VALUE},"Driver":"bridge",
             "IPAM":{"Config":[{"Subnet":"172.31.10.0/24","Gateway":"172.31.10.1"},{"Subnet":"2001:db8:31::/64","Gateway":"2001:db8:31::1"}]},
             "Options":{"com.docker.network.bridge.gateway_mode_ipv4":"nat",
                        "com.docker.network.bridge.gateway_mode_ipv6":"routed",
                        "com.docker.network.bridge.trusted_host_interfaces":"eth1"}}
        with self.assertRaises(nl.LifecycleError): nl.validate_existing(net,cfg)

if __name__ == "__main__": unittest.main()
