import importlib.util, json, os, tempfile, unittest
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

    def test_dual_stack_dns_port_mapping_has_no_public_ipv6_host_port(self):
        cfg=self.write_config()
        container={"NetworkSettings":{"Networks":{},
            "Ports":{}}}
        for proto in ("udp","tcp"):
            container["NetworkSettings"]["Ports"][f"6055/{proto}"]=[
                {"HostIp":"127.0.0.1","HostPort":"32768"},
                {"HostIp":"0.0.0.0","HostPort":""},
                {"HostIp":"::","HostPort":""}]
        container["NetworkSettings"]["Networks"][cfg["network"]]={"IPAddress":"172.31.10.2","GlobalIPv6Address":"2001:db8:31::2"}
        nl.validate_dns_port_bindings(container,cfg)
        container["NetworkSettings"]["Ports"]["6055/tcp"][1]["HostPort"]="32770"
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

    def test_single_default_route_must_use_bridge_gateway(self):
        self.assertTrue(nl.preserves_single_default_route(["default via 172.17.0.1 dev eth0"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.17.0.1 dev eth0","default via 172.31.10.1 dev eth1"],"172.17.0.1"))
        self.assertFalse(nl.preserves_single_default_route(["default via 172.31.10.1 dev eth1"],"172.17.0.1"))

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
