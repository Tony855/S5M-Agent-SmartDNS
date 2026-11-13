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
        self.write(self.valid()); cfg=mod.load_config(self.path); rules=mod.render_nft(cfg)
        self.assertIn('iifname "eth1" ip daddr 172.31.10.2', rules)
        self.assertIn('ip daddr 172.31.10.2 udp dport 6055 drop', rules)
        self.assertIn('ip6 daddr 2001:db8:31::2 tcp dport 6055 drop', rules)
        self.assertNotIn('dport 53', rules)
    def test_rejects_extra_keys_and_noncanonical_cidr(self):
        x=self.valid(); x["source_ip_preserved"]=True; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
        x=self.valid(); x["client_cidrs"]=["192.168.50.1/24"]; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
    def test_rejects_overlap_and_missing_family_address(self):
        x=self.valid(); x["client_cidrs"] += ["192.168.50.0/25"]; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
        x=self.valid(); x["ipv6_address"]=None; self.write(x)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
    def test_rejects_unsafe_permissions_and_symlink(self):
        self.write(self.valid(),0o666)
        with self.assertRaises(mod.ConfigError): mod.load_config(self.path)
        link=self.path.with_name("link.json"); link.symlink_to(self.path)
        with self.assertRaises(mod.ConfigError): mod.load_config(link)

if __name__ == "__main__": unittest.main()
