from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DocumentationContractTests(unittest.TestCase):
    def test_ipv6_docs_match_the_opt_in_runtime_contract(self):
        readme = (ROOT / "scripts/host-ingress/README.md").read_text(encoding="utf-8")
        attestation = (ROOT / "docs/SMARTDNS-INGRESS-HOST-ATTESTATION-CN.md").read_text(encoding="utf-8")
        lifecycle = (ROOT / "scripts/host-ingress/network-lifecycle.py").read_text(encoding="utf-8")
        deploy_agent = (ROOT / "scripts/deploy-agent.sh").read_text(encoding="utf-8")
        deploy_menu = (ROOT / "scripts/deploy-s5m-agent.sh").read_text(encoding="utf-8")

        self.assertIn("IPv6 per-client ingress is opt-in", readme)
        self.assertIn("Keep IPv6 disabled in production", readme)
        self.assertNotIn("IPv6 provisioning is currently rejected before any Docker mutation", readme)

        self.assertIn("显式 opt-in 的双栈 IPv4/IPv6 provisioning 路径", attestation)
        self.assertIn("生产环境仍须保持 IPv6 关闭", attestation)
        self.assertNotIn("当前生产代码只允许 IPv4 per-client ingress", attestation)
        self.assertNotIn("ipv6_address：当前必须为 null", attestation)

        self.assertIn('if 6 in cfg["_networks"]', lifecycle)
        self.assertIn("gateway_mode_ipv6", lifecycle)
        self.assertIn("ENABLE_PER_CLIENT_INGRESS_IPV6", deploy_agent)
        self.assertIn("ENABLE_PER_CLIENT_INGRESS_IPV6", deploy_menu)


if __name__ == "__main__":
    unittest.main()
