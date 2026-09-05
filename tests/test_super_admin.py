import unittest
import asyncio
from app.modules.config.dynamic_config import DynamicConfigManager
from app.api.v1.endpoints.super_admin import (
    update_prompt_engineering, PromptUpdateRequest,
    test_prompt_playground, PromptTestRequest,
    add_trusted_domain, TrustedDomainRequest, remove_trusted_domain,
    save_vip_target, VipTargetRequest, remove_vip_target,
    update_heuristic_rules, HeuristicRulesRequest,
    update_policies, PoliciesUpdateRequest,
    get_audit_logs
)

class TestSuperAdminControlPlane(unittest.TestCase):

    def test_dynamic_prompt_update_and_test(self):
        # Update Prompt
        req = PromptUpdateRequest(
            gemini_model="gemini-1.5-flash",
            temperature=0.2,
            system_prompt="Test System Prompt: detect BEC and Social Engineering."
        )
        res = asyncio.run(update_prompt_engineering(req))
        self.assertEqual(res["status"], "success")
        self.assertEqual(DynamicConfigManager.get_prompt_config()["temperature"], 0.2)

        # Test Prompt Playground
        test_req = PromptTestRequest(
            gemini_model="gemini-1.5-flash",
            temperature=0.2,
            sample_subject="Urgent Wire Transfer Escrow",
            sample_sender_display="Sarah Jenkins (CFO)",
            sample_sender_email="sarah.jenkins@c0mpany-wire.com",
            sample_body="Please remit $85,000 wire to Escrow immediately. Routing: 121000248 Account: 9948201948",
            is_vip_simulated=True
        )
        play_res = asyncio.run(test_prompt_playground(test_req))
        self.assertEqual(play_res["status"], "success")
        self.assertGreater(play_res["latency_ms"], 0)
        self.assertTrue(play_res["evaluation"]["is_threat"])

    def test_trusted_domain_lifecycle(self):
        # Add new trusted SaaS partner
        add_req = TrustedDomainRequest(
            domain="custompartner.com",
            name="Custom Partner Portal",
            category="Strategic Supplier",
            status="ACTIVE"
        )
        res = asyncio.run(add_trusted_domain(add_req))
        self.assertEqual(res["status"], "success")
        self.assertTrue(DynamicConfigManager.is_trusted_domain("custompartner.com"))
        self.assertTrue(DynamicConfigManager.is_trusted_domain("auth.custompartner.com"))

        # Remove domain
        del_res = asyncio.run(remove_trusted_domain("custompartner.com"))
        self.assertEqual(del_res["status"], "success")
        self.assertFalse(DynamicConfigManager.is_trusted_domain("custompartner.com"))

    def test_vip_directory_lifecycle(self):
        # Add new VIP
        vip_req = VipTargetRequest(
            name="Elena Rostova",
            title="Chief Operations Officer (COO)",
            corporate_email="elena.rostova@cloudnet.io",
            personal_emails=["elena.personal@gmail.com"],
            homoglyph_sensitivity=90
        )
        res = asyncio.run(save_vip_target(vip_req))
        self.assertEqual(res["status"], "success")
        
        found = any(v["name"] == "Elena Rostova" for v in DynamicConfigManager.get_vip_directory())
        self.assertTrue(found)

    def test_heuristic_rules_and_policies(self):
        # Update heuristic rules
        h_req = HeuristicRulesRequest(
            payroll_phrases=["divert my salary", "switch my payroll direct deposit"],
            wire_phrases=["remittance wire", "escrow authorization"]
        )
        h_res = asyncio.run(update_heuristic_rules(h_req))
        self.assertEqual(h_res["status"], "success")
        self.assertIn("divert my salary", DynamicConfigManager.get_heuristic_rules()["payroll_phrases"])

        # Update policies
        p_req = PoliciesUpdateRequest(
            auto_remediation_threshold=85,
            security_admin_email="soc-lead@organization.com"
        )
        p_res = asyncio.run(update_policies(p_req))
        self.assertEqual(p_res["status"], "success")
        self.assertEqual(DynamicConfigManager.get_policies()["auto_remediation_threshold"], 85)

        # Check Audit Log
        logs_res = asyncio.run(get_audit_logs())
        self.assertEqual(logs_res["status"], "success")
        self.assertGreater(logs_res["total"], 0)

if __name__ == '__main__':
    unittest.main()
