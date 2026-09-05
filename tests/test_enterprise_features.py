import unittest
from app.modules.intelligence.vip_engine import VipImpersonationEngine
from app.modules.intelligence.attachment_scanner import AttachmentScanner
from app.modules.remediation.banner_engine import WarningBannerEngine

class TestEnterpriseFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.db.database import init_db
        import asyncio
        asyncio.run(init_db())

    def test_vip_display_name_spoofing(self):
        res = VipImpersonationEngine.analyze(
            sender_display_name="Alex Mercer (CEO)",
            sender_header_from="alex.mercer.corp@attacker-domain.com",
            reply_to="alex.mercer.corp@attacker-domain.com"
        )
        self.assertTrue(res["is_impersonation_threat"])
        self.assertIn("Alex Mercer", res["impersonated_vip"]["name"])

    def test_homoglyph_and_lookalike_domain(self):
        res = VipImpersonationEngine.analyze(
            sender_display_name="Sarah Jenkins",
            sender_header_from="sarah@cl0udnet.io",
            reply_to="sarah@cl0udnet.io"
        )
        self.assertTrue(res["is_impersonation_threat"])
        self.assertTrue(res["lookalike_domain_detected"])
        self.assertTrue(res["lookalike_details"]["homoglyph_detected"])

    def test_attachment_scanner_quishing(self):
        attachments = [
            {
                "filename": "mfa_login_qr.png",
                "content_type": "image/png",
                "size_bytes": 14200,
                "raw_bytes": b"https://microsoft-online-secure-auth.eu-west-1.id-verify.com/login?token=8x9Fk2"
            }
        ]
        scan_res = AttachmentScanner.scan_attachments(attachments)
        self.assertEqual(scan_res["total_attachments"], 1)
        self.assertTrue(scan_res["is_quishing_detected"])
        self.assertGreater(len(scan_res["extracted_qr_urls"]), 0)

    def test_attachment_scanner_pdf_invoice(self):
        attachments = [
            {
                "filename": "supplier_invoice_94821.pdf",
                "content_type": "application/pdf",
                "size_bytes": 28400,
                "raw_bytes": b"(INVOICE #94821) (Routing: 121000248) (Account: 9948201948) (Total: $45,000.00)"
            }
        ]
        scan_res = AttachmentScanner.scan_attachments(attachments)
        self.assertEqual(scan_res["total_attachments"], 1)
        self.assertEqual(scan_res["extracted_financial_entities"]["routing_number"], "121000248")
        self.assertEqual(scan_res["extracted_financial_entities"]["account_number"], "9948201948")

    def test_cluster_purge_logic(self):
        from app.api.v1.endpoints.remediation import execute_cluster_purge, ClusterPurgeRequest
        from app.api.v1.endpoints.alerts import _PARSED_ALERT_CACHE
        import asyncio

        # Insert live test message matching cluster criteria
        _PARSED_ALERT_CACHE["test-campaign-01"] = {
            "id": "test-campaign-01",
            "subject": "Confidential Acquisition Escrow Transfer",
            "sender_header_from": "attacker@c0mpany-wire.com",
            "recipient_to": ["victim@organization.com"],
            "threat_score": 90,
            "remediation_status": "DELIVERED"
        }

        req = ClusterPurgeRequest(
            subject_pattern="Confidential Acquisition",
            sender_domain="c0mpany-wire.com"
        )
        res = asyncio.run(execute_cluster_purge(req))
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action"], "ORGANIZATION_CLUSTER_PURGE")
        self.assertGreater(res["metrics"]["total_mailboxes_scanned"], 0)
        self.assertEqual(res["metrics"]["purged_messages_count"], 1)
        self.assertEqual(_PARSED_ALERT_CACHE["test-campaign-01"]["remediation_status"], "CLUSTER_PURGED")

if __name__ == '__main__':
    unittest.main()


