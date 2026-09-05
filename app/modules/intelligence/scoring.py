import logging
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

class ThreatScoringEngine:
    """Unified Composite Threat Scoring Engine for ICES."""

    @classmethod
    def calculate_composite_score(
        cls,
        gemini_nlp: Dict[str, Any],
        hop_analysis: Dict[str, Any],
        vip_engine: Dict[str, Any],
        parsed_email: Dict[str, Any],
        attachment_scanner: Optional[Dict[str, Any]] = None,
        sender_behavioral_baseline: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Calculates unified composite score dictionary with VIP & Quishing boosts."""
        spf = parsed_email.get("spf_status", "PASS")
        dkim = parsed_email.get("dkim_status", "PASS")
        dmarc = parsed_email.get("dmarc_status", "PASS")
        reply_mismatch = bool(parsed_email.get("reply_to") and parsed_email.get("reply_to") != parsed_email.get("sender_header_from"))
        origin_geo = (hop_analysis.get("originating_intel") or {}) if hop_analysis else {}

        score, severity = cls.calculate_score(
            spf_status=spf,
            dkim_status=dkim,
            dmarc_status=dmarc,
            reply_to_mismatch=reply_mismatch,
            originating_geo=origin_geo,
            nlp_evaluation=gemini_nlp or {}
        )

        # VIP Impersonation Boost
        if vip_engine and (vip_engine.get("is_impersonation_threat") or vip_engine.get("is_impersonation")):
            score = max(score, 88)
            severity = "CRITICAL"

        # Quishing / Insecure HTTP / Attachment Malicious Boost
        if (gemini_nlp and gemini_nlp.get("threat_category") in ["QR_CODE_PHISHING", "INSECURE_PLAINTEXT_COMMUNICATION"]) or (attachment_scanner and (attachment_scanner.get("is_quishing_detected") or attachment_scanner.get("has_malicious_attachment"))):
            score = max(score, 90)
            severity = "CRITICAL"

        category = (gemini_nlp or {}).get("threat_category", "CLEAN")
        if score >= 80 and category == "CLEAN":
            category = "VIP_IMPERSONATION" if vip_engine and (vip_engine.get("is_impersonation_threat") or vip_engine.get("is_impersonation")) else "SUSPICIOUS_COMMUNICATION"

        return {
            "composite_score": score,
            "severity": severity,
            "primary_threat_category": category,
            "auth_status": f"SPF={spf} DKIM={dkim} DMARC={dmarc}"
        }

    @classmethod
    def calculate_score(
        cls,
        spf_status: str,
        dkim_status: str,
        dmarc_status: str,
        reply_to_mismatch: bool,
        originating_geo: Dict[str, Any],
        nlp_evaluation: Dict[str, Any]
    ) -> Tuple[int, str]:
        """
        Calculates unified Threat Score (0–100) and Severity Level.
        Formula:
          - Authentication Breakdown: 25% max
          - Relay & GeoIP Breakdown: 25% max
          - Gemini NLP Intent & Urgency: 50% max
        """
        auth_score = 0
        if spf_status in ["FAIL", "SOFTFAIL"]:
            auth_score += 10
        if dkim_status == "FAIL":
            auth_score += 10
        if dmarc_status == "FAIL":
            auth_score += 15
        auth_score = min(25, auth_score)

        relay_score = 0
        if reply_to_mismatch:
            relay_score += 10
        if originating_geo.get("is_tor_or_vpn"):
            relay_score += 15
        if originating_geo.get("risk_multiplier", 0) > 0.7:
            relay_score += 10
        relay_score = min(25, relay_score)

        nlp_score = 0
        if nlp_evaluation.get("is_threat"):
            conf = float(nlp_evaluation.get("confidence_score", 0.0))
            urgency = int(nlp_evaluation.get("urgency_score", 0))
            nlp_score = int((conf * 38) + ((urgency / 100) * 12))
        nlp_score = min(50, nlp_score)

        total_score = auth_score + relay_score + nlp_score
        total_score = max(0, min(100, total_score))

        if total_score >= 85:
            severity = "CRITICAL"
        elif total_score >= 70:
            severity = "HIGH"
        elif total_score >= 40:
            severity = "MEDIUM"
        elif total_score >= 20:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        return total_score, severity
