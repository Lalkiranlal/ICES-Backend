import logging
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.modules.ingestion.parser import EmlParser
from app.modules.intelligence.hop_analyzer import SMTPHopAnalyzer
from app.modules.intelligence.gemini_nlp import GeminiNLPAnalyzer
from app.modules.intelligence.scoring import ThreatScoringEngine
from app.modules.remediation.engine import RemediationEngine

logger = logging.getLogger(__name__)
router = APIRouter()

class EmlTextRequest(BaseModel):
    raw_eml_text: str
    recipient_email: Optional[str] = "security-analyst@company.com"

@router.post("/analyze-raw")
async def analyze_raw_eml(payload: EmlTextRequest):
    """
    On-demand forensic analyzer for raw RFC 822 EML text.
    Parses headers, auth records, SMTP hops, runs Gemini BEC NLP, and computes threat scores.
    """
    try:
        raw_bytes = payload.raw_eml_text.encode("utf-8")
        parsed = EmlParser.parse_raw_eml(raw_bytes)
        
        enriched_hops, originating_geo, reactflow_graph = SMTPHopAnalyzer.analyze_chain(parsed["smtp_hops"])
        
        nlp_eval = await GeminiNLPAnalyzer.analyze_email(
            subject=parsed["subject"],
            sender_header_from=parsed["sender_header_from"],
            sender_display_name=parsed["sender_display_name"],
            reply_to=parsed["reply_to"],
            recipients=parsed["recipient_to"] or [payload.recipient_email],
            text_body=parsed["text_body"] or parsed["html_body"],
            spf_status=parsed["spf_status"],
            dkim_status=parsed["dkim_status"],
            dmarc_status=parsed["dmarc_status"]
        )
        
        threat_score, severity = ThreatScoringEngine.calculate_score(
            spf_status=parsed["spf_status"],
            dkim_status=parsed["dkim_status"],
            dmarc_status=parsed["dmarc_status"],
            reply_to_mismatch=parsed["reply_to_mismatch"],
            originating_geo=originating_geo,
            nlp_evaluation=nlp_eval
        )
        
        # Policy action evaluation
        remediation_action = "AUTO_QUARANTINE" if threat_score > 80 else ("APPLY_SUSPICIOUS_BANNER" if threat_score > 50 else "DELIVER_NORMAL")
        
        return {
            "threat_score": threat_score,
            "severity": severity,
            "recommended_action": remediation_action,
            "authentication": {
                "spf": parsed["spf_status"],
                "dkim": parsed["dkim_status"],
                "dmarc": parsed["dmarc_status"],
                "raw": parsed["raw_authentication_results"]
            },
            "originating_intel": originating_geo,
            "smtp_hops": enriched_hops,
            "reactflow_graph": reactflow_graph,
            "gemini_bec_analysis": nlp_eval,
            "headers": {
                "message_id": parsed["rfc822_message_id"],
                "from": parsed["sender_header_from"],
                "display_name": parsed["sender_display_name"],
                "reply_to": parsed["reply_to"],
                "reply_to_mismatch": parsed["reply_to_mismatch"],
                "subject": parsed["subject"],
                "recipients": parsed["recipient_to"],
                "date": parsed["date_header"]
            }
        }
    except Exception as e:
        logger.error(f"Error during raw EML forensic analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
