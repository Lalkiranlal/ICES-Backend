import re
import json
import logging
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid

from app.modules.ingestion.gmail_client import GmailClient
from app.modules.ingestion.parser import EmlParser
from app.modules.intelligence.hop_analyzer import SMTPHopAnalyzer
from app.modules.intelligence.gemini_nlp import GeminiNLPAnalyzer
from app.modules.intelligence.scoring import ThreatScoringEngine
from app.modules.remediation.engine import RemediationEngine
from app.modules.intelligence.vip_engine import VipImpersonationEngine
from app.modules.intelligence.attachment_scanner import AttachmentScanner
from app.db import crud

logger = logging.getLogger(__name__)
router = APIRouter()

class PubSubMessage(BaseModel):
    data: str = Field(description="Base64-encoded JSON message from GCP Pub/Sub")
    messageId: str
    publishTime: str

class PubSubPushEnvelope(BaseModel):
    message: PubSubMessage
    subscription: str

class AttackSimulationRequest(BaseModel):
    attack_type: Optional[str] = "vip_wire_fraud"
    target_recipient: Optional[str] = "finance@company.com"

async def process_email_ingestion_pipeline(user_email: str, history_id: str, message_id: Optional[str] = None):
    """
    Asynchronous forensic ingestion pipeline:
    1. Fetch raw .eml via Gmail API
    2. Parse MIME & Auth headers (SPF/DKIM/DMARC)
    3. Analyze SMTP Received chain & GeoIP
    4. Execute Gemini NLP BEC analysis
    5. Compute composite Threat Score
    6. Execute automated remediation (Score > 80)
    7. Persist records to SQL database
    """
    logger.info(f"Starting ingestion pipeline for mailbox {user_email} (historyId={history_id})")
    
    msg_id = message_id or f"msg_{uuid.uuid4().hex[:12]}"
    org_id = str(uuid.uuid4())
    
    # 1. Fetch raw EML bytes
    gmail_client = GmailClient()
    raw_eml_bytes = gmail_client.fetch_raw_message(user_email, msg_id)
    
    # If in mock/dev mode, construct a sample high-risk BEC .eml payload
    if not raw_eml_bytes:
        sample_eml = f"""Received: from mail-relay-direct.cc (mail-relay-direct.cc [194.26.29.112])
    by mx.google.com with ESMTPS id abc123xyz
    for <{user_email}>; Mon, 22 Aug 2026 09:14:22 +0000
Received: from unknown (HELO tor-exit.amsterdam.nl) [185.220.101.5]
    by mail-relay-direct.cc with ESMTP; Mon, 22 Aug 2026 09:14:18 +0000
Authentication-Results: mx.google.com;
    dkim=fail header.i=@mail-relay-direct.cc;
    spf=fail (google.com: domain of executive-desk-office84@gmail.com does not designate 194.26.29.112 as permitted sender) smtp.mailfrom=executive-desk-office84@gmail.com;
    dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=company.com
Message-ID: <threat-bec-{uuid.uuid4().hex[:8]}@mail-relay-direct.cc>
From: "Sarah Jenkins (CEO)" <sarah.jenkins.corp@mail-relay-direct.cc>
Reply-To: executive-desk-office84@gmail.com
To: {user_email}
Subject: Confidential Acquisition - Urgent Wire Requirement
Date: Mon, 22 Aug 2026 09:14:22 +0000
Content-Type: text/plain; charset="utf-8"

Alex,
I am in a closed-door M&A session with the board. Do not call my cell as I cannot answer.
We need to wire the initial escrow deposit of $148,500.00 immediately to finalize the closing before 2 PM today.
Please remit to:
Beneficiary: Global Escrow Holdings LLC
Bank: Silverline Trust
Routing: 021000021
Account: 883920194829

Send me the transaction confirmation receipt once done.
Sarah Jenkins
Chief Executive Officer
"""
        raw_eml_bytes = sample_eml.encode("utf-8")

    # 2. Parse Raw EML
    parsed = EmlParser.parse_raw_eml(raw_eml_bytes)
    
    # 3. Analyze SMTP Relay Chain & GeoIP
    enriched_hops, originating_geo, reactflow_graph = SMTPHopAnalyzer.analyze_chain(parsed["smtp_hops"])
    
    vip_res = VipImpersonationEngine.analyze(
        sender_display_name=parsed["sender_display_name"],
        sender_header_from=parsed["sender_header_from"],
        reply_to=parsed["reply_to"]
    )
    att_res = AttachmentScanner.scan_attachments(parsed["attachments"])

    # 4. Gemini NLP BEC Evaluation
    nlp_eval = await GeminiNLPAnalyzer.analyze_email(
        subject=parsed["subject"],
        sender_header_from=parsed["sender_header_from"],
        sender_display_name=parsed["sender_display_name"],
        reply_to=parsed["reply_to"],
        recipients=parsed["recipient_to"] if isinstance(parsed["recipient_to"], list) else [parsed["recipient_to"]],
        text_body=parsed["text_body"],
        spf_status=parsed["spf_status"],
        dkim_status=parsed["dkim_status"],
        dmarc_status=parsed["dmarc_status"],
        vip_analysis=vip_res,
        attachment_analysis=att_res
    )
    
    # 5. Composite Threat Score Calculation
    score_breakdown = ThreatScoringEngine.calculate_composite_score(
        gemini_nlp=nlp_eval,
        hop_analysis={"enriched_hops": enriched_hops, "originating_intel": originating_geo},
        vip_engine=vip_res,
        parsed_email=parsed,
        attachment_scanner=att_res
    )
    threat_score = score_breakdown["composite_score"]
    severity = score_breakdown["severity"]
    
    alert_id = str(uuid.uuid4())
    
    # 6. Database Insertion: Alert Record
    alert_payload = {
        "id": alert_id,
        "org_id": org_id,
        "provider_message_id": msg_id,
        "rfc822_message_id": parsed["rfc822_message_id"],
        "sender_envelope": parsed["sender_header_from"],
        "sender_header_from": parsed["sender_header_from"],
        "sender_display_name": parsed["sender_display_name"],
        "reply_to": parsed["reply_to"],
        "recipient_to": parsed["recipient_to"] if isinstance(parsed["recipient_to"], list) else [parsed["recipient_to"]],
        "recipient_cc": parsed["recipient_cc"] or [],
        "subject": parsed["subject"],
        "received_timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_score": threat_score,
        "threat_category": score_breakdown.get("primary_threat_category", "SUSPICIOUS_ANOMALY"),
        "severity": severity,
        "spf_status": parsed["spf_status"],
        "dkim_status": parsed["dkim_status"],
        "dmarc_status": parsed["dmarc_status"],
        "remediation_status": "AUTOMATICALLY_QUARANTINED" if threat_score >= 80 else "INBOX_PROTECTED",
        "applied_labels": ["[SUSPICIOUS]"] if threat_score >= 80 else [],
        "vip_analysis": vip_res,
        "attachment_forensics": att_res
    }
    
    # 7. Database Insertion: Forensics & NLP
    forensic_payload = {
        "id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "originating_ip": originating_geo.get("ip"),
        "originating_country": originating_geo.get("country"),
        "originating_country_name": originating_geo.get("country_name"),
        "originating_city": originating_geo.get("city"),
        "originating_asn": originating_geo.get("asn"),
        "originating_isp": originating_geo.get("isp"),
        "is_tor_or_vpn": originating_geo.get("is_tor_or_vpn", False),
        "smtp_hops": enriched_hops,
        "raw_authentication_results": parsed["raw_authentication_results"],
        "raw_received_headers": parsed["raw_received_headers"],
        "reply_to_mismatch": parsed["reply_to_mismatch"],
        "display_name_spoofing": vip_res.get("is_impersonation_threat", False)
    }
    
    nlp_payload = {
        "id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "model_version": "gemini-1.5-flash",
        "bec_subtype": nlp_eval.get("bec_subtype"),
        "confidence_score": nlp_eval.get("confidence_score", 0.0),
        "urgency_score": nlp_eval.get("urgency_score", 0),
        "financial_request_detected": nlp_eval.get("financial_analysis", {}).get("financial_request_detected", False),
        "requested_amount_usd": nlp_eval.get("financial_analysis", {}).get("requested_amount_usd"),
        "impersonated_executive": nlp_eval.get("impersonation_analysis", {}).get("impersonated_name"),
        "executive_summary": nlp_eval.get("executive_summary", ""),
        "linguistic_cues": nlp_eval.get("linguistic_cues", []),
        "deception_techniques": nlp_eval.get("deception_techniques", []),
        "extracted_bank_entities": nlp_eval.get("financial_analysis", {}).get("extracted_entities", {}),
        "raw_gemini_response": nlp_eval
    }
    
    try:
        await crud.insert_email_alert(alert_payload)
        await crud.insert_forensic_log(forensic_payload)
        await crud.insert_nlp_evaluation(nlp_payload)
    except Exception as e:
        logger.warning(f"Database persistence error: {e}")

    # 8. Automated Remediation
    remediation_res = await RemediationEngine.evaluate_and_remediate(
        alert_id=alert_id,
        org_id=org_id,
        user_email=user_email,
        provider_message_id=msg_id,
        threat_score=threat_score
    )
    
    logger.info(f"Finished pipeline for {msg_id}: Threat Score {threat_score}, Remediation: {remediation_res['action']}")
    return {
        "alert": alert_payload,
        "forensics": forensic_payload,
        "nlp": nlp_payload,
        "remediation": remediation_res,
        "reactflow_graph": reactflow_graph
    }

@router.post("/simulate")
async def simulate_attack_webhook(req: AttackSimulationRequest):
    """
    Simulates inbound threat attack payloads (VIP Impersonation, Quishing, Invoice Fraud, Payroll)
    and executes full ICES forensic analysis and remediation.
    """
    recipient = req.target_recipient or "security-analyst@company.com"
    sim_id = f"sim-{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    if req.attack_type == "quishing_qr_attack":
        sample_eml = f"""Received: from mail-sender.sec-auth.eu (sec-auth.eu [194.26.29.112])
    by mx.google.com with ESMTPS id quish_01
    for <{recipient}>; {now_str}
Authentication-Results: mx.google.com;
    dkim=fail; spf=fail; dmarc=fail
Message-ID: <{sim_id}@sec-auth.eu>
From: "IT Security Helpdesk" <security-portal@sec-auth.eu>
Reply-To: support@sec-auth.eu
To: {recipient}
Subject: Action Required: Re-authenticate Microsoft Authenticator MFA Device
Date: {now_str}
Content-Type: text/plain; charset="utf-8"

SECURITY ADVISORY:
Your 2FA mobile authenticator device registration has expired.
To avoid account lockout, scan the attached QR code with your mobile camera immediately:
https://microsoft-online-secure-auth.eu-west-1.id-verify.com/login?token=8x9Fk2
"""
    elif req.attack_type == "payroll_diversion":
        sample_eml = f"""Received: from hr-portal.org (hr-portal.org [194.26.29.112])
    by mx.google.com with ESMTPS id pay_01
    for <{recipient}>; {now_str}
Authentication-Results: mx.google.com;
    dkim=none; spf=softfail; dmarc=fail
Message-ID: <{sim_id}@hr-portal.org>
From: "David Miller" <david.miller.payroll@gmail.com>
Reply-To: staff-change99@gmail.com
To: {recipient}
Subject: Direct Deposit Account Change Request for Next Pay Period
Date: {now_str}
Content-Type: text/plain; charset="utf-8"

Hello Payroll Team,
I have recently switched banks. Please update my direct deposit bank details to:
Routing Number: 121000248
Account Number: 9948201948
Bank: Wells Fargo NA

Please confirm as soon as this is updated for the upcoming payroll run.
David Miller
"""
    elif req.attack_type == "supplier_invoice":
        sample_eml = f"""Received: from billing-mta.supply-vendor.cc (supply-vendor.cc [193.32.162.88])
    by mx.google.com with ESMTPS id inv_01
    for <{recipient}>; {now_str}
Authentication-Results: mx.google.com;
    dkim=fail; spf=fail; dmarc=fail
Message-ID: <{sim_id}@supply-vendor.cc>
From: "Apex Logistics Accounts" <invoicing@supply-vendor.cc>
Reply-To: vendor-payments@proton.me
To: {recipient}
Subject: Updated Supplier Invoice #94821 & Remittance Routing Changes
Date: {now_str}
Content-Type: text/plain; charset="utf-8"

Dear Accounts Payable Team,
Please find attached our updated monthly logistics invoice #94821 for $45,000.00 USD.
Note that our receiving banking coordinates have changed due to our bank merger.
Please remit all pending wire payments to our new account:
ABA Routing: 121000248
Account: 9948201948
Beneficiary: Apex Logistics Global
"""
    else: # Default: vip_wire_fraud
        sample_eml = f"""Received: from mail-relay-direct.cc (mail-relay-direct.cc [194.26.29.112])
    by mx.google.com with ESMTPS id vip_01
    for <{recipient}>; {now_str}
Received: from unknown (HELO tor-exit.amsterdam.nl) [185.220.101.5]
    by mail-relay-direct.cc with ESMTP; {now_str}
Authentication-Results: mx.google.com;
    dkim=fail header.i=@c0mpany-wire.com;
    spf=fail (google.com: domain does not designate 194.26.29.112 as permitted sender) smtp.mailfrom=sarah.jenkins@c0mpany-wire.com;
    dmarc=fail (p=QUARANTINE) header.from=c0mpany-wire.com
Message-ID: <{sim_id}@c0mpany-wire.com>
From: "Sarah Jenkins (CFO)" <sarah.jenkins@c0mpany-wire.com>
Reply-To: executive-desk-wire@gmail.com
To: {recipient}
Subject: URGENT: Confidential Acquisition Escrow Wire Authorization
Date: {now_str}
Content-Type: text/plain; charset="utf-8"

Hi Team,
I am currently in a closed-door acquisition meeting with the board. Please do not call my mobile.
We need to wire the initial escrow deposit of $148,500.00 immediately before 3 PM today.

Beneficiary: Apex Global Holdings LLC
Bank: Wells Fargo NA
Routing Number: 121000248
Account Number: 99482019482

Please confirm once the wire transfer confirmation receipt is generated.
Sarah Jenkins
Chief Financial Officer
"""

    parsed = EmlParser.parse_raw_eml(sample_eml.encode("utf-8"))
    enriched_hops, originating_geo, reactflow_graph = SMTPHopAnalyzer.analyze_chain(parsed["smtp_hops"])
    
    if req.attack_type == "quishing_qr_attack" and not parsed.get("attachments"):
        parsed["attachments"] = [
            {
                "filename": "mfa_login_qr.png",
                "content_type": "image/png",
                "size_bytes": 14200,
                "raw_bytes": b"https://microsoft-online-secure-auth.eu-west-1.id-verify.com/login?token=8x9Fk2"
            }
        ]
    elif req.attack_type == "supplier_invoice" and not parsed.get("attachments"):
        parsed["attachments"] = [
            {
                "filename": "supplier_invoice_94821.pdf",
                "content_type": "application/pdf",
                "size_bytes": 28400,
                "raw_bytes": b"(INVOICE #94821) (Routing: 121000248) (Account: 9948201948) (Total: $45,000.00)"
            }
        ]

    vip_res = VipImpersonationEngine.analyze(
        sender_display_name=parsed["sender_display_name"],
        sender_header_from=parsed["sender_header_from"],
        reply_to=parsed["reply_to"]
    )
    att_res = AttachmentScanner.scan_attachments(parsed["attachments"])

    nlp_eval = await GeminiNLPAnalyzer.analyze_email(
        subject=parsed["subject"],
        sender_header_from=parsed["sender_header_from"],
        sender_display_name=parsed["sender_display_name"],
        reply_to=parsed["reply_to"],
        recipients=parsed["recipient_to"] or [recipient],
        text_body=parsed["text_body"],
        spf_status=parsed["spf_status"],
        dkim_status=parsed["dkim_status"],
        dmarc_status=parsed["dmarc_status"],
        vip_analysis=vip_res,
        attachment_analysis=att_res
    )
    
    score_breakdown = ThreatScoringEngine.calculate_composite_score(
        gemini_nlp=nlp_eval,
        hop_analysis={"enriched_hops": enriched_hops, "originating_intel": originating_geo},
        vip_engine=vip_res,
        parsed_email=parsed,
        attachment_scanner=att_res
    )

    threat_score = score_breakdown["composite_score"]
    severity = score_breakdown["severity"]
    alert_id = f"sim-alert-{uuid.uuid4().hex[:8]}"

    # Extract URLs
    found_urls = re.findall(r'https?://[^\s<>"]+', parsed["text_body"] or "")
    qr_urls_list = (att_res.get("extracted_qr_urls") or []) if att_res else []
    combined_urls = list(set(found_urls + qr_urls_list))
    extracted_url_telemetry = [
        {
            "url": u,
            "is_insecure_http": u.lower().startswith("http://"),
            "is_qr_code": u in qr_urls_list,
            "risk": "CRITICAL" if u.lower().startswith("http://") or u in qr_urls_list else "LOW"
        }
        for u in combined_urls
    ]

    forensic_payload = {
        "id": f"fl-{sim_id}",
        "alert_id": alert_id,
        "originating_ip": originating_geo.get("ip", "185.220.101.5"),
        "originating_country": originating_geo.get("country", "DE"),
        "originating_country_name": originating_geo.get("country_name", "Germany"),
        "originating_city": originating_geo.get("city", "Frankfurt"),
        "originating_asn": originating_geo.get("asn", "AS60729"),
        "originating_isp": originating_geo.get("isp", "Tor Anonymity Network"),
        "is_tor_or_vpn": originating_geo.get("is_tor_or_vpn", True),
        "smtp_hops": enriched_hops,
        "raw_authentication_results": parsed.get("raw_authentication_results") or f"spf={parsed['spf_status']} dkim={parsed['dkim_status']} dmarc={parsed['dmarc_status']}",
        "raw_received_headers": parsed.get("raw_received_headers") or [],
        "raw_eml_snippet": parsed.get("text_body") or "Simulated EML content",
        "reply_to_mismatch": parsed.get("reply_to_mismatch", False),
        "display_name_spoofing": vip_res.get("is_impersonation_threat", False),
        "lookalike_domain_detected": vip_res.get("lookalike_domain_detected", False),
        "extracted_urls": extracted_url_telemetry
    }

    nlp_payload = {
        "id": f"nlp-{sim_id}",
        "alert_id": alert_id,
        "model_version": "gemini-1.5-flash",
        "bec_subtype": nlp_eval.get("bec_subtype", "SIMULATED_ATTACK"),
        "confidence_score": float(nlp_eval.get("confidence_score", 0.95)),
        "urgency_score": int(nlp_eval.get("urgency_score", 90)),
        "financial_request_detected": bool(nlp_eval.get("financial_analysis", {}).get("financial_request_detected", False)),
        "requested_amount_usd": nlp_eval.get("financial_analysis", {}).get("requested_amount_usd"),
        "impersonated_executive": nlp_eval.get("impersonation_analysis", {}).get("impersonated_name") or parsed.get("sender_display_name"),
        "executive_summary": nlp_eval.get("executive_summary") or "Simulated attack analyzed via ICES intelligence matrix.",
        "linguistic_cues": nlp_eval.get("linguistic_cues", []),
        "deception_techniques": nlp_eval.get("deception_techniques", []),
        "extracted_bank_entities": nlp_eval.get("financial_analysis", {}).get("extracted_entities", {}),
        "raw_gemini_response": nlp_eval
    }

    alert_payload = {
        "id": alert_id,
        "provider_message_id": sim_id,
        "rfc822_message_id": parsed["rfc822_message_id"],
        "sender_envelope": parsed["sender_header_from"],
        "sender_header_from": parsed["sender_header_from"],
        "sender_display_name": parsed["sender_display_name"],
        "reply_to": parsed["reply_to"],
        "recipient_to": [recipient],
        "recipient_cc": [],
        "subject": parsed["subject"],
        "received_timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_score": threat_score,
        "threat_category": score_breakdown.get("primary_threat_category", "SUSPICIOUS_ANOMALY"),
        "severity": severity,
        "spf_status": parsed["spf_status"],
        "dkim_status": parsed["dkim_status"],
        "dmarc_status": parsed["dmarc_status"],
        "remediation_status": "AUTO_QUARANTINED" if threat_score >= 80 else "ALLOWLISTED",
        "applied_labels": ["[SUSPICIOUS]", "QUARANTINED"] if threat_score >= 80 else ["INBOX"],
        "vip_analysis": vip_res,
        "attachment_forensics": att_res,
        "forensic_logs": [forensic_payload],
        "nlp_evaluations": [nlp_payload]
    }

    try:
        await crud.insert_email_alert(alert_payload)
        await crud.insert_forensic_log(forensic_payload)
        await crud.insert_nlp_evaluation(nlp_payload)
    except Exception as e:
        logger.warning(f"Error persisting simulated alert: {e}")

    # Register in memory cache
    from app.api.v1.endpoints.alerts import _PARSED_ALERT_CACHE
    _PARSED_ALERT_CACHE[sim_id] = alert_payload
    _PARSED_ALERT_CACHE[alert_id] = alert_payload

    return {
        "status": "success",
        "simulated": True,
        "attack_type": req.attack_type,
        "threat_score": threat_score,
        "severity": severity,
        "remediation_action": "AUTO_QUARANTINE" if threat_score >= 80 else "DELIVER_NORMAL",
        "alert": alert_payload,
        "nlp_reasoning": nlp_eval.get("executive_summary"),
        "reactflow_graph": reactflow_graph
    }

@router.post("/pubsub", status_code=status.HTTP_200_OK)
async def receive_gcp_pubsub_webhook(envelope: PubSubPushEnvelope, background_tasks: BackgroundTasks):
    """
    Receives Google Cloud Pub/Sub push webhooks for incoming Gmail events.
    Returns HTTP 200 immediately to acknowledge receipt and offloads processing to BackgroundTasks.
    """
    if not envelope.message or not envelope.message.data:
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub envelope: missing message.data")

    try:
        data = GmailClient.decode_pubsub_payload(envelope.message.data)
        user_email = data.get("email_address")
        history_id = data.get("history_id")
        
        logger.info(f"Received Pub/Sub push notification for mailbox: {user_email}, historyId: {history_id}")
        
        # Enqueue pipeline execution in background to prevent Pub/Sub delivery timeout
        background_tasks.add_task(
            process_email_ingestion_pipeline,
            user_email=user_email,
            history_id=history_id
        )
        
        return {"status": "accepted", "email": user_email, "historyId": history_id}
    except Exception as e:
        logger.error(f"Error handling Pub/Sub webhook: {e}")
        raise HTTPException(status_code=500, detail=str(e))
