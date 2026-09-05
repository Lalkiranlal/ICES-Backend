import os
import json
import logging
import asyncio
import hashlib
from typing import Dict, Any, List, Optional
import httpx
from app.core.config import settings
from app.modules.config.dynamic_config import DynamicConfigManager

logger = logging.getLogger(__name__)

# Concurrency and Rate Limiting
_LLM_SEMAPHORE = asyncio.Semaphore(1)

# Real-time token accounting
_TOTAL_PROMPT_TOKENS = 0
_TOTAL_CANDIDATE_TOKENS = 0
_TOTAL_TOKENS_CONSUMED = 0
_TOTAL_AI_CALLS = 0

# In-memory analysis cache (key: sha256 of context)
_ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}

# High-Availability Gemini Multi-Model Failover Pool
GEMINI_MODEL_POOL = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-2.5-flash",
    "gemini-3.5-flash-lite"
]


class GeminiNLPAnalyzer:
    """
    Autonomous Threat Intelligence & Business Email Compromise (BEC) NLP Analyzer.
    Features Multi-Model Failover Pool, 429 Resilience, and Token Accounting.
    """

    @classmethod
    async def analyze_email_async(
        cls,
        sender: str = "",
        subject: str = "",
        body_text: str = "",
        received_headers: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        return await cls.analyze_email(
            subject=subject,
            sender_display_name=sender.split("<")[0].strip() if "<" in sender else sender,
            sender_header_from=sender.split("<")[-1].replace(">", "").strip() if "<" in sender else sender,
            recipients=kwargs.get("recipients", []),
            reply_to=kwargs.get("reply_to"),
            text_body=body_text,
            spf_status=kwargs.get("spf_status", "PASS"),
            dkim_status=kwargs.get("dkim_status", "PASS"),
            dmarc_status=kwargs.get("dmarc_status", "PASS"),
            received_headers=received_headers,
            vip_analysis=kwargs.get("vip_analysis"),
            attachment_analysis=kwargs.get("attachment_analysis")
        )

    @classmethod
    async def analyze_email(
        cls,
        subject: str,
        sender_display_name: str,
        sender_header_from: str,
        recipients: List[str],
        reply_to: Optional[str] = None,
        text_body: Optional[str] = None,
        spf_status: str = "PASS",
        dkim_status: str = "PASS",
        dmarc_status: str = "PASS",
        received_headers: Optional[str] = None,
        vip_analysis: Optional[Dict[str, Any]] = None,
        attachment_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        
        email_context = f"""
EMAIL TELEMETRY FOR THREAT EVALUATION:
- Subject: {subject}
- Header From: {sender_header_from} (Display Name: {sender_display_name})
- Reply-To: {reply_to or sender_header_from}
- Recipients: {", ".join(recipients) if recipients else "internal-employee"}
- Authentication Status: SPF={spf_status}, DKIM={dkim_status}, DMARC={dmarc_status}
- VIP Baseline: {json.dumps(vip_analysis or {})}
- Attachment Telemetry: {json.dumps(attachment_analysis or {})}
- Body Content Snippet:
{(text_body or "")[:2500]}
"""
        
        # If API key is provided, execute real Gemini API call
        if settings.GEMINI_API_KEY and settings.GEMINI_API_KEY != "placeholder-key":
            try:
                return await cls._call_gemini_api(email_context)
            except Exception as e:
                logger.warning(f"Gemini API pool busy (429/quota), engaging high-speed heuristic analyzer: {e}")
                
        # Heuristic fallback for zero-dependency / deterministic evaluation
        return cls._heuristic_nlp_evaluation(
            subject=subject,
            display_name=sender_display_name,
            from_email=sender_header_from,
            reply_to=reply_to,
            body=text_body,
            vip_analysis=vip_analysis,
            attachment_analysis=attachment_analysis
        )

    @classmethod
    async def _call_gemini_api(cls, email_context: str) -> Dict[str, Any]:
        """Calls Google Gemini REST API with multi-model failover pool, 429 resilience, and caching."""
        global _TOTAL_PROMPT_TOKENS, _TOTAL_CANDIDATE_TOKENS, _TOTAL_TOKENS_CONSUMED, _TOTAL_AI_CALLS

        # 1. In-Memory Cache Check
        ctx_hash = hashlib.sha256(email_context.encode("utf-8")).hexdigest()
        if ctx_hash in _ANALYSIS_CACHE:
            logger.debug("Serving threat NLP evaluation from in-memory cache.")
            return _ANALYSIS_CACHE[ctx_hash]

        prompt_cfg = DynamicConfigManager.get_prompt_config()
        configured_model = settings.GEMINI_MODEL_NAME or prompt_cfg.get("gemini_model") or "gemini-1.5-flash"
        
        # Build priority model candidate list
        active_models = [configured_model] + [m for m in GEMINI_MODEL_POOL if m != configured_model]

        system_inst = prompt_cfg.get("system_prompt")
        temperature = prompt_cfg.get("temperature", 0.1)

        raw_k = settings.GEMINI_API_KEY.strip()
        clean_key = raw_k.split("=")[-1].strip() if "=" in raw_k else raw_k

        payload = {
            "contents": [{"parts": [{"text": email_context}]}],
            "systemInstruction": {"parts": [{"text": system_inst}]},
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json"
            }
        }

        async with _LLM_SEMAPHORE:
            last_err = None
            for model_name in active_models:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={clean_key}"
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        resp = await client.post(url, json=payload)
                        if resp.status_code == 429:
                            logger.info(f"Model {model_name} rate limit reached. Rotating to next model...")
                            continue  # Rotate to next model immediately without blocking
                        
                        resp.raise_for_status()
                        res_json = resp.json()

                        # Token Accounting
                        usage = res_json.get("usageMetadata", {})
                        p_tok = usage.get("promptTokenCount", 320)
                        c_tok = usage.get("candidatesTokenCount", 75)
                        t_tok = usage.get("totalTokenCount", p_tok + c_tok)

                        _TOTAL_PROMPT_TOKENS += p_tok
                        _TOTAL_CANDIDATE_TOKENS += c_tok
                        _TOTAL_TOKENS_CONSUMED += t_tok
                        _TOTAL_AI_CALLS += 1

                        raw_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
                        parsed = json.loads(raw_text)

                        parsed["token_usage"] = {
                            "prompt_tokens": p_tok,
                            "candidate_tokens": c_tok,
                            "total_tokens": t_tok,
                            "model_version": model_name,
                            "cached": False
                        }

                        # Save in cache
                        _ANALYSIS_CACHE[ctx_hash] = parsed
                        return parsed

                except Exception as e:
                    last_err = e
                    continue

            # If all pool models exhausted, raise to trigger heuristic evaluation
            if last_err:
                raise last_err
            raise RuntimeError("All Gemini models in pool exhausted")

    @classmethod
    def _heuristic_nlp_evaluation(
        cls,
        subject: str,
        display_name: str,
        from_email: str,
        reply_to: Optional[str] = None,
        body: Optional[str] = None,
        vip_analysis: Optional[Dict[str, Any]] = None,
        attachment_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Deterministic zero-latency security heuristic analysis aligned with Gemini JSON schema."""
        import re
        body_safe = body or ""
        text_full = f"{subject} {body_safe}".lower()
        score = 0
        reasons = []
        cues = []
        deceptions = []
        is_threat = False
        cat = "CLEAN"
        subtype = "LEGITIMATE_COMMUNICATION"
        
        # 1. Lookalike domain / VIP spoofing penalty
        is_vip_threat = bool(vip_analysis and (vip_analysis.get("is_impersonation_threat") or vip_analysis.get("is_impersonation")))
        if is_vip_threat:
            score += 75
            is_threat = True
            cat = "BEC_EXECUTIVE_IMPERSONATION"
            subtype = "EXECUTIVE_URGENT_WIRE" if ("wire" in text_full or "escrow" in text_full or "urgent" in text_full) else "EXECUTIVE_IMPERSONATION"
            reasons.append(f"Executive Impersonation: Display name '{display_name}' spoofed from unverified external address.")
            deceptions.append("Executive Authority Spoofing")
            cues.append(f"Display Name Mimicry: {display_name}")

        # 2. Urgent Financial Transfer Triggers
        urgency_terms = ["urgent", "wire transfer", "payment overdue", "gift card", "w-2", "bank account", "direct deposit", "invoice attached", "remittance", "swift", "escrow"]
        matched_terms = [t for t in urgency_terms if t in text_full]
        if matched_terms:
            score += len(matched_terms) * 15
            for m in matched_terms:
                cues.append(f"Urgent Financial Keyword: {m}")
            if "wire" in text_full or "escrow" in text_full:
                is_threat = True
                if cat == "CLEAN":
                    cat = "BEC_EXECUTIVE_IMPERSONATION" if is_vip_threat else "BEC_SUPPLIER_INVOICE_FRAUD"
                subtype = "EXECUTIVE_URGENT_WIRE"
                reasons.append("High-pressure financial wire remittance instructions detected.")
                deceptions.append("Payment Diversion Tactics")
            elif "direct deposit" in text_full or "payroll" in text_full:
                is_threat = True
                cat = "BEC_PAYROLL_DIVERSION"
                subtype = "PAYROLL_DIRECT_DEPOSIT_UPDATE"
                reasons.append("Payroll direct deposit rerouting phrasing detected.")
                deceptions.append("Direct Deposit Tampering")

        # 3. Unencrypted HTTP Link Interception
        if "http://" in (body or "").lower():
            score += 40
            is_threat = True
            if cat == "CLEAN":
                cat = "CREDENTIAL_HARVESTING"
                subtype = "INSECURE_HTTP_CREDENTIAL_RISK"
            reasons.append("Insecure plaintext HTTP link embedded in body.")
            deceptions.append("Unencrypted Credential Harvesting Vector")

        # 4. Attachment Quishing Triggers
        if attachment_analysis and (attachment_analysis.get("is_quishing_detected") or attachment_analysis.get("quishing_detected")):
            score += 85
            is_threat = True
            cat = "QR_CODE_PHISHING"
            subtype = "QR_CODE_CREDENTIAL_PHISH"
            reasons.append("Malicious QR Code (Quishing) identified in attachment.")
            deceptions.append("Optical Channel Obfuscation")

        # Extract amounts and bank coordinates
        fin_req = bool("wire" in text_full or "deposit" in text_full or "invoice" in text_full or "$" in text_full or "bank" in text_full)
        amt_match = re.search(r'\$\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?)', f"{subject} {body_safe}")
        amt = float(amt_match.group(1).replace(",", "")) if amt_match else None
        
        routing_match = re.search(r'\b(?:routing|aba|transit|sort\s*code)[\s:#]+([0-9]{9})\b', text_full, re.IGNORECASE)
        acct_match = re.search(r'\b(?:account|acct|iban)[\s:#]+([0-9A-Z]{6,34})\b', text_full, re.IGNORECASE)

        extracted_entities = {}
        if routing_match:
            extracted_entities["routing_number"] = routing_match.group(1)
        if acct_match:
            extracted_entities["account_number"] = acct_match.group(1)
        if "wells fargo" in text_full:
            extracted_entities["bank_name"] = "Wells Fargo NA"
        elif "silverline" in text_full:
            extracted_entities["bank_name"] = "Silverline Trust"

        beneficiary_m = re.search(r'\b(?:beneficiary|to:)[\s:#]+([A-Za-z0-9\s,.]+)', text_full, re.IGNORECASE)
        if beneficiary_m:
            extracted_entities["beneficiary"] = beneficiary_m.group(1).split("\n")[0].strip()

        score = min(100, max(0, score))
        sev = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 20 else "LOW"))

        confidence = round(min(0.99, max(0.05, score / 100.0)), 2)
        urgency = min(100, max(10, score))

        summary = " ".join(reasons) if reasons else f"Routine inbound communication from {from_email}. Cryptographic headers and reputation are consistent with standard business traffic."

        remediation = "AUTO_QUARANTINE" if score >= 80 else ("APPLY_SUSPICIOUS_BANNER" if score >= 50 else "DELIVER_NORMAL")

        return {
            "is_threat": is_threat or score >= 40,
            "threat_category": cat,
            "bec_subtype": subtype,
            "confidence_score": confidence,
            "urgency_score": urgency,
            "executive_summary": summary,
            "impersonation_analysis": {
                "is_impersonation": is_vip_threat,
                "impersonated_name": ((vip_analysis.get("impersonated_vip") or {}).get("name") if vip_analysis else None) or (display_name if is_vip_threat else None),
                "impersonated_title": (vip_analysis.get("impersonated_vip") or {}).get("title") if vip_analysis else None,
                "spoofing_technique": (vip_analysis.get("spoofing_technique") if vip_analysis else None) or ("DISPLAY_NAME_SPOOF" if is_vip_threat else "NONE")
            },
            "financial_analysis": {
                "financial_request_detected": fin_req,
                "requested_amount_usd": amt,
                "currency": "USD" if amt else None,
                "extracted_entities": extracted_entities
            },
            "linguistic_cues": cues,
            "deception_techniques": deceptions,
            "remediation_recommendation": remediation,
            "threat_score": score,
            "severity": sev,
            "is_bec_threat": is_threat,
            "bec_category": cat,
            "intent_summary": summary,
            "extracted_bank_entities": extracted_entities,
            "token_usage": {
                "prompt_tokens": 0,
                "candidate_tokens": 0,
                "total_tokens": 0,
                "model_version": "heuristic-fallback-v1",
                "cached": False
            }
        }

    @classmethod
    def get_token_accounting(cls) -> Dict[str, Any]:
        """Returns live cumulative token accounting & API invocation stats."""
        global _TOTAL_PROMPT_TOKENS, _TOTAL_CANDIDATE_TOKENS, _TOTAL_TOKENS_CONSUMED, _TOTAL_AI_CALLS
        est_cost = (_TOTAL_PROMPT_TOKENS * 0.000000075) + (_TOTAL_CANDIDATE_TOKENS * 0.0000003)
        return {
            "total_ai_calls": _TOTAL_AI_CALLS,
            "total_prompt_tokens": _TOTAL_PROMPT_TOKENS,
            "total_candidate_tokens": _TOTAL_CANDIDATE_TOKENS,
            "total_tokens_consumed": _TOTAL_TOKENS_CONSUMED,
            "estimated_cost_usd": round(est_cost, 6),
            "cached_evaluations_count": len(_ANALYSIS_CACHE)
        }

    @classmethod
    def get_token_telemetry(cls) -> Dict[str, Any]:
        """Alias for get_token_accounting."""
        return cls.get_token_accounting()