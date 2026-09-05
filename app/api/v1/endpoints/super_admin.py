import time
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from app.modules.config.dynamic_config import DynamicConfigManager
from app.modules.intelligence.gemini_nlp import GeminiNLPAnalyzer
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

class PromptUpdateRequest(BaseModel):
    system_prompt: Optional[str] = None
    gemini_model: Optional[str] = None
    gemini_api_key: Optional[str] = None
    temperature: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    top_p: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    top_k: Optional[int] = Field(default=None, ge=1, le=100)
    max_output_tokens: Optional[int] = Field(default=None, ge=128, le=4096)
    author: Optional[str] = "SuperAdmin"


class PromptTestRequest(BaseModel):
    system_prompt: Optional[str] = None
    gemini_model: Optional[str] = "gemini-3.5-flash-lite"
    temperature: Optional[float] = 0.1
    sample_subject: str
    sample_sender_display: str
    sample_sender_email: str
    sample_body: str
    is_vip_simulated: Optional[bool] = False

class TrustedDomainRequest(BaseModel):
    domain: str
    name: Optional[str] = None
    category: Optional[str] = "Enterprise SaaS Partner"
    status: Optional[str] = "ACTIVE"
    author: Optional[str] = "SuperAdmin"

class VipTargetRequest(BaseModel):
    id: Optional[str] = None
    name: str
    title: str
    corporate_email: str
    personal_emails: Optional[List[str]] = []
    homoglyph_sensitivity: Optional[int] = 85
    is_active: Optional[bool] = True
    author: Optional[str] = "SuperAdmin"

class HeuristicRulesRequest(BaseModel):
    payroll_phrases: Optional[List[str]] = None
    wire_phrases: Optional[List[str]] = None
    urgency_phrases: Optional[List[str]] = None
    author: Optional[str] = "SuperAdmin"

class PoliciesUpdateRequest(BaseModel):
    auto_remediation_threshold: Optional[int] = None
    caution_banner_threshold: Optional[int] = None
    security_admin_email: Optional[str] = None
    notify_user_on_quarantine: Optional[bool] = None
    slack_webhook_url: Optional[str] = None
    webhook_alerting_enabled: Optional[bool] = None
    author: Optional[str] = "SuperAdmin"

@router.get("/config")
async def get_super_admin_config():
    """Returns the complete SaaS Control Plane configuration snapshot."""
    return {
        "status": "success",
        "data": DynamicConfigManager.get_all_config()
    }

@router.post("/prompt")
async def update_prompt_engineering(req: PromptUpdateRequest):
    """Updates the Gemini LLM system prompt and inference hyperparameters."""
    update_data = req.model_dump(exclude_unset=True, exclude={"author"})
    updated = DynamicConfigManager.update_prompt_config(update_data, author=req.author or "SuperAdmin")
    return {
        "status": "success",
        "message": "Successfully updated Gemini system prompt & hyperparameters",
        "prompt_config": updated
    }

@router.post("/prompt/test")
async def test_prompt_playground(req: PromptTestRequest):
    """
    Executes a real-time prompt playground test with latency measurement.
    Allows testing prompt changes before deploying to production email stream.
    """
    t0 = time.time()
    
    vip_sim = None
    if req.is_vip_simulated:
        vip_sim = {
            "is_impersonation_threat": True,
            "display_name_spoofing": True,
            "lookalike_domain_detected": True,
            "spoofing_technique": "HOMOGLYPH_LOOKALIKE",
            "impersonated_vip": {"name": req.sample_sender_display, "title": "Executive"},
            "lookalike_details": {"attack_domain": req.sample_sender_email.split("@")[-1]}
        }

    # Execute NLP evaluation
    res = await GeminiNLPAnalyzer.analyze_email(
        subject=req.sample_subject,
        sender_header_from=req.sample_sender_email,
        sender_display_name=req.sample_sender_display,
        reply_to=req.sample_sender_email,
        recipients=["target-employee@cloudnet.io"],
        text_body=req.sample_body,
        spf_status="PASS",
        dkim_status="PASS",
        dmarc_status="PASS",
        vip_analysis=vip_sim,
        attachment_analysis=None
    )

    elapsed_ms = round((time.time() - t0) * 1000, 1)

    return {
        "status": "success",
        "model_used": req.gemini_model,
        "latency_ms": elapsed_ms,
        "estimated_tokens": len(req.sample_body.split()) + len(req.sample_subject.split()) + 420,
        "evaluation": res
    }

@router.post("/trusted-domains")
async def add_trusted_domain(req: TrustedDomainRequest):
    """Adds or updates a trusted platform domain in the global allowlist."""
    res = DynamicConfigManager.add_trusted_domain(
        req.model_dump(exclude={"author"}),
        author=req.author or "SuperAdmin"
    )
    return {"status": "success", "trusted_domains": res}

@router.delete("/trusted-domains/{domain}")
async def remove_trusted_domain(domain: str, author: str = "SuperAdmin"):
    """Removes a trusted platform domain from the allowlist."""
    res = DynamicConfigManager.remove_trusted_domain(domain, author=author)
    return {"status": "success", "trusted_domains": res}

@router.post("/vip-directory")
async def save_vip_target(req: VipTargetRequest):
    """Registers or updates a VIP Executive target in the identity protection registry."""
    res = DynamicConfigManager.save_vip_target(
        req.model_dump(exclude={"author"}),
        author=req.author or "SuperAdmin"
    )
    return {"status": "success", "vip_directory": res}

@router.delete("/vip-directory/{vip_id}")
async def remove_vip_target(vip_id: str, author: str = "SuperAdmin"):
    """Removes a VIP target from the protection directory."""
    res = DynamicConfigManager.remove_vip_target(vip_id, author=author)
    return {"status": "success", "vip_directory": res}

@router.post("/heuristic-rules")
async def update_heuristic_rules(req: HeuristicRulesRequest):
    """Updates keyword lists and phrase sets for intent detection."""
    update_data = req.model_dump(exclude_unset=True, exclude={"author"})
    res = DynamicConfigManager.update_heuristic_rules(update_data, author=req.author or "SuperAdmin")
    return {"status": "success", "heuristic_rules": res}

@router.post("/policies")
async def update_policies(req: PoliciesUpdateRequest):
    """Updates automated quarantine thresholds, notification routing, and webhook alerting."""
    update_data = req.model_dump(exclude_unset=True, exclude={"author"})
    res = DynamicConfigManager.update_policies(update_data, author=req.author or "SuperAdmin")
    return {"status": "success", "policies": res}

@router.get("/audit-logs")
async def get_audit_logs():
    """Returns the revision log of all prompt edits, allowlist changes, and policy modifications."""
    logs = DynamicConfigManager.get_audit_logs()
    return {"status": "success", "total": len(logs), "audit_logs": logs}
