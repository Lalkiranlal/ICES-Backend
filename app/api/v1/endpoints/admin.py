import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.core.config import settings
from app.api.v1.endpoints.alerts import _PARSED_ALERT_CACHE
from app.db import crud
from app.modules.config.dynamic_config import DynamicConfigManager

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory storage for monitored users & dynamic settings
_MONITORED_USERS_REGISTRY = [
    {
        "id": "usr-01",
        "email": "admin@organization.com",
        "display_name": "Primary Monitored Mailbox",
        "provider": "Google Workspace / Gmail",
        "status": "PROTECTED",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "total_scanned": 0,
        "threats_blocked": 0,
        "last_active": "Real-time sync active"
    }
]

_ADMIN_CONFIG = {
    "security_admin_email": settings.SECURITY_ADMIN_EMAIL or "admin@organization.com",
    "notify_user_on_quarantine": settings.NOTIFY_USER_ON_QUARANTINE,
    "auto_remediation_threshold": settings.AUTO_REMEDIATION_THRESHOLD,
    "environment": settings.ENVIRONMENT,
    "gemini_model": settings.GEMINI_MODEL_NAME
}

class VipEntryRequest(BaseModel):
    name: str
    title: Optional[str] = "Executive Staff"
    email: str

class OnboardingRequest(BaseModel):
    org_name: str
    domain: str
    admin_email: str
    provider: Optional[str] = "google_workspace"
    auto_remediation_threshold: Optional[int] = 80
    vips: Optional[List[VipEntryRequest]] = []

class UserRegisterRequest(BaseModel):
    email: str
    display_name: Optional[str] = "Employee Mailbox"
    provider: Optional[str] = "Google Workspace"

class AdminConfigUpdateRequest(BaseModel):
    security_admin_email: Optional[str] = None
    notify_user_on_quarantine: Optional[bool] = None
    auto_remediation_threshold: Optional[int] = None

@router.post("/onboarding")
async def process_organization_onboarding(req: OnboardingRequest) -> Dict[str, Any]:
    """
    Full SaaS Onboarding:
    1. Persists Organization & Monitored Mailbox in Neon/PostgreSQL DB.
    2. Registers Executive VIPs in real-time VIP Engine for impersonation defense.
    3. Configures auto-remediation policy & notification routing.
    """
    # 1. Save to Database
    org = await crud.save_organization_onboarding(
        org_name=req.org_name,
        domain=req.domain,
        admin_email=req.admin_email,
        remediation_threshold=req.auto_remediation_threshold or 80,
        provider=req.provider or "google_workspace"
    )

    # 2. Register VIPs in DynamicConfigManager
    registered_vips = []
    if req.vips:
        for idx, vip in enumerate(req.vips):
            vip_record = {
                "id": f"vip-custom-{idx + 1:02d}",
                "name": vip.name,
                "title": vip.title or "Executive Staff",
                "corporate_email": vip.email,
                "personal_emails": [],
                "monitored_domains": [req.domain],
                "homoglyph_sensitivity": 85,
                "is_active": True
            }
            DynamicConfigManager.save_vip_target(vip_record, author="OnboardingWizard")
            registered_vips.append(vip_record)

    # 3. Update runtime admin config & settings
    _ADMIN_CONFIG["security_admin_email"] = req.admin_email
    _ADMIN_CONFIG["auto_remediation_threshold"] = req.auto_remediation_threshold or 80
    settings.SECURITY_ADMIN_EMAIL = req.admin_email
    settings.AUTO_REMEDIATION_THRESHOLD = req.auto_remediation_threshold or 80

    # 4. Update user registry
    if _MONITORED_USERS_REGISTRY:
        _MONITORED_USERS_REGISTRY[0]["email"] = req.admin_email
        _MONITORED_USERS_REGISTRY[0]["display_name"] = f"{req.org_name} Security Gateway"

    logger.info(f"Successfully completed onboarding for organization '{req.org_name}' ({req.domain}) with {len(registered_vips)} VIPs.")

    return {
        "status": "success",
        "message": f"Organization '{req.org_name}' onboarded successfully.",
        "organization": org,
        "vips_registered": len(registered_vips),
        "config": _ADMIN_CONFIG
    }

@router.get("/onboarding/status")
async def get_onboarding_status() -> Dict[str, Any]:
    """Checks if an organization has been configured in the SQL database."""
    org = await crud.get_active_organization()
    vips = DynamicConfigManager.get_vip_directory()
    return {
        "is_onboarded": org is not None,
        "organization": org,
        "vips_count": len(vips),
        "admin_config": _ADMIN_CONFIG
    }

@router.get("/users")
async def get_monitored_users() -> Dict[str, Any]:
    """Returns the directory of all registered mailboxes and their protection telemetry."""
    active_mb = await crud.get_active_mailbox_credentials()
    primary_email = active_mb.get("user_email") if active_mb else "admin@organization.com"
    all_cached_alerts = list(_PARSED_ALERT_CACHE.values())
    scanned_count = len(all_cached_alerts)
    blocked_count = len([a for a in all_cached_alerts if a.get("threat_score", 0) >= 80 or "QUARANTINED" in a.get("remediation_status", "")])

    if _MONITORED_USERS_REGISTRY:
        _MONITORED_USERS_REGISTRY[0]["email"] = primary_email
        _MONITORED_USERS_REGISTRY[0]["total_scanned"] = scanned_count
        _MONITORED_USERS_REGISTRY[0]["threats_blocked"] = blocked_count
        _MONITORED_USERS_REGISTRY[0]["last_active"] = "Active (<1s ago)" if scanned_count > 0 else "Idle"

    return {
        "status": "success",
        "total_users": len(_MONITORED_USERS_REGISTRY),
        "users": _MONITORED_USERS_REGISTRY,
        "config": _ADMIN_CONFIG
    }


@router.post("/users")
async def register_new_user(req: UserRegisterRequest) -> Dict[str, Any]:
    """Registers a new employee or organizational mailbox for ICES threat protection."""
    for user in _MONITORED_USERS_REGISTRY:
        if user["email"].lower() == req.email.lower():
            return {"status": "exists", "message": f"User {req.email} is already registered.", "user": user}

    new_user = {
        "id": f"usr-{len(_MONITORED_USERS_REGISTRY) + 1:02d}",
        "email": req.email,
        "display_name": req.display_name,
        "provider": req.provider,
        "status": "PROTECTED",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "total_scanned": 0,
        "threats_blocked": 0,
        "last_active": "Pending initial sync"
    }
    _MONITORED_USERS_REGISTRY.append(new_user)
    logger.info(f"Registered new mailbox {req.email} in CloudNet ICES")
    return {"status": "success", "message": f"Successfully registered {req.email}", "user": new_user}

@router.delete("/users/{user_id}")
async def remove_user(user_id: str) -> Dict[str, Any]:
    """Removes a user mailbox from monitoring."""
    global _MONITORED_USERS_REGISTRY
    initial_len = len(_MONITORED_USERS_REGISTRY)
    _MONITORED_USERS_REGISTRY = [u for u in _MONITORED_USERS_REGISTRY if u["id"] != user_id]
    if len(_MONITORED_USERS_REGISTRY) < initial_len:
        return {"status": "success", "message": f"Removed user {user_id}"}
    raise HTTPException(status_code=404, detail="User not found")

@router.get("/config")
async def get_admin_config() -> Dict[str, Any]:
    """Returns organizational alert routing and policy configuration."""
    return _ADMIN_CONFIG

@router.post("/config")
async def update_admin_config(req: AdminConfigUpdateRequest) -> Dict[str, Any]:
    """Updates security admin destination email and automated thresholds."""
    if req.security_admin_email is not None:
        _ADMIN_CONFIG["security_admin_email"] = req.security_admin_email
        settings.SECURITY_ADMIN_EMAIL = req.security_admin_email
    if req.notify_user_on_quarantine is not None:
        _ADMIN_CONFIG["notify_user_on_quarantine"] = req.notify_user_on_quarantine
        settings.NOTIFY_USER_ON_QUARANTINE = req.notify_user_on_quarantine
    if req.auto_remediation_threshold is not None:
        _ADMIN_CONFIG["auto_remediation_threshold"] = req.auto_remediation_threshold
        settings.AUTO_REMEDIATION_THRESHOLD = req.auto_remediation_threshold

    logger.info(f"Updated admin config: {_ADMIN_CONFIG}")
    return {"status": "success", "config": _ADMIN_CONFIG}
