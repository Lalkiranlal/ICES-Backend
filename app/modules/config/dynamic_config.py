import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.core.config import settings

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """You are ApexShield-NLP, an advanced AI engine in an Integrated Cloud Email Security (ICES) platform.
Your task is to analyze email headers, sender identities, and content to detect Business Email Compromise (BEC), Executive VIP Impersonation, Supplier Invoice Fraud, and Social Engineering.
You must respond with pure JSON adhering to the specified schema with fields:
- is_threat (boolean)
- threat_category (string: BEC_EXECUTIVE_IMPERSONATION, BEC_PAYROLL_DIVERSION, BEC_SUPPLIER_INVOICE_FRAUD, CREDENTIAL_HARVESTING, EXTORTION_RANSOM, SUSPICIOUS_ANOMALY, CLEAN)
- bec_subtype (string)
- confidence_score (number 0.0-1.0)
- urgency_score (integer 0-100)
- executive_summary (concise 2-sentence summary)
- impersonation_analysis (object with is_impersonation, impersonated_name, spoofing_technique)
- financial_analysis (object with financial_request_detected, requested_amount_usd, extracted_entities)
- linguistic_cues (array of string phrases)
- deception_techniques (array of strings)
- remediation_recommendation (AUTO_QUARANTINE, APPLY_SUSPICIOUS_BANNER, DELIVER_NORMAL)
"""

DEFAULT_PAYROLL_PHRASES = [
    "change my direct deposit", "update my direct deposit", "change direct deposit",
    "update direct deposit", "new direct deposit", "change my bank account for payroll",
    "update my bank details for payroll", "switch my direct deposit", "new banking details for my paycheck",
    "change my paycheck account", "divert my payroll", "update payroll account"
]

DEFAULT_WIRE_PHRASES = [
    "wire transfer", "wire funds", "wire payment", "escrow transfer", "bank wire",
    "send wire", "authorize wire", "transfer funds", "remittance transfer", "wire authorization"
]

DEFAULT_URGENCY_PHRASES = [
    "urgent", "immediately", "asap", "strictly confidential", "closed-door",
    "do not call", "confidential acquisition", "time-sensitive wire", "today before close of business"
]

DEFAULT_TRUSTED_DOMAINS = [
    {"domain": "linkedin.com", "name": "LinkedIn Platform", "category": "Professional Social / InMail", "status": "ACTIVE"},
    {"domain": "messaging.linkedin.com", "name": "LinkedIn InMail Relay", "category": "InMail Relay", "status": "ACTIVE"},
    {"domain": "e.linkedin.com", "name": "LinkedIn Notification Services", "category": "Platform Notifications", "status": "ACTIVE"},
    {"domain": "github.com", "name": "GitHub Inc.", "category": "Developer Platform", "status": "ACTIVE"},
    {"domain": "google.com", "name": "Google Workspace Services", "category": "Cloud Suite", "status": "ACTIVE"},
    {"domain": "slack.com", "name": "Slack Technologies", "category": "Collaboration", "status": "ACTIVE"},
    {"domain": "stripe.com", "name": "Stripe Payments", "category": "Financial Infrastructure", "status": "ACTIVE"},
    {"domain": "microsoft.com", "name": "Microsoft 365", "category": "Enterprise Suite", "status": "ACTIVE"},
    {"domain": "apple.com", "name": "Apple Services", "category": "Platform Notifications", "status": "ACTIVE"},
    {"domain": "zoom.us", "name": "Zoom Video Communications", "category": "Video Conferencing", "status": "ACTIVE"}
]

DEFAULT_VIP_DIRECTORY = [
    {
        "id": "vip-01",
        "name": "Alex Mercer",
        "title": "Chief Executive Officer (CEO)",
        "corporate_email": "alex.mercer@cloudnet.io",
        "personal_emails": [],
        "homoglyph_sensitivity": 85,
        "is_active": True
    },
    {
        "id": "vip-02",
        "name": "Sarah Jenkins",
        "title": "Chief Financial Officer (CFO)",
        "corporate_email": "sarah.jenkins@cloudnet.io",
        "personal_emails": [],
        "homoglyph_sensitivity": 90,
        "is_active": True
    },
    {
        "id": "vip-03",
        "name": "David Marcus",
        "title": "VP of Engineering",
        "corporate_email": "david.marcus@cloudnet.io",
        "personal_emails": [],
        "homoglyph_sensitivity": 80,
        "is_active": True
    }
]

class DynamicConfigManager:
    """Manages all runtime SaaS configurations, prompt engineering definitions, and security rules."""
    
    _config: Dict[str, Any] = {
        "prompt_config": {
            "system_prompt": DEFAULT_SYSTEM_PROMPT,
            "gemini_model": settings.GEMINI_MODEL_NAME or "gemini-3.5-flash-lite",
            "gemini_api_key": settings.GEMINI_API_KEY or "",
            "temperature": 0.1,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 1024,
            "response_mime_type": "application/json"
        },

        "trusted_domains": DEFAULT_TRUSTED_DOMAINS,
        "vip_directory": DEFAULT_VIP_DIRECTORY,
        "heuristic_rules": {
            "payroll_phrases": DEFAULT_PAYROLL_PHRASES,
            "wire_phrases": DEFAULT_WIRE_PHRASES,
            "urgency_phrases": DEFAULT_URGENCY_PHRASES
        },
        "policies": {
            "auto_remediation_threshold": settings.AUTO_REMEDIATION_THRESHOLD,
            "caution_banner_threshold": 50,
            "security_admin_email": settings.SECURITY_ADMIN_EMAIL or "admin@cloudnet.io",
            "notify_user_on_quarantine": settings.NOTIFY_USER_ON_QUARANTINE,
            "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/X00",
            "webhook_alerting_enabled": False
        },
        "banner_customizer": {
            "threat_banner_title": "CRITICAL SECURITY WARNING: SUSPECTED THREAT QUARANTINED",
            "caution_banner_title": "CAUTION: UNVERIFIED EXTERNAL SENDER",
            "verified_banner_title": "VERIFIED: AUTHENTICATED INTERNAL SENDER",
            "security_contact_email": "security@cloudnet.io"
        },
        "audit_logs": [
            {
                "id": "aud-init",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "author": "SuperAdmin (System)",
                "action": "PLATFORM_INITIALIZATION",
                "details": "ApexShield-NLP ICES control plane initialized with default enterprise baselines."
            }
        ]
    }

    @classmethod
    def get_all_config(cls) -> Dict[str, Any]:
        """Returns full platform configuration snapshot."""
        return cls._config

    @classmethod
    def get_prompt_config(cls) -> Dict[str, Any]:
        return cls._config["prompt_config"]

    @classmethod
    def update_prompt_config(cls, prompt_data: Dict[str, Any], author: str = "SuperAdmin") -> Dict[str, Any]:
        cls._config["prompt_config"].update(prompt_data)
        if "gemini_model" in prompt_data:
            settings.GEMINI_MODEL_NAME = prompt_data["gemini_model"]
        if "gemini_api_key" in prompt_data:
            settings.GEMINI_API_KEY = prompt_data["gemini_api_key"]
        
        cls._record_audit(author, "PROMPT_ENGINEERING_UPDATE", f"Updated Gemini model to {cls._config['prompt_config']['gemini_model']} and adjusted system instructions.")
        return cls._config["prompt_config"]


    @classmethod
    def get_trusted_domains(cls) -> List[Dict[str, Any]]:
        return cls._config["trusted_domains"]

    @classmethod
    def add_trusted_domain(cls, domain_entry: Dict[str, Any], author: str = "SuperAdmin") -> List[Dict[str, Any]]:
        domain = domain_entry.get("domain", "").lower().strip()
        if not domain:
            return cls._config["trusted_domains"]
        
        # Check if already exists
        for d in cls._config["trusted_domains"]:
            if d["domain"].lower() == domain:
                d.update(domain_entry)
                cls._record_audit(author, "TRUSTED_DOMAIN_UPDATED", f"Updated trusted platform '{domain}'.")
                return cls._config["trusted_domains"]
        
        new_entry = {
            "domain": domain,
            "name": domain_entry.get("name", domain.capitalize()),
            "category": domain_entry.get("category", "Enterprise SaaS Partner"),
            "status": domain_entry.get("status", "ACTIVE")
        }
        cls._config["trusted_domains"].append(new_entry)
        cls._record_audit(author, "TRUSTED_DOMAIN_ADDED", f"Added '{domain}' to global trusted platform allowlist.")
        return cls._config["trusted_domains"]

    @classmethod
    def remove_trusted_domain(cls, domain: str, author: str = "SuperAdmin") -> List[Dict[str, Any]]:
        cls._config["trusted_domains"] = [d for d in cls._config["trusted_domains"] if d["domain"].lower() != domain.lower()]
        cls._record_audit(author, "TRUSTED_DOMAIN_REMOVED", f"Removed '{domain}' from trusted platform allowlist.")
        return cls._config["trusted_domains"]

    @classmethod
    def is_trusted_domain(cls, domain: str) -> bool:
        domain = domain.lower().strip()
        for entry in cls._config["trusted_domains"]:
            if entry.get("status") == "ACTIVE":
                td = entry["domain"].lower()
                if domain == td or domain.endswith("." + td):
                    return True
        return False

    @classmethod
    def get_vip_directory(cls) -> List[Dict[str, Any]]:
        return cls._config["vip_directory"]

    @classmethod
    def save_vip_target(cls, vip_data: Dict[str, Any], author: str = "SuperAdmin") -> List[Dict[str, Any]]:
        vip_id = vip_data.get("id") or f"vip-{len(cls._config['vip_directory']) + 1:02d}"
        vip_data["id"] = vip_id

        # Update if exists
        for idx, vip in enumerate(cls._config["vip_directory"]):
            if vip["id"] == vip_id:
                cls._config["vip_directory"][idx].update(vip_data)
                cls._record_audit(author, "VIP_TARGET_UPDATED", f"Updated VIP Executive profile for '{vip_data.get('name')}'.")
                return cls._config["vip_directory"]

        cls._config["vip_directory"].append(vip_data)
        cls._record_audit(author, "VIP_TARGET_ADDED", f"Registered new VIP Executive '{vip_data.get('name')}' in identity directory.")
        return cls._config["vip_directory"]

    @classmethod
    def remove_vip_target(cls, vip_id: str, author: str = "SuperAdmin") -> List[Dict[str, Any]]:
        target_name = vip_id
        for v in cls._config["vip_directory"]:
            if v["id"] == vip_id:
                target_name = v.get("name", vip_id)
                break
        cls._config["vip_directory"] = [v for v in cls._config["vip_directory"] if v["id"] != vip_id]
        cls._record_audit(author, "VIP_TARGET_REMOVED", f"Removed VIP profile '{target_name}'.")
        return cls._config["vip_directory"]

    @classmethod
    def get_heuristic_rules(cls) -> Dict[str, Any]:
        return cls._config["heuristic_rules"]

    @classmethod
    def update_heuristic_rules(cls, rules: Dict[str, Any], author: str = "SuperAdmin") -> Dict[str, Any]:
        cls._config["heuristic_rules"].update(rules)
        cls._record_audit(author, "HEURISTIC_RULES_UPDATED", "Updated NLP heuristic keyword triggers and fraud intent phrase matrices.")
        return cls._config["heuristic_rules"]

    @classmethod
    def get_policies(cls) -> Dict[str, Any]:
        return cls._config["policies"]

    @classmethod
    def update_policies(cls, policies: Dict[str, Any], author: str = "SuperAdmin") -> Dict[str, Any]:
        cls._config["policies"].update(policies)
        if "auto_remediation_threshold" in policies:
            settings.AUTO_REMEDIATION_THRESHOLD = policies["auto_remediation_threshold"]
        if "security_admin_email" in policies:
            settings.SECURITY_ADMIN_EMAIL = policies["security_admin_email"]
        if "notify_user_on_quarantine" in policies:
            settings.NOTIFY_USER_ON_QUARANTINE = policies["notify_user_on_quarantine"]
        
        cls._record_audit(author, "POLICY_UPDATED", f"Updated automated quarantine threshold to {cls._config['policies']['auto_remediation_threshold']} and routing rules.")
        return cls._config["policies"]

    @classmethod
    def get_audit_logs(cls) -> List[Dict[str, Any]]:
        return cls._config["audit_logs"]

    @classmethod
    def _record_audit(cls, author: str, action: str, details: str):
        entry = {
            "id": f"aud-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "author": author,
            "action": action,
            "details": details
        }
        cls._config["audit_logs"].insert(0, entry)
        logger.info(f"[SUPER-ADMIN AUDIT] {action} by {author}: {details}")
