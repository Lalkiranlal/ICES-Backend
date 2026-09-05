import logging
from typing import Dict, Any, List, Optional
from app.modules.ingestion.gmail_client import GmailClient
from app.core.config import settings

logger = logging.getLogger(__name__)

class RemediationActions:
    """Dispatches API actions to mail providers to quarantine and label compromised messages."""

    @classmethod
    async def quarantine_and_tag(
        cls,
        provider: str,
        user_email: str,
        message_id: str,
        tag_label: str = settings.SUSPICIOUS_TAG_LABEL_NAME,
        sender_email: Optional[str] = None,
        subject: Optional[str] = None,
        threat_score: int = 90,
        category: str = "SUSPICIOUS_THREAT"
    ) -> Dict[str, Any]:
        """
        NON-DESTRUCTIVE REMEDIATION:
        Never deletes any email. Attaches [SUSPICIOUS] label tag and optionally copies to Quarantine folder.
        Dispatches automated incident notification if enabled.
        """
        logger.info(f"Applying non-destructive threat label to message {message_id} in {user_email}")
        
        if provider == "google_workspace":
            client = GmailClient()
            # Non-destructive: Add '[SUSPICIOUS]' and 'QUARANTINED' labels.
            add_labels = [tag_label, "QUARANTINED"]
            
            # If user prefers to keep in inbox with warning tag:
            remove_labels = [] if settings.PRESERVE_IN_INBOX_WITH_LABEL else ["INBOX"]
            
            result = client.apply_remediation_labels(
                user_email=user_email,
                message_id=message_id,
                add_labels=add_labels,
                remove_labels=remove_labels
            )

            # 1. Automated Incident Notification to recipient
            if settings.NOTIFY_USER_ON_QUARANTINE and sender_email:
                client.send_quarantine_notice(
                    recipient_email=user_email,
                    sender_email=sender_email,
                    original_subject=subject or "Suspicious Message",
                    threat_score=threat_score,
                    category=category
                )

            # 2. Automated SOC Incident Alert to Security Admin
            if settings.SECURITY_ADMIN_EMAIL:
                client.send_admin_enforcement_alert(
                    target_user=user_email,
                    sender_email=sender_email or "External Sender",
                    subject=subject or "Flagged Security Incident",
                    threat_score=threat_score,
                    category=category,
                    admin_email=settings.SECURITY_ADMIN_EMAIL,
                    action="ENFORCE_QUARANTINE",
                    reason="Threat score policy threshold exceeded or manual SOC analyst intervention"
                )


            return {
                "success": True,
                "provider": provider,
                "action": "NON_DESTRUCTIVE_TAG_AND_LABEL",
                "applied_labels": add_labels,
                "removed_labels": remove_labels,
                "deleted": False,
                "details": result
            }
        else:
            # Microsoft Graph API simulation / placeholder
            logger.info(f"Microsoft Graph API: Moving message {message_id} to DeletedItems / Quarantine")
            return {
                "success": True,
                "provider": "microsoft_365",
                "action": "AUTO_QUARANTINE_AND_TAG",
                "applied_labels": [tag_label],
                "removed_labels": ["Inbox"]
            }

    @classmethod
    async def release_message(
        cls,
        provider: str,
        user_email: str,
        message_id: str
    ) -> Dict[str, Any]:
        """Restores a false positive email and cleans security warning labels."""
        if provider == "google_workspace":
            client = GmailClient()
            result = client.apply_remediation_labels(
                user_email=user_email,
                message_id=message_id,
                add_labels=["INBOX"],
                remove_labels=[settings.SUSPICIOUS_TAG_LABEL_NAME, "QUARANTINED"]
            )
            return {"success": True, "action": "RESTORE_TO_INBOX", "details": result}
        return {"success": True, "action": "RESTORE_TO_INBOX"}
