import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.modules.remediation.actions import RemediationActions
from app.core.config import settings
from app.db import crud

logger = logging.getLogger(__name__)

class RemediationEngine:
    """Evaluates Threat Scores and automates zero-touch containment workflows."""

    @classmethod
    async def evaluate_and_remediate(
        cls,
        alert_id: str,
        org_id: str,
        user_email: str,
        provider_message_id: str,
        threat_score: int,
        provider: str = "google_workspace",
        threshold: int = settings.AUTO_REMEDIATION_THRESHOLD
    ) -> Dict[str, Any]:
        """
        If threat_score > threshold (e.g. 80), automatically quarantines the email
        and attaches [SUSPICIOUS] tag via provider API.
        """
        if threat_score > threshold:
            logger.warning(f"Threat score {threat_score} exceeds threshold {threshold}! Initiating auto-quarantine for {provider_message_id}")
            
            # Execute provider API modification
            action_result = await RemediationActions.quarantine_and_tag(
                provider=provider,
                user_email=user_email,
                message_id=provider_message_id,
                tag_label=settings.SUSPICIOUS_TAG_LABEL_NAME
            )
            
            # Record remediation audit in DB
            audit_entry = {
                "alert_id": alert_id,
                "actor_type": "SYSTEM_POLICY",
                "action_taken": "AUTO_QUARANTINE",
                "previous_status": "PENDING_ANALYSIS",
                "new_status": "AUTO_QUARANTINED",
                "provider_response_code": 200,
                "provider_response_body": action_result,
                "reason": f"Automated Policy Execution: Composite Threat Score ({threat_score}) > Threshold ({threshold})"
            }
            try:
                await crud.record_remediation_audit(audit_entry)
                await crud.update_alert_status(
                    alert_id=alert_id,
                    new_status="AUTO_QUARANTINED",
                    applied_labels=[settings.SUSPICIOUS_TAG_LABEL_NAME, "QUARANTINED"]
                )
            except Exception as e:
                logger.error(f"Error persisting remediation state in database: {e}")

            return {
                "remediated": True,
                "action": "AUTO_QUARANTINED",
                "threat_score": threat_score,
                "threshold": threshold,
                "details": action_result
            }
        else:
            logger.info(f"Threat score {threat_score} <= threshold {threshold}. Message kept in inbox.")
            try:
                await crud.update_alert_status(
                    alert_id=alert_id,
                    new_status="ALLOWLISTED" if threat_score < 20 else "PENDING_ANALYSIS"
                )
            except Exception as e:
                logger.warning(f"Error updating status: {e}")

            return {
                "remediated": False,
                "action": "INBOX_RETAINED",
                "threat_score": threat_score,
                "threshold": threshold
            }
