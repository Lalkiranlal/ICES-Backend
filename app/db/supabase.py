import logging
from typing import Optional, Dict, Any, List
from app.db import crud

logger = logging.getLogger(__name__)

# Forward calls directly to the self-hosted portable SQL CRUD engine
async def insert_email_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    return await crud.insert_email_alert(alert_data)

async def insert_forensic_log(forensic_data: Dict[str, Any]) -> Dict[str, Any]:
    return await crud.insert_forensic_log(forensic_data)

async def insert_nlp_evaluation(nlp_data: Dict[str, Any]) -> Dict[str, Any]:
    return await crud.insert_nlp_evaluation(nlp_data)

async def record_remediation_audit(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    return await crud.record_remediation_audit(audit_data)

async def update_alert_status(alert_id: str, new_status: str, applied_labels: List[str] = None) -> Dict[str, Any]:
    return await crud.update_alert_status(alert_id, new_status, applied_labels)
