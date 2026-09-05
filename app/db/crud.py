import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import select, update, desc, func
from sqlalchemy.orm import selectinload
from app.db.database import AsyncSessionLocal
from app.db.models import (
    EmailAlert,
    ForensicLog,
    NlpEvaluation,
    RemediationAuditLog,
    SenderProfile,
    Organization,
    MonitoredMailbox,
    utc_now
)

logger = logging.getLogger(__name__)

async def get_active_mailbox_credentials(user_email: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetches OAuth2 tokens stored in SQL database (Neon PostgreSQL) for a monitored mailbox."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(MonitoredMailbox).where(
                MonitoredMailbox.oauth_credentials.is_not(None),
                MonitoredMailbox.user_email.is_not(None),
                MonitoredMailbox.user_email != ""
            )
            if user_email:
                stmt = stmt.where(MonitoredMailbox.user_email == user_email.lower().strip())
            stmt = stmt.order_by(desc(MonitoredMailbox.updated_at)).limit(1)
            result = await session.execute(stmt)
            mb = result.scalar_one_or_none()
            if mb and mb.oauth_credentials:
                return {
                    "user_email": mb.user_email,
                    "credentials": mb.oauth_credentials
                }
    except Exception as e:
        logger.warning(f"Error fetching mailbox credentials from database: {e}")
    return None


async def update_mailbox_credentials(user_email: str, new_credentials: Dict[str, Any]) -> bool:
    """Persists refreshed OAuth2 access token back into SQL database."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(MonitoredMailbox).where(MonitoredMailbox.user_email == user_email.lower().strip())
            res = await session.execute(stmt)
            mb = res.scalar_one_or_none()
            if mb:
                # Merge new access token and retain refresh_token
                existing = mb.oauth_credentials or {}
                existing.update(new_credentials)
                mb.oauth_credentials = existing
                mb.updated_at = utc_now()
                await session.commit()
                return True
    except Exception as e:
        logger.warning(f"Error updating refreshed mailbox credentials: {e}")
    return False


# ==============================================================================
# Gap 1: Behavioral Baseline (Sender Profile & Frequency Intelligence)
# ==============================================================================

async def get_sender_history(sender_email: str, days: int = 90) -> Dict[str, Any]:
    """
    Retrieves behavioral baseline telemetry for a sender:
    - total communication frequency
    - first & last contact timestamp
    - average threat score
    - is_new_sender detection
    - allowlist / blocklist flags
    """
    if not sender_email:
        return {
            "sender_email": "",
            "is_new_sender": True,
            "total_emails_count": 0,
            "avg_threat_score": 0.0,
            "is_allowlisted": False,
            "is_blocklisted": False,
            "first_seen_at": None,
            "vip_impersonation_attempts": 0
        }

    clean_email = sender_email.lower().strip()
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(SenderProfile).where(SenderProfile.sender_email == clean_email)
            result = await session.execute(stmt)
            profile = result.scalar_one_or_none()

            if profile:
                return {
                    "sender_email": profile.sender_email,
                    "sender_domain": profile.sender_domain,
                    "is_new_sender": False,
                    "total_emails_count": profile.total_emails_count,
                    "avg_threat_score": profile.avg_threat_score,
                    "is_allowlisted": profile.is_allowlisted,
                    "is_blocklisted": profile.is_blocklisted,
                    "first_seen_at": profile.first_seen_at.isoformat() if profile.first_seen_at else None,
                    "last_seen_at": profile.last_seen_at.isoformat() if profile.last_seen_at else None,
                    "vip_impersonation_attempts": profile.vip_impersonation_attempts
                }
            else:
                return {
                    "sender_email": clean_email,
                    "sender_domain": clean_email.split("@")[-1] if "@" in clean_email else "",
                    "is_new_sender": True,
                    "total_emails_count": 0,
                    "avg_threat_score": 0.0,
                    "is_allowlisted": False,
                    "is_blocklisted": False,
                    "first_seen_at": None,
                    "vip_impersonation_attempts": 0
                }
    except Exception as e:
        logger.warning(f"Error fetching sender history for {clean_email}: {e}")
        return {
            "sender_email": clean_email,
            "is_new_sender": True,
            "total_emails_count": 0,
            "avg_threat_score": 0.0,
            "is_allowlisted": False,
            "is_blocklisted": False,
            "first_seen_at": None,
            "vip_impersonation_attempts": 0
        }


async def upsert_sender_profile(
    sender_email: str,
    threat_score: int,
    sender_display_name: Optional[str] = None,
    is_vip_impersonation: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Updates the sender's cumulative profile baseline with new email observations.
    """
    if not sender_email:
        return None

    clean_email = sender_email.lower().strip()
    domain = clean_email.split("@")[-1] if "@" in clean_email else ""

    try:
        async with AsyncSessionLocal() as session:
            stmt = select(SenderProfile).where(SenderProfile.sender_email == clean_email)
            result = await session.execute(stmt)
            profile = result.scalar_one_or_none()

            now = utc_now()
            if profile:
                new_count = profile.total_emails_count + 1
                # Cumulative moving average
                new_avg = round(((profile.avg_threat_score * profile.total_emails_count) + threat_score) / new_count, 2)
                profile.total_emails_count = new_count
                profile.avg_threat_score = new_avg
                profile.last_seen_at = now
                if is_vip_impersonation:
                    profile.vip_impersonation_attempts += 1

                names = list(profile.display_names_seen or [])
                if sender_display_name and sender_display_name not in names:
                    names.append(sender_display_name)
                    profile.display_names_seen = names[-5:] # Keep last 5

            else:
                profile = SenderProfile(
                    sender_email=clean_email,
                    sender_domain=domain,
                    display_names_seen=[sender_display_name] if sender_display_name else [],
                    total_emails_count=1,
                    avg_threat_score=float(threat_score),
                    first_seen_at=now,
                    last_seen_at=now,
                    vip_impersonation_attempts=1 if is_vip_impersonation else 0
                )
                session.add(profile)

            await session.commit()
            return {
                "sender_email": profile.sender_email,
                "total_emails_count": profile.total_emails_count,
                "avg_threat_score": profile.avg_threat_score
            }
    except Exception as e:
        logger.warning(f"Error upserting sender profile for {clean_email}: {e}")
        return None


# ==============================================================================
# Core Alert Persistence (Self-Hosted SQL)
# ==============================================================================

async def insert_email_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Persists a new or updated email security alert into SQL database."""
    try:
        async with AsyncSessionLocal() as session:
            alert_id = str(alert_data.get("id") or f"live-{alert_data.get('provider_message_id')}")
            
            # Check if alert already exists
            stmt = select(EmailAlert).where(EmailAlert.id == alert_id)
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            parsed_ts = alert_data.get("received_timestamp")
            if isinstance(parsed_ts, str):
                try:
                    ts = datetime.fromisoformat(parsed_ts.replace("Z", "+00:00"))
                except Exception:
                    ts = utc_now()
            elif isinstance(parsed_ts, datetime):
                ts = parsed_ts
            else:
                ts = utc_now()

            # Sanitize banner to string for PostgreSQL Text column
            banner_raw = alert_data.get("warning_banner")
            if isinstance(banner_raw, dict):
                banner_str = banner_raw.get("html_markup") or json.dumps(banner_raw)
            elif isinstance(banner_raw, str):
                banner_str = banner_raw
            else:
                banner_str = None

            # Sanitize recipients
            raw_to = alert_data.get("recipient_to") or []
            flat_to = [str(x) for sub in raw_to for x in (sub if isinstance(sub, list) else [sub])] if isinstance(raw_to, list) else [str(raw_to)]

            raw_cc = alert_data.get("recipient_cc") or []
            flat_cc = [str(x) for sub in raw_cc for x in (sub if isinstance(sub, list) else [sub])] if isinstance(raw_cc, list) else [str(raw_cc)]

            if existing:
                existing.threat_score = alert_data.get("threat_score", existing.threat_score)
                existing.threat_category = alert_data.get("threat_category", existing.threat_category)
                existing.severity = alert_data.get("severity", existing.severity)
                existing.remediation_status = alert_data.get("remediation_status", existing.remediation_status)
                existing.applied_labels = alert_data.get("applied_labels", existing.applied_labels)
                existing.warning_banner = banner_str
                existing.vip_analysis = alert_data.get("vip_analysis", existing.vip_analysis)
                existing.attachment_forensics = alert_data.get("attachment_forensics", existing.attachment_forensics)
            else:
                new_alert = EmailAlert(
                    id=alert_id,
                    provider_message_id=str(alert_data.get("provider_message_id") or ""),
                    rfc822_message_id=alert_data.get("rfc822_message_id"),
                    thread_id=alert_data.get("thread_id"),
                    sender_envelope=str(alert_data.get("sender_envelope") or alert_data.get("sender_header_from") or ""),
                    sender_header_from=str(alert_data.get("sender_header_from") or ""),
                    sender_display_name=alert_data.get("sender_display_name"),
                    reply_to=alert_data.get("reply_to"),
                    recipient_to=flat_to,
                    recipient_cc=flat_cc,
                    subject=alert_data.get("subject"),
                    received_timestamp=ts,
                    threat_score=int(alert_data.get("threat_score", 0)),
                    threat_category=str(alert_data.get("threat_category", "SUSPICIOUS_ANOMALY")),
                    severity=str(alert_data.get("severity", "MEDIUM")),
                    spf_status=str(alert_data.get("spf_status", "NONE")),
                    dkim_status=str(alert_data.get("dkim_status", "NONE")),
                    dmarc_status=str(alert_data.get("dmarc_status", "NONE")),
                    remediation_status=str(alert_data.get("remediation_status", "PENDING_ANALYSIS")),
                    applied_labels=alert_data.get("applied_labels") or [],
                    vip_analysis=alert_data.get("vip_analysis") or {},
                    attachment_forensics=alert_data.get("attachment_forensics") or {},
                    warning_banner=banner_str
                )
                session.add(new_alert)

            await session.commit()
            return alert_data
    except Exception as e:
        logger.warning(f"Error persisting email alert to SQL DB: {e}")
        return alert_data


async def insert_forensic_log(forensic_data: Dict[str, Any]) -> Dict[str, Any]:
    """Persists forensic log telemetry."""
    try:
        async with AsyncSessionLocal() as session:
            log_id = str(forensic_data.get("id") or f"fl-{forensic_data.get('alert_id')}")
            stmt = select(ForensicLog).where(ForensicLog.id == log_id)
            res = await session.execute(stmt)
            if not res.scalar_one_or_none():
                raw_c = str(forensic_data.get("originating_country") or "US")
                raw_c_name = str(forensic_data.get("originating_country_name") or forensic_data.get("originating_country") or "Google Cloud")
                f_log = ForensicLog(
                    id=log_id,
                    alert_id=str(forensic_data.get("alert_id")),
                    originating_ip=(str(forensic_data.get("originating_ip"))[:64] if forensic_data.get("originating_ip") else None),
                    originating_hostname=(str(forensic_data.get("originating_hostname"))[:512] if forensic_data.get("originating_hostname") else None),
                    originating_country=raw_c[:16],
                    originating_country_name=raw_c_name[:128],
                    originating_city=(str(forensic_data.get("originating_city"))[:128] if forensic_data.get("originating_city") else None),
                    originating_asn=(str(forensic_data.get("originating_asn"))[:128] if forensic_data.get("originating_asn") else None),
                    originating_isp=(str(forensic_data.get("originating_isp"))[:255] if forensic_data.get("originating_isp") else None),
                    is_tor_or_vpn=bool(forensic_data.get("is_tor_or_vpn", False)),
                    smtp_hops=forensic_data.get("smtp_hops") or [],
                    raw_authentication_results=forensic_data.get("raw_authentication_results"),
                    raw_received_headers=forensic_data.get("raw_received_headers") or [],
                    raw_eml_snippet=forensic_data.get("raw_eml_snippet"),
                    reply_to_mismatch=bool(forensic_data.get("reply_to_mismatch", False)),
                    display_name_spoofing=bool(forensic_data.get("display_name_spoofing", False)),
                    lookalike_domain_detected=bool(forensic_data.get("lookalike_domain_detected", False)),
                    domain_age_days=forensic_data.get("domain_age_days"),
                    extracted_urls=forensic_data.get("extracted_urls") or [],
                    extracted_attachments=forensic_data.get("extracted_attachments") or []
                )
                session.add(f_log)
                await session.commit()
        return forensic_data
    except Exception as e:
        logger.warning(f"Error persisting forensic log to SQL DB: {e}")
        return forensic_data


async def insert_nlp_evaluation(nlp_data: Dict[str, Any]) -> Dict[str, Any]:
    """Persists Gemini BEC/Phishing analysis output."""
    try:
        async with AsyncSessionLocal() as session:
            nlp_id = str(nlp_data.get("id") or f"nlp-{nlp_data.get('alert_id')}")
            stmt = select(NlpEvaluation).where(NlpEvaluation.id == nlp_id)
            res = await session.execute(stmt)
            if not res.scalar_one_or_none():
                nlp = NlpEvaluation(
                    id=nlp_id,
                    alert_id=str(nlp_data.get("alert_id")),
                    model_version=str(nlp_data.get("model_version", "gemini-3.5-flash-lite")),
                    bec_subtype=nlp_data.get("bec_subtype"),
                    confidence_score=float(nlp_data.get("confidence_score", 0.0)),
                    urgency_score=int(nlp_data.get("urgency_score", 0)),
                    financial_request_detected=bool(nlp_data.get("financial_request_detected", False)),
                    requested_amount_usd=float(nlp_data["requested_amount_usd"]) if nlp_data.get("requested_amount_usd") is not None else None,
                    impersonated_executive=nlp_data.get("impersonated_executive"),
                    executive_summary=str(nlp_data.get("executive_summary") or "NLP Evaluation Completed."),
                    linguistic_cues=nlp_data.get("linguistic_cues") or [],
                    deception_techniques=nlp_data.get("deception_techniques") or [],
                    extracted_bank_entities=nlp_data.get("extracted_bank_entities") or {},
                    raw_gemini_response=nlp_data.get("raw_gemini_response") or {}
                )
                session.add(nlp)
                await session.commit()
        return nlp_data
    except Exception as e:
        logger.warning(f"Error persisting nlp evaluation to SQL DB: {e}")
        return nlp_data


async def record_remediation_audit(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """Records an automated or analyst remediation action in the SQL audit log."""
    try:
        async with AsyncSessionLocal() as session:
            log_id = str(audit_data.get("id") or f"audit-{int(datetime.now().timestamp() * 1000)}")
            audit = RemediationAuditLog(
                id=log_id,
                alert_id=str(audit_data.get("alert_id")),
                actor_id=audit_data.get("actor_id"),
                actor_type=str(audit_data.get("actor_type", "SYSTEM_POLICY")),
                action_taken=str(audit_data.get("action_taken", "UNKNOWN")),
                previous_status=audit_data.get("previous_status"),
                new_status=str(audit_data.get("new_status", "UNKNOWN")),
                provider_response_code=audit_data.get("provider_response_code"),
                provider_response_body=audit_data.get("provider_response_body") or {},
                reason=audit_data.get("reason")
            )
            session.add(audit)
            await session.commit()
        return audit_data
    except Exception as e:
        logger.warning(f"Error recording remediation audit to SQL DB: {e}")
        return audit_data


async def update_alert_status(alert_id: str, new_status: str, applied_labels: List[str] = None) -> Dict[str, Any]:
    """Updates the remediation status of an alert in SQL DB."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(EmailAlert).where(EmailAlert.id == alert_id)
            res = await session.execute(stmt)
            alert = res.scalar_one_or_none()
            if alert:
                alert.remediation_status = new_status
                alert.remediated_at = utc_now()
                if applied_labels is not None:
                    alert.applied_labels = applied_labels
                await session.commit()
                return {"id": alert_id, "remediation_status": new_status, "applied_labels": applied_labels}
    except Exception as e:
        logger.warning(f"Error updating alert status in SQL DB: {e}")
    return {"id": alert_id, "remediation_status": new_status, "applied_labels": applied_labels}


async def get_persisted_alerts(limit: int = 50, user_email: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches recently persisted email alerts with multi-mailbox tenant isolation."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(EmailAlert)
                .options(
                    selectinload(EmailAlert.forensic_logs),
                    selectinload(EmailAlert.nlp_evaluations)
                )
            )
            if user_email:
                clean_email = user_email.lower().strip()
                from sqlalchemy import or_, cast, String
                stmt = stmt.where(
                    or_(
                        cast(EmailAlert.recipient_to, String).ilike(f"%{clean_email}%"),
                        EmailAlert.sender_header_from.ilike(f"%{clean_email}%"),
                        EmailAlert.sender_envelope.ilike(f"%{clean_email}%")
                    )
                )
            stmt = stmt.order_by(desc(EmailAlert.received_timestamp), desc(EmailAlert.created_at), desc(EmailAlert.id)).limit(limit)
            result = await session.execute(stmt)
            alerts = result.scalars().all()

            results = []
            for a in alerts:
                f_logs = [
                    {
                        "id": f.id,
                        "alert_id": f.alert_id,
                        "originating_ip": f.originating_ip,
                        "originating_country": f.originating_country,
                        "originating_country_name": f.originating_country_name,
                        "originating_city": f.originating_city,
                        "originating_asn": f.originating_asn,
                        "originating_isp": f.originating_isp,
                        "is_tor_or_vpn": f.is_tor_or_vpn,
                        "reply_to_mismatch": f.reply_to_mismatch,
                        "display_name_spoofing": f.display_name_spoofing,
                        "lookalike_domain_detected": f.lookalike_domain_detected,
                        "raw_authentication_results": f.raw_authentication_results,
                        "raw_received_headers": f.raw_received_headers,
                        "raw_eml_snippet": f.raw_eml_snippet,
                        "smtp_hops": f.smtp_hops
                    } for f in a.forensic_logs
                ]
                nlps = [
                    {
                        "id": n.id,
                        "alert_id": n.alert_id,
                        "model_version": n.model_version,
                        "bec_subtype": n.bec_subtype,
                        "confidence_score": n.confidence_score,
                        "urgency_score": n.urgency_score,
                        "financial_request_detected": n.financial_request_detected,
                        "requested_amount_usd": n.requested_amount_usd,
                        "impersonated_executive": n.impersonated_executive,
                        "executive_summary": n.executive_summary,
                        "linguistic_cues": n.linguistic_cues,
                        "deception_techniques": n.deception_techniques,
                        "extracted_bank_entities": n.extracted_bank_entities
                    } for n in a.nlp_evaluations
                ]

                results.append({
                    "id": a.id,
                    "provider_message_id": a.provider_message_id,
                    "rfc822_message_id": a.rfc822_message_id,
                    "thread_id": a.thread_id,
                    "sender_envelope": a.sender_envelope,
                    "sender_header_from": a.sender_header_from,
                    "sender_display_name": a.sender_display_name,
                    "reply_to": a.reply_to,
                    "recipient_to": a.recipient_to,
                    "recipient_cc": a.recipient_cc,
                    "subject": a.subject,
                    "received_timestamp": a.received_timestamp.isoformat() if a.received_timestamp else utc_now().isoformat(),
                    "threat_score": a.threat_score,
                    "threat_category": a.threat_category,
                    "severity": a.severity,
                    "spf_status": a.spf_status,
                    "dkim_status": a.dkim_status,
                    "dmarc_status": a.dmarc_status,
                    "remediation_status": a.remediation_status,
                    "applied_labels": a.applied_labels,
                    "vip_analysis": a.vip_analysis,
                    "attachment_forensics": a.attachment_forensics,
                    "warning_banner": a.warning_banner,
                    "forensic_logs": f_logs,
                    "nlp_evaluations": nlps
                })
            return results
    except Exception as e:
        logger.warning(f"Error fetching persisted alerts from SQL DB: {e}")
        return []


# ==============================================================================
# Organization Onboarding & Identity Persistence
# ==============================================================================

async def save_organization_onboarding(
    org_name: str,
    domain: str,
    admin_email: str,
    remediation_threshold: int = 80,
    provider: str = "google_workspace"
) -> Dict[str, Any]:
    """Persists or updates the active customer organization and registers the primary monitored mailbox in SQL."""
    try:
        async with AsyncSessionLocal() as session:
            clean_domain = domain.lower().strip()
            stmt = select(Organization).where(Organization.domain == clean_domain)
            res = await session.execute(stmt)
            org = res.scalar_one_or_none()

            if org:
                org.name = org_name
                org.remediation_score_threshold = remediation_threshold
                org.service_account_email = admin_email
                org.provider = provider
            else:
                org = Organization(
                    name=org_name,
                    domain=clean_domain,
                    provider=provider,
                    service_account_email=admin_email,
                    remediation_score_threshold=remediation_threshold
                )
                session.add(org)
            await session.flush()

            # Ensure monitored mailbox exists for admin_email
            clean_email = admin_email.lower().strip()
            mb_stmt = select(MonitoredMailbox).where(MonitoredMailbox.user_email == clean_email)
            mb_res = await session.execute(mb_stmt)
            mailbox = mb_res.scalar_one_or_none()
            if not mailbox:
                mailbox = MonitoredMailbox(
                    org_id=org.id,
                    user_email=clean_email,
                    sync_status="ACTIVE",
                    is_vip=True
                )
                session.add(mailbox)

            await session.commit()
            return {
                "id": org.id,
                "name": org.name,
                "domain": org.domain,
                "provider": org.provider,
                "remediation_score_threshold": org.remediation_score_threshold,
                "service_account_email": org.service_account_email
            }
    except Exception as e:
        logger.warning(f"Error saving organization onboarding to SQL DB: {e}")
        return {
            "name": org_name,
            "domain": domain,
            "provider": provider,
            "remediation_score_threshold": remediation_threshold
        }


async def get_active_organization() -> Optional[Dict[str, Any]]:
    """Returns the primary active organization from the SQL database."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Organization).limit(1)
            res = await session.execute(stmt)
            org = res.scalar_one_or_none()
            if org:
                return {
                    "id": org.id,
                    "name": org.name,
                    "domain": org.domain,
                    "provider": org.provider,
                    "remediation_score_threshold": org.remediation_score_threshold,
                    "service_account_email": org.service_account_email,
                    "created_at": org.created_at.isoformat() if org.created_at else None
                }
    except Exception as e:
        logger.warning(f"Error fetching organization from SQL DB: {e}")
    return None

