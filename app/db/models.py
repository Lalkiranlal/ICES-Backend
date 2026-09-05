import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from app.db.database import Base

def utc_now():
    return datetime.now(timezone.utc)

def generate_uuid():
    return str(uuid.uuid4())

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True)
    provider = Column(String(64), nullable=False, default="google_workspace")
    tenant_external_id = Column(String(255), nullable=True)
    service_account_email = Column(String(255), nullable=True)
    auto_remediation_enabled = Column(Boolean, nullable=False, default=True)
    remediation_score_threshold = Column(Integer, nullable=False, default=80)
    quarantine_mailbox = Column(String(255), default="security-quarantine@company.internal")
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    mailboxes = relationship("MonitoredMailbox", back_populates="organization", cascade="all, delete-orphan")
    alerts = relationship("EmailAlert", back_populates="organization", cascade="all, delete-orphan")
    sender_profiles = relationship("SenderProfile", back_populates="organization", cascade="all, delete-orphan")


class MonitoredMailbox(Base):
    __tablename__ = "monitored_mailboxes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    user_email = Column(String(255), nullable=False, index=True)
    history_id = Column(String(128), nullable=True)
    subscription_expiration = Column(DateTime(timezone=True), nullable=True)
    sync_status = Column(String(64), default="ACTIVE")
    is_vip = Column(Boolean, default=False)
    oauth_credentials = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="mailboxes")
    alerts = relationship("EmailAlert", back_populates="mailbox")


class EmailAlert(Base):
    __tablename__ = "email_alerts"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    mailbox_id = Column(String(36), ForeignKey("monitored_mailboxes.id", ondelete="SET NULL"), nullable=True)
    provider_message_id = Column(String(255), nullable=False, index=True)
    rfc822_message_id = Column(String(512), nullable=True)
    thread_id = Column(String(255), nullable=True)

    sender_envelope = Column(String(255), nullable=False, index=True)
    sender_header_from = Column(String(255), nullable=False, index=True)
    sender_display_name = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    recipient_to = Column(JSON, default=list)
    recipient_cc = Column(JSON, default=list)
    subject = Column(Text, nullable=True)
    received_timestamp = Column(DateTime(timezone=True), default=utc_now)

    threat_score = Column(Integer, nullable=False, default=0, index=True)
    threat_category = Column(String(64), nullable=False, default="SUSPICIOUS_ANOMALY", index=True)
    severity = Column(String(32), nullable=False, default="MEDIUM", index=True)

    spf_status = Column(String(32), default="NONE")
    dkim_status = Column(String(32), default="NONE")
    dmarc_status = Column(String(32), default="NONE")

    remediation_status = Column(String(64), nullable=False, default="PENDING_ANALYSIS", index=True)
    remediated_at = Column(DateTime(timezone=True), nullable=True)
    remediated_by = Column(String(64), default="AUTOMATED_ENGINE")
    applied_labels = Column(JSON, default=list)

    vip_analysis = Column(JSON, default=dict)
    attachment_forensics = Column(JSON, default=dict)
    warning_banner = Column(Text, nullable=True)

    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="alerts")
    mailbox = relationship("MonitoredMailbox", back_populates="alerts")
    forensic_logs = relationship("ForensicLog", back_populates="alert", cascade="all, delete-orphan")
    nlp_evaluations = relationship("NlpEvaluation", back_populates="alert", cascade="all, delete-orphan")
    remediation_audit_logs = relationship("RemediationAuditLog", back_populates="alert", cascade="all, delete-orphan")


class ForensicLog(Base):
    __tablename__ = "forensic_logs"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    alert_id = Column(String(64), ForeignKey("email_alerts.id", ondelete="CASCADE"), nullable=False, index=True)

    originating_ip = Column(String(64), nullable=True)
    originating_hostname = Column(String(512), nullable=True)
    originating_country = Column(String(128), nullable=True)
    originating_country_name = Column(String(128), nullable=True)
    originating_city = Column(String(128), nullable=True)
    originating_asn = Column(String(128), nullable=True)
    originating_isp = Column(String(255), nullable=True)
    is_tor_or_vpn = Column(Boolean, default=False)

    smtp_hops = Column(JSON, default=list)

    raw_authentication_results = Column(Text, nullable=True)
    raw_received_headers = Column(JSON, default=list)
    raw_eml_snippet = Column(Text, nullable=True)
    reply_to_mismatch = Column(Boolean, default=False)
    display_name_spoofing = Column(Boolean, default=False)
    lookalike_domain_detected = Column(Boolean, default=False)
    domain_age_days = Column(Integer, nullable=True)

    extracted_urls = Column(JSON, default=list)
    extracted_attachments = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    alert = relationship("EmailAlert", back_populates="forensic_logs")


class NlpEvaluation(Base):
    __tablename__ = "nlp_evaluations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    alert_id = Column(String(64), ForeignKey("email_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    model_version = Column(String(64), default="gemini-3.5-flash-lite")

    bec_subtype = Column(String(128), nullable=True)
    confidence_score = Column(Float, default=0.0)
    urgency_score = Column(Integer, default=0)
    financial_request_detected = Column(Boolean, default=False)
    requested_amount_usd = Column(Float, nullable=True)
    impersonated_executive = Column(String(255), nullable=True)

    executive_summary = Column(Text, nullable=False)
    linguistic_cues = Column(JSON, default=list)
    deception_techniques = Column(JSON, default=list)
    extracted_bank_entities = Column(JSON, default=dict)
    raw_gemini_response = Column(JSON, default=dict)

    created_at = Column(DateTime(timezone=True), default=utc_now)

    alert = relationship("EmailAlert", back_populates="nlp_evaluations")


class RemediationAuditLog(Base):
    __tablename__ = "remediation_audit_logs"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    alert_id = Column(String(64), ForeignKey("email_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = Column(String(64), nullable=True)
    actor_type = Column(String(32), default="SYSTEM_POLICY")
    action_taken = Column(String(64), nullable=False)
    previous_status = Column(String(64), nullable=True)
    new_status = Column(String(64), nullable=False)
    provider_response_code = Column(Integer, nullable=True)
    provider_response_body = Column(JSON, default=dict)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    alert = relationship("EmailAlert", back_populates="remediation_audit_logs")


# ==============================================================================
# Gap 1: Behavioral Baseline (Sender Profile & Frequency History)
# ==============================================================================
class SenderProfile(Base):
    __tablename__ = "sender_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    sender_email = Column(String(255), nullable=False, unique=True, index=True)
    sender_domain = Column(String(255), nullable=True, index=True)
    display_names_seen = Column(JSON, default=list)
    
    first_seen_at = Column(DateTime(timezone=True), default=utc_now)
    last_seen_at = Column(DateTime(timezone=True), default=utc_now)
    total_emails_count = Column(Integer, default=1)
    avg_threat_score = Column(Float, default=0.0)
    vip_impersonation_attempts = Column(Integer, default=0)
    
    is_allowlisted = Column(Boolean, default=False)
    is_blocklisted = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="sender_profiles")
