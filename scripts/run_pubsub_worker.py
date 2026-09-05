#!/usr/bin/env python3
"""
Real-Time Pub/Sub Pull Worker & Live Ingestion Daemon
=====================================================
Pulls incoming email notifications directly from your GCP Pub/Sub topic subscription in real time.
Eliminates the need for public webhooks or ngrok during local development and testing!

Usage:
  ./venv/bin/python3 scripts/run_pubsub_worker.py
"""

import os
import sys
import json
import base64
import asyncio
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.cloud import pubsub_v1

# Setup paths for backend imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.modules.ingestion.parser import EmlParser
from app.modules.intelligence.hop_analyzer import SMTPHopAnalyzer
from app.modules.intelligence.gemini_nlp import GeminiNLPAnalyzer
from app.modules.intelligence.scoring import ThreatScoringEngine
from app.modules.remediation.actions import RemediationActions
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("LiveIngestionWorker")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
]

def get_project_id():
    if os.path.exists("credentials.json"):
        try:
            with open("credentials.json", "r") as f:
                data = json.load(f)
                return data.get("installed", {}).get("project_id", "klkproject")
        except Exception:
            pass
    return "klkproject"

class LiveEmailMonitor:
    def __init__(self):
        self.project_id = get_project_id()
        self.subscription_name = f"projects/{self.project_id}/subscriptions/gmail-threat-ingestion-sub"
        self.creds = None
        self.service = None
        self.last_history_id = None
        self._init_gmail_client()

    def _init_gmail_client(self):
        if not os.path.exists("token.json"):
            logger.error("token.json not found! Run setup_personal_gmail.py first.")
            sys.exit(1)
        self.creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        self.service = build("gmail", "v1", credentials=self.creds)
        profile = self.service.users().getProfile(userId="me").execute()
        self.user_email = profile.get("emailAddress")
        self.last_history_id = profile.get("historyId")
        logger.info(f"Connected to Gmail account: {self.user_email} (Current historyId: {self.last_history_id})")

    def process_incoming_message(self, message_id: str):
        """Fetches raw message, runs EML parser, executes Gemini BEC AI, and applies safe non-destructive tags."""
        try:
            logger.info(f"⚡ [INGESTION] Fetching raw RFC 822 payload for message ID: {message_id}")
            raw_msg = self.service.users().messages().get(userId="me", id=message_id, format="raw").execute()
            raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"].encode("ASCII"))

            # 1. Parse EML
            parsed = EmlParser.parse_raw_eml(raw_bytes)
            
            # 2. Analyze SMTP Hops & GeoIP
            enriched_hops, originating_geo, _ = SMTPHopAnalyzer.analyze_chain(parsed["smtp_hops"])

            logger.info(f"📧 [INSPECTED] Subject: '{parsed['subject']}' from '{parsed['sender_header_from']}'")
            logger.info(f"🔐 [AUTH] SPF: {parsed['spf_status']} | DKIM: {parsed['dkim_status']} | DMARC: {parsed['dmarc_status']}")
            logger.info(f"🌍 [ORIGIN] IP: {originating_geo.get('ip')} ({originating_geo.get('country')}), ASN: {originating_geo.get('asn')}")

            # 3. Gemini NLP BEC Evaluation (Async run)
            nlp_eval = asyncio.run(GeminiNLPAnalyzer.analyze_email(
                subject=parsed["subject"],
                sender_header_from=parsed["sender_header_from"],
                sender_display_name=parsed["sender_display_name"],
                reply_to=parsed["reply_to"],
                recipients=parsed["recipient_to"],
                text_body=parsed["text_body"] or parsed["html_body"],
                spf_status=parsed["spf_status"],
                dkim_status=parsed["dkim_status"],
                dmarc_status=parsed["dmarc_status"]
            ))

            # 4. Composite Threat Score
            threat_score, severity = ThreatScoringEngine.calculate_score(
                spf_status=parsed["spf_status"],
                dkim_status=parsed["dkim_status"],
                dmarc_status=parsed["dmarc_status"],
                reply_to_mismatch=parsed["reply_to_mismatch"],
                originating_geo=originating_geo,
                nlp_evaluation=nlp_eval
            )

            logger.info(f"🎯 [THREAT SCORE] Score: {threat_score}/100 -> {severity} (Category: {nlp_eval.get('threat_category')})")

            # 5. Non-Destructive Remediation (Tagging [SUSPICIOUS] if Score > 80)
            if threat_score > 80:
                logger.warning(f"🚨 [THREAT DETECTED] Threat Score ({threat_score}) > Threshold (80)! Attaching [SUSPICIOUS] tag...")
                asyncio.run(RemediationActions.quarantine_and_tag(
                    provider="google_workspace",
                    user_email=self.user_email,
                    message_id=message_id
                ))
                logger.info(f"✓ [SAFEGUARD] Applied [SUSPICIOUS] label tag to message {message_id}. Email safely preserved.")
            else:
                logger.info(f"✓ [SAFE] Email classified as legitimate. Delivered normally.")

        except Exception as e:
            logger.error(f"Error processing message {message_id}: {e}")

    def poll_for_new_emails(self, interval_sec: int = 4):
        """Continuous live inbox polling monitor."""
        logger.info(f"🚀 LIVE SENTINEL ACTIVE — Monitoring '{self.user_email}' for incoming emails...")
        logger.info("Send any email to this address to watch live forensic detection in action!")
        
        seen_ids = set()
        # Prime existing recent messages so we only trigger on brand new incoming emails
        try:
            initial = self.service.users().messages().list(userId="me", maxResults=10, q="in:inbox").execute()
            for m in initial.get("messages", []):
                seen_ids.add(m["id"])
        except Exception:
            pass

        import time
        while True:
            try:
                res = self.service.users().messages().list(userId="me", maxResults=5, q="in:inbox").execute()
                messages = res.get("messages", [])
                for msg in messages:
                    msg_id = msg["id"]
                    if msg_id not in seen_ids:
                        seen_ids.add(msg_id)
                        logger.info(f"\n🔔 NEW INCOMING EMAIL DETECTED! Processing Message ID: {msg_id}")
                        self.process_incoming_message(msg_id)
            except Exception as e:
                logger.warning(f"Poll loop check: {e}")

            time.sleep(interval_sec)

if __name__ == "__main__":
    monitor = LiveEmailMonitor()
    monitor.poll_for_new_emails()
