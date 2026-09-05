#!/usr/bin/env python3
"""
Live Gmail Email Inspector & Forensic Tester
===========================================
Fetches recent emails from your connected Gmail account, parses raw headers & bodies,
traces SMTP relay hops with GeoIP, and runs threat scoring.

Usage:
  ./venv/bin/python3 scripts/fetch_live_gmail.py
"""

import os
import sys
import json
import base64
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Add parent directory to path for backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.modules.ingestion.parser import EmlParser
from app.modules.intelligence.hop_analyzer import SMTPHopAnalyzer
from app.modules.intelligence.scoring import ThreatScoringEngine
from app.modules.intelligence.gemini_nlp import GeminiNLPAnalyzer

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
]

def inspect_recent_emails(max_count: int = 5):
    token_path = "token.json"
    if not os.path.exists(token_path):
        print(f"[!] Error: {token_path} not found. Run setup_personal_gmail.py first.")
        return

    creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    service = build("gmail", "v1", credentials=creds)

    print("\n" + "="*70)
    print("  📬 FETCHING LATEST MESSAGES FROM GMAIL INBOX")
    print("="*70)

    # 1. Fetch latest messages list
    results = service.users().messages().list(userId="me", maxResults=max_count, q="in:inbox").execute()
    messages = results.get("messages", [])

    if not messages:
        print("[*] No messages found in INBOX.")
        return

    print(f"[*] Found {len(messages)} recent emails. Analyzing forensic headers...\n")

    for idx, msg_meta in enumerate(messages):
        msg_id = msg_meta["id"]
        
        # 2. Fetch raw RFC 822 .eml payload
        raw_msg = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
        raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"].encode("ASCII"))

        # 3. Run ICES Forensic Parser
        parsed = EmlParser.parse_raw_eml(raw_bytes)
        enriched_hops, originating_geo, _ = SMTPHopAnalyzer.analyze_chain(parsed["smtp_hops"])

        print(f"{'─'*70}")
        print(f"📧 EMAIL #{idx+1} [ID: {msg_id}]")
        print(f"  • Subject       : {parsed['subject']}")
        print(f"  • From          : {parsed['sender_display_name']} <{parsed['sender_header_from']}>")
        print(f"  • Reply-To      : {parsed['reply_to'] or 'Same as From'}")
        print(f"  • To            : {', '.join(parsed['recipient_to'])}")
        print(f"  • Date          : {parsed['date_header']}")
        
        print("\n  🔐 Cryptographic Authentication:")
        print(f"    - SPF   : {parsed['spf_status']}")
        print(f"    - DKIM  : {parsed['dkim_status']}")
        print(f"    - DMARC : {parsed['dmarc_status']}")
        
        print("\n  🌍 Originating Telemetry & GeoIP:")
        print(f"    - Origin IP   : {originating_geo.get('ip')}")
        print(f"    - Location    : {originating_geo.get('city')}, {originating_geo.get('country_name')}")
        print(f"    - ASN / Org   : {originating_geo.get('asn')}")
        print(f"    - Tor/VPN Node: {originating_geo.get('is_tor_or_vpn')}")

        print(f"\n  🛰️ SMTP Relay Chain ({len(enriched_hops)} Hops Detected):")
        for hop in enriched_hops:
            susp_flag = " ⚠️ [SUSPICIOUS]" if hop['is_suspicious'] else ""
            print(f"    Hop #{hop['hop_index']+1}: {hop['from_relay']} -> {hop['by_relay']} (IP: {hop['ip']}, +{hop['delay_ms']}ms){susp_flag}")

        # Quick Heuristic Threat Assessment
        is_suspicious = (
            parsed['spf_status'] == 'FAIL' or
            parsed['dmarc_status'] == 'FAIL' or
            parsed['reply_to_mismatch'] or
            originating_geo.get('is_tor_or_vpn')
        )
        score = 85 if is_suspicious else 5
        print(f"\n  🎯 Threat Score Assessment: {score}/100 ({'HIGH RISK' if score > 80 else 'CLEAN'})")
        print(f"{'─'*70}\n")

if __name__ == "__main__":
    inspect_recent_emails()
