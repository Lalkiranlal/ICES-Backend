#!/usr/bin/env python3
"""
Gmail Ingestion Watcher & Integration Script
===========================================
This script registers a mailbox with Google Cloud Pub/Sub using Gmail API `users.watch`.
Once registered, Gmail pushes notifications for every incoming message directly to your ICES backend.

Usage:
  python setup_gmail_watch.py --user-email user@yourdomain.com --topic-name projects/YOUR_GCP_PROJECT/topics/gmail-threat-ingestion
"""

import argparse
import json
import os
import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
]

def setup_watch(service_account_path: str, user_email: str, topic_name: str):
    print(f"[*] Authenticating for mailbox: {user_email}")
    
    if not os.path.exists(service_account_path):
        print(f"[!] Error: Service account JSON not found at {service_account_path}")
        sys.exit(1)

    with open(service_account_path, "r") as f:
        sa_info = json.load(f)

    # Domain-Wide Delegation credentials
    credentials = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=SCOPES
    ).with_subject(user_email)

    service = build("gmail", "v1", credentials=credentials)

    print(f"[*] Registering Gmail API push watch on topic: {topic_name}")
    request_body = {
        "topicName": topic_name,
        "labelIds": ["INBOX"] # Listen for incoming messages to the inbox
    }

    try:
        response = service.users().watch(userId=user_email, body=request_body).execute()
        print("\n[✓] SUCCESS: Gmail Push Notifications successfully established!")
        print(f"    - Starting historyId : {response.get('historyId')}")
        print(f"    - Watch Expiration   : {response.get('expiration')} (Renew every 7 days)")
        print("\nEvery incoming email will now trigger your ICES backend webhook for automated analysis and remediation.")
    except Exception as e:
        print(f"\n[!] Failed to setup Gmail watch: {e}")
        print("\nTroubleshooting Checklist:")
        print("  1. Have you granted 'gmail-api-push@system.gserviceaccount.com' the 'Pub/Sub Publisher' role on your topic?")
        print("  2. Did you enable Domain-Wide Delegation in Google Workspace Admin Console for your Service Account Client ID?")
        print("  3. Are the required OAuth scopes added to the Admin Console?")
        sys.exit(1)

def stop_watch(service_account_path: str, user_email: str):
    print(f"[*] Stopping Gmail API push watch for mailbox: {user_email}")
    with open(service_account_path, "r") as f:
        sa_info = json.load(f)

    credentials = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=SCOPES
    ).with_subject(user_email)

    service = build("gmail", "v1", credentials=credentials)
    service.users().stop(userId=user_email).execute()
    print("[✓] Gmail push watch stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICES Gmail Watch Setup")
    parser.add_argument("--sa-json", default="service_account.json", help="Path to GCP Service Account JSON key")
    parser.add_argument("--user-email", required=True, help="Gmail / Google Workspace email address to monitor")
    parser.add_argument("--topic-name", default="projects/ices-threat-intelligence/topics/gmail-threat-ingestion", help="Full GCP Pub/Sub Topic name")
    parser.add_argument("--stop", action="store_true", help="Stop watching mailbox")

    args = parser.parse_args()

    if args.stop:
        stop_watch(args.sa_json, args.user_email)
    else:
        setup_watch(args.sa_json, args.user_email, args.topic_name)
