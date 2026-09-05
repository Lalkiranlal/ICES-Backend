#!/usr/bin/env python3
"""
Personal Gmail OAuth2 Quickstart Setup
======================================
Auto-detects project_id from credentials.json and uses existing token.json if present.
"""

import argparse
import os
import json
import sys
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
]

def load_or_generate_creds(credentials_file: str, token_output: str) -> Credentials:
    creds = None
    if os.path.exists(token_output):
        try:
            creds = Credentials.from_authorized_user_file(token_output, SCOPES)
            if creds and creds.valid:
                print(f"[✓] Reusing existing valid credentials from {token_output}")
                return creds
        except Exception as e:
            print(f"[*] token.json not reusable: {e}")

    if not os.path.exists(credentials_file):
        print(f"[!] Error: OAuth credentials file '{credentials_file}' not found.")
        sys.exit(1)

    print("[*] Launching browser for one-time Google Account authorization...")
    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
    creds = flow.run_local_server(port=0)

    with open(token_output, "w") as token_file:
        token_file.write(creds.to_json())
    print(f"[✓] Saved user OAuth token to {token_output}")
    return creds

def get_project_id_from_credentials(credentials_file: str) -> str:
    if os.path.exists(credentials_file):
        try:
            with open(credentials_file, "r") as f:
                data = json.load(f)
                client_info = data.get("installed") or data.get("web") or {}
                return client_info.get("project_id", "klkproject")
        except Exception:
            pass
    return "klkproject"

def authenticate_and_watch(credentials_file: str, token_output: str, topic_name: str):
    creds = load_or_generate_creds(credentials_file, token_output)
    service = build("gmail", "v1", credentials=creds)

    project_id = get_project_id_from_credentials(credentials_file)

    # Sanitize topic name
    if not topic_name or "apps.googleusercontent.com" in topic_name:
        topic_name = f"projects/{project_id}/topics/gmail-threat-ingestion"

    print(f"[*] Target GCP Project : {project_id}")
    print(f"[*] Target Pub/Sub Topic: {topic_name}")

    try:
        profile = service.users().getProfile(userId="me").execute()
        email_address = profile.get("emailAddress")
        print(f"[*] Authenticated User : {email_address}")

        print(f"[*] Registering push watch on topic '{topic_name}'...")
        request_body = {
            "topicName": topic_name,
            "labelIds": ["INBOX"]
        }
        res = service.users().watch(userId="me", body=request_body).execute()

        print("\n" + "="*65)
        print("  🎉 SUCCESS: Connected to Personal Gmail!")
        print("="*65)
        print(f"  • Monitored Account  : {email_address}")
        print(f"  • Starting historyId : {res.get('historyId')}")
        print(f"  • Watch Expiration   : {res.get('expiration')} (Unix timestamp)")
        print("="*65)
        print("\nEvery incoming email will now push events to your ICES backend.")

    except HttpError as e:
        err_str = str(e)
        if "Gmail API has not been used" in err_str or "accessNotConfigured" in err_str:
            print("\n" + "!"*65)
            print("  ⚠️ GMAIL API IS DISABLED IN YOUR GCP PROJECT")
            print("!"*65)
            print(f"\nPlease enable the Gmail API by clicking this link:\n👉 https://console.developers.google.com/apis/api/gmail.googleapis.com/overview?project={project_id}\n")
            print("Click the blue 'ENABLE' button, wait 10 seconds, and run this script again.")
            print("!"*65)
        elif "User not authorized" in err_str or "Permission denied" in err_str or "403" in err_str:
            print("\n" + "!"*65)
            print("  ⚠️ PUB/SUB TOPIC PERMISSION MISSING")
            print("!"*65)
            print(f"1. Make sure topic '{topic_name}' exists in GCP Console.")
            print("2. In Pub/Sub > Topics > Permissions, add principal:")
            print("   'gmail-api-push@system.gserviceaccount.com' with role 'Pub/Sub Publisher'.")
            print("!"*65)
        else:
            print(f"\n[!] Gmail API Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Personal Gmail ICES Integration Setup")
    parser.add_argument("--credentials", default="credentials.json", help="Path to credentials.json")
    parser.add_argument("--token-output", default="token.json", help="Path to token.json")
    parser.add_argument("--topic-name", default="", help="Full GCP Pub/Sub Topic name")
    args = parser.parse_args()
    
    authenticate_and_watch(args.credentials, args.token_output, args.topic_name)
