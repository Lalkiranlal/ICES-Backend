import base64
import json
import logging
from typing import Dict, Any, Optional, List
import os
try:
    from google.oauth2.credentials import Credentials
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError:
    Credentials = None
    service_account = None
    build = None
from app.core.config import settings

logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels"
]

class GmailClient:
    """Client for Google Workspace and Personal Gmail API integration."""

    def __init__(self, delegated_user: Optional[str] = None):
        self.delegated_user = delegated_user or settings.GOOGLE_ADMIN_DELEGATED_USER
        self._service = None

    def _get_service(self, user_email: str, credentials_dict: Optional[Dict[str, Any]] = None):
        """
        Initializes Gmail API service:
        1. Checks for explicitly passed credentials_dict (from DB OAuth tokens)
        2. Checks for personal account token.json
        3. Checks for Google Workspace Service Account JSON (Domain-Wide Delegation)
        4. Falls back to mock simulation mode
        """
        if credentials_dict:
            try:
                creds = Credentials(
                    token=credentials_dict.get("access_token"),
                    refresh_token=credentials_dict.get("refresh_token"),
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=settings.GOOGLE_CLIENT_ID,
                    client_secret=settings.GOOGLE_CLIENT_SECRET,
                    scopes=SCOPES
                )
                return build("gmail", "v1", credentials=creds, cache_discovery=False)
            except Exception as e:
                logger.error(f"Failed to build Gmail service from DB credentials: {e}")

        # Check for personal account token.json
        if os.path.exists("token.json"):
            try:
                creds = Credentials.from_authorized_user_file("token.json", SCOPES)
                return build("gmail", "v1", credentials=creds, cache_discovery=False)
            except Exception as e:
                logger.warning(f"Failed to load token.json: {e}")

        # Check for Google Workspace Service Account JSON
        if settings.GOOGLE_SERVICE_ACCOUNT_JSON:
            try:
                service_account_info = json.loads(settings.GOOGLE_SERVICE_ACCOUNT_JSON)
                credentials = service_account.Credentials.from_service_account_info(
                    service_account_info,
                    scopes=SCOPES
                ).with_subject(user_email)
                return build("gmail", "v1", credentials=credentials, cache_discovery=False)
            except Exception as e:
                logger.error(f"Failed to authenticate with Service Account for {user_email}: {e}")

        logger.warning("No Gmail credentials found (DB tokens, token.json, or service_account.json). Running in simulation mode.")
        return None

    def fetch_raw_message(self, user_email: str, message_id: str) -> Optional[bytes]:
        """
        Fetches the raw RFC 822 .eml byte payload for a given message ID.
        """
        service = self._get_service(user_email)
        if not service:
            logger.info(f"[SIMULATION] Mocking raw .eml fetch for {user_email}:{message_id}")
            return None
        
        try:
            msg_obj = service.users().messages().get(
                userId=user_email,
                id=message_id,
                format="raw"
            ).execute()
            
            raw_b64 = msg_obj.get("raw", "")
            raw_bytes = base64.urlsafe_b64decode(raw_b64.encode("ASCII"))
            return raw_bytes
        except Exception as e:
            logger.error(f"Error fetching raw message {message_id} for {user_email}: {e}")
            raise e

    def apply_remediation_labels(
        self,
        user_email: str,
        message_id: str,
        add_labels: List[str],
        remove_labels: List[str]
    ) -> Dict[str, Any]:
        """
        Modifies Gmail labels to isolate/quarantine threats (e.g. remove INBOX, add [SUSPICIOUS]).
        """
        service = self._get_service(user_email)
        if not service:
            logger.info(f"[SIMULATION] Mocking label remediation on {message_id}: Add {add_labels}, Remove {remove_labels}")
            return {"status": "mock_remediated", "message_id": message_id, "add": add_labels, "remove": remove_labels}

        uid = "me" if os.path.exists("token.json") else user_email
        try:
            # Resolve actual Google label IDs for both add and remove lists
            label_ids_to_add = self._resolve_label_ids(service, uid, add_labels, create_if_missing=True)
            label_ids_to_remove = self._resolve_label_ids(service, uid, remove_labels, create_if_missing=False)
            
            body = {
                "addLabelIds": label_ids_to_add,
                "removeLabelIds": label_ids_to_remove
            }
            result = service.users().messages().modify(
                userId=uid,
                id=message_id,
                body=body
            ).execute()
            logger.info(f"Successfully remediated message {message_id} in mailbox {user_email}")
            return result
        except Exception as e:
            logger.error(f"Failed to modify message labels {message_id}: {e}")
            return {"status": "local_override_only", "detail": str(e)}

    def _resolve_label_ids(self, service, user_email: str, label_names: List[str], create_if_missing: bool = True) -> List[str]:
        label_ids = []
        uid = "me" if os.path.exists("token.json") else user_email
        system_labels = {"INBOX": "INBOX", "UNREAD": "UNREAD", "SPAM": "SPAM", "TRASH": "TRASH", "STARRED": "STARRED", "IMPORTANT": "IMPORTANT"}

        try:
            existing = service.users().labels().list(userId=uid).execute().get("labels", [])
            name_to_id = {lbl["name"].upper(): lbl["id"] for lbl in existing}
            
            for name in label_names:
                name_upper = name.upper()
                if name_upper in system_labels:
                    label_ids.append(system_labels[name_upper])
                elif name_upper in name_to_id:
                    label_ids.append(name_to_id[name_upper])
                elif create_if_missing:
                    try:
                        new_lbl = service.users().labels().create(
                            userId=uid,
                            body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
                        ).execute()
                        label_ids.append(new_lbl["id"])
                        name_to_id[name_upper] = new_lbl["id"]
                    except Exception as ce:
                        logger.warning(f"Label creation notice: {ce}")
        except Exception as e:
            logger.warning(f"Error resolving labels: {e}")
        return label_ids

    def send_quarantine_notice(
        self,
        recipient_email: str,
        sender_email: str,
        original_subject: str,
        threat_score: int,
        category: str
    ) -> bool:
        """Sends an automated security incident notice to the recipient."""
        service = self._get_service(recipient_email)
        if not service:
            logger.info(f"[SIMULATION] Quarantine alert notice logged for {recipient_email}: Threat from {sender_email}")
            return True

        uid = "me" if os.path.exists("token.json") else recipient_email
        try:
            from email.message import EmailMessage
            msg = EmailMessage()
            msg["Subject"] = f"🛡️ Security Notice: Suspicious Email Quarantined"
            msg["From"] = "security-alerts@cloudnet.io"
            msg["To"] = recipient_email
            msg.set_content(f"""Hello,

CloudNet Integrated Cloud Email Security (ICES) has automatically quarantined a high-risk email sent to your inbox:

• Sender: {sender_email}
• Subject: {original_subject}
• Threat Classification: {category}
• Threat Risk Score: {threat_score}/100

Action Taken: The email was tagged [SUSPICIOUS] and secured to protect against potential phishing or financial compromise.

If you believe this message is legitimate, contact your SOC administrator or request release from the CloudNet Portal.

— CloudNet ICES Automated Defense Engine
""")
            raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
            service.users().messages().send(userId=uid, body={"raw": raw_b64}).execute()
            logger.info(f"Dispatched quarantine notification notice to {recipient_email}")
            return True
        except Exception as e:
            logger.warning(f"Notice dispatch notice: {e}")
            return False

    def send_admin_enforcement_alert(
        self,
        target_user: str,
        sender_email: str,
        subject: str,
        threat_score: int,
        category: str,
        admin_email: Optional[str] = None,
        action: str = "ENFORCE_QUARANTINE",
        reason: str = "Automated / Manual SOC Policy Enforcement"
    ) -> bool:
        """Dispatches real-time SOC incident briefing email to the registered Organization Admin or security distribution."""
        destination_admin = admin_email or settings.SECURITY_ADMIN_EMAIL or target_user
        if not destination_admin:
            return False

        service = self._get_service(destination_admin)
        if not service:
            logger.info(f"[SIMULATION] Admin alert logged for {destination_admin}: {action} on {target_user}")
            return True

        uid = "me" if os.path.exists("token.json") else destination_admin
        try:
            from email.message import EmailMessage
            from datetime import datetime, timezone
            msg = EmailMessage()
            msg["Subject"] = f"🚨 [SOC ALERT] {action}: {category} in {target_user}"
            msg["From"] = "security-alerts@cloudnet.io"
            msg["To"] = destination_admin
            msg.set_content(f"""CloudNet ICES — Security Incident Alert

An enforcement action was executed on an incoming message.

INCIDENT DETAILS:
• Target User Mailbox: {target_user}
• Remediation Action: {action}
• Composite Threat Score: {threat_score}/100
• Threat Category: {category}
• Sender Address: {sender_email}
• Subject Line: {subject}
• Policy Reason: {reason}
• Execution Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

CONTAINMENT STATUS:
The suspicious email has been isolated with the [SUSPICIOUS] label in the user's mailbox.

Review and audit full telemetry at the SOC Console: {settings.FRONTEND_URL}

— CloudNet ICES Real-Time Threat Intelligence
""")
            raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
            service.users().messages().send(userId=uid, body={"raw": raw_b64}).execute()
            logger.info(f"Dispatched admin security alert to {destination_admin}")
            return True
        except Exception as e:
            logger.warning(f"Admin alert dispatch notice: {e}")
            return False


    @staticmethod
    def decode_pubsub_payload(message_data_b64: str) -> Dict[str, Any]:
        """Decodes Google Cloud Pub/Sub push notification payload."""
        try:
            decoded_bytes = base64.b64decode(message_data_b64)
            data_dict = json.loads(decoded_bytes.decode("utf-8"))
            return {
                "email_address": data_dict.get("emailAddress"),
                "history_id": str(data_dict.get("historyId"))
            }
        except Exception as e:
            logger.error(f"Error decoding Pub/Sub payload: {e}")
            raise ValueError(f"Invalid Pub/Sub base64 payload: {e}")
