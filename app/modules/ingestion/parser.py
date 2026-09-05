import email
from email import policy
from email.message import EmailMessage
import re
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class EmlParser:
    """Forensic parser for raw .eml RFC 822 email payloads."""

    @classmethod
    def parse_raw_eml(cls, raw_bytes: bytes) -> Dict[str, Any]:
        """Parses raw EML bytes into structured headers, body parts, auth results, and hop chain."""
        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # 1. Header Extraction
        rfc822_id = msg.get("Message-ID", "").strip("<>")
        subject = msg.get("Subject", "(No Subject)")
        header_from = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        header_to = [addr.strip() for addr in msg.get("To", "").split(",") if addr.strip()]
        header_cc = [addr.strip() for addr in msg.get("Cc", "").split(",") if addr.strip()]
        date_header = msg.get("Date", "")
        
        # Parse display name vs address
        display_name, from_email = cls._extract_display_and_email(header_from)
        _, reply_to_email = cls._extract_display_and_email(reply_to)
        
        # 2. Extract Body text and HTML
        text_body, html_body = cls._extract_bodies(msg)
        
        # 3. Parse Authentication-Results (SPF, DKIM, DMARC)
        auth_results_raw = msg.get("Authentication-Results", "")
        spf_status, dkim_status, dmarc_status = cls._parse_auth_results(auth_results_raw)
        
        # 4. Parse Received: header chain (SMTP Hops)
        received_headers = msg.get_all("Received", [])
        smtp_hops = cls._parse_received_hops(received_headers)
        
        # 5. Extract Attachments info & run Attachment Scanner (QR / PDF / OCR)
        from app.modules.intelligence.attachment_scanner import AttachmentScanner
        attachments = cls._extract_attachments(msg, html_body=html_body)
        attachment_scan = AttachmentScanner.scan_attachments(attachments)

        return {
            "rfc822_message_id": rfc822_id,
            "subject": subject,
            "sender_header_from": from_email,
            "sender_display_name": display_name,
            "reply_to": reply_to_email,
            "recipient_to": header_to,
            "recipient_cc": header_cc,
            "date_header": date_header,
            "text_body": text_body,
            "html_body": html_body,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "raw_authentication_results": auth_results_raw,
            "raw_received_headers": received_headers,
            "smtp_hops": smtp_hops,
            "attachments": attachments,
            "attachment_scan": attachment_scan,
            "reply_to_mismatch": cls._is_domain_mismatch(from_email, reply_to_email)
        }


    @staticmethod
    def _is_domain_mismatch(from_addr: str, reply_to_addr: str) -> bool:
        if not reply_to_addr or not from_addr:
            return False
        from_dom = from_addr.split("@")[-1].lower().strip()
        reply_dom = reply_to_addr.split("@")[-1].lower().strip()
        if from_dom == reply_dom:
            return False
        from_parts = from_dom.split(".")
        reply_parts = reply_dom.split(".")
        if len(from_parts) >= 2 and len(reply_parts) >= 2:
            from_root = ".".join(from_parts[-2:])
            reply_root = ".".join(reply_parts[-2:])
            if from_root == reply_root:
                return False
        return True

    @staticmethod
    def _extract_display_and_email(header_val: str) -> Tuple[str, str]:
        if not header_val:
            return "", ""
        match = re.search(r'(?:"?([^"]*)"?\s)?(?:<(.+?)>|([^\s<>]+))', header_val)
        if match:
            display = match.group(1) or ""
            addr = match.group(2) or match.group(3) or ""
            return display.strip(), addr.strip()
        return "", header_val.strip()

    @staticmethod
    def _extract_bodies(msg: EmailMessage) -> Tuple[str, str]:
        text_body = ""
        html_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if content_type == "text/plain" and not text_body:
                        text_body = decoded
                    elif content_type == "text/html" and not html_body:
                        html_body = decoded
                except Exception as e:
                    logger.warning(f"Error decoding message part: {e}")
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if msg.get_content_type() == "text/html":
                        html_body = decoded
                    else:
                        text_body = decoded
            except Exception as e:
                logger.warning(f"Error decoding singlepart body: {e}")

        return text_body, html_body

    @classmethod
    def _parse_auth_results(cls, auth_str: str) -> Tuple[str, str, str]:
        """Parses Authentication-Results header into SPF, DKIM, DMARC statuses."""
        if not auth_str:
            return "NONE", "NONE", "NONE"
        
        spf = cls._extract_auth_tag(auth_str, "spf")
        dkim = cls._extract_auth_tag(auth_str, "dkim")
        dmarc = cls._extract_auth_tag(auth_str, "dmarc")
        return spf, dkim, dmarc

    @staticmethod
    def _extract_auth_tag(header: str, tag: str) -> str:
        # Matches e.g. spf=pass, dkim=neutral, dmarc=fail
        match = re.search(rf'\b{tag}=([a-zA-Z]+)', header, re.IGNORECASE)
        if match:
            val = match.group(1).upper()
            if val in ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "PERMERROR", "TEMPERROR"]:
                return val
        return "NONE"

    @classmethod
    def _parse_received_hops(cls, received_list: List[str]) -> List[Dict[str, Any]]:
        """
        Parses Received: headers in chronological order (Origin -> Gateway).
        SMTP headers are recorded top-down (most recent first), so we reverse them for chronological trace.
        """
        hops = []
        reversed_headers = list(reversed(received_list))
        
        for idx, rec in enumerate(reversed_headers):
            from_relay = ""
            by_relay = ""
            protocol = "ESMTP"
            extracted_ip = None
            
            from_match = re.search(r'from\s+([^\s\(\);]+)', rec, re.IGNORECASE)
            if from_match:
                from_relay = from_match.group(1).strip("<>")
            
            by_match = re.search(r'by\s+([^\s\(\);]+)', rec, re.IGNORECASE)
            if by_match:
                by_relay = by_match.group(1).strip("<>")
                
            with_match = re.search(r'with\s+([^\s;]+)', rec, re.IGNORECASE)
            if with_match:
                protocol = with_match.group(1)
                
            # IPv4 extraction [x.x.x.x]
            ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', rec)
            if ip_match:
                candidate_ip = ip_match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(candidate_ip)
                    extracted_ip = str(ip_obj)
                except ValueError:
                    pass

            # IPv6 extraction [x:x:...] or plain IPv6 in by/from
            if not extracted_ip:
                ipv6_match = re.search(r'\[([0-9a-fA-F:]{4,39})\]', rec)
                if ipv6_match:
                    try:
                        ip_obj = ipaddress.ip_address(ipv6_match.group(1))
                        extracted_ip = str(ip_obj)
                    except ValueError:
                        pass

            # Check if by_relay itself is an IPv6 address (e.g. Received: by 2002:a05:...)
            is_internal_handoff = False
            if by_relay and (by_relay.startswith("2002:") or by_relay.startswith("2607:")):
                extracted_ip = by_relay
                by_relay = f"google-internal-delivery ({by_relay[:16]}...)"
                if not from_relay:
                    from_relay = "mx.google.com"
                is_internal_handoff = True
            elif not from_relay and by_relay:
                from_relay = "mx.google.com"
                is_internal_handoff = True

            hops.append({
                "hop_index": idx,
                "from_relay": from_relay or "Originating Client/MTA",
                "by_relay": by_relay or "mx.google.com",
                "protocol": protocol,
                "ip": extracted_ip or ("Internal Handoff" if is_internal_handoff else "0.0.0.0"),
                "is_private_ip": ipaddress.ip_address(extracted_ip).is_private if (extracted_ip and ":" not in extracted_ip and extracted_ip != "0.0.0.0") else False,
                "is_internal_handoff": is_internal_handoff,
                "raw_snippet": rec.strip()[:200]
            })
            
        return hops

    @classmethod
    def _extract_attachments(cls, msg: EmailMessage, html_body: str = "") -> List[Dict[str, Any]]:
        attachments = []
        import base64
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            ctype = part.get_content_type().lower()
            if filename or "attachment" in disposition or "image/" in ctype:
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = b""
                size_bytes = len(payload) if payload else 0
                b64_val = base64.b64encode(payload).decode('utf-8') if payload else ""
                attachments.append({
                    "filename": filename or f"inline_asset_{len(attachments)+1}.png",
                    "content_type": ctype,
                    "size_bytes": size_bytes,
                    "raw_bytes": payload,
                    "raw_base64": b64_val
                })

        if html_body:
            import re
            inline_matches = re.findall(r"""src=["']data:(image/[^;]+);base64,([A-Za-z0-9+/=]+)["']""", html_body)
            for i, (img_type, b64_str) in enumerate(inline_matches):
                try:
                    img_bytes = base64.b64decode(b64_str)
                    attachments.append({
                        "filename": f"inline_qr_or_image_{i+1}.png",
                        "content_type": img_type,
                        "size_bytes": len(img_bytes),
                        "raw_bytes": img_bytes,
                        "raw_base64": b64_str
                    })
                except Exception:
                    pass
        return attachments
