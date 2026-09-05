import logging
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class WarningBannerEngine:
    """Generates responsive, high-contrast, executive-styled HTML warning banners for mailbox injection."""

    @classmethod
    def generate_banner_metadata(
        cls,
        threat_score: int,
        severity: str = "LOW",
        sender_email: str = "",
        display_name: str = "",
        nlp_summary: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """Generates warning banner metadata dictionary."""
        return cls.generate_banner_html(
            threat_score=threat_score,
            threat_category=severity,
            vip_details=kwargs.get("vip_details"),
            quishing_url=kwargs.get("quishing_url"),
            action_callback_url=kwargs.get("action_callback_url")
        )

    @classmethod
    def generate_banner_html(
        cls,
        threat_score: int,
        threat_category: str,
        vip_details: Optional[Dict[str, Any]] = None,
        quishing_url: Optional[str] = None,
        action_callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds the banner metadata and HTML markup to prepend at the top of an email.
        """
        callback_url = action_callback_url or settings.REPORT_CALLBACK_URL

        if threat_score >= 80 or (vip_details and vip_details.get("is_impersonation_threat")):
            banner_type = "CRITICAL_RED"
            title = "⚠️ CRITICAL SECURITY WARNING: Impersonation & High-Risk Request"
            
            if vip_details and vip_details.get("display_name_spoofing"):
                vip_name = vip_details.get("impersonated_vip", {}).get("name", "Executive")
                body_msg = f"This sender is pretending to be <strong>{vip_name}</strong> from an unverified external address. Do NOT wire money, provide gift cards, or share credentials."
            elif quishing_url:
                body_msg = "This email contains an embedded <strong>QR Code (Quishing)</strong> linking to an external authentication page. Do NOT scan with your mobile device."
            else:
                body_msg = "CloudNet AI detected high-confidence wire fraud or social engineering in this payload. Do NOT reply or click attachments."

            bg_color = "#1f090d"
            border_color = "#ef4444"
            text_color = "#fca5a5"
            accent_color = "#ef4444"
            badge_text = "AUTO-QUARANTINED"
            badge_bg = "rgba(239, 68, 68, 0.2)"

        elif threat_score >= 40:
            banner_type = "CAUTION_YELLOW"
            title = "⚠️ CAUTION: External Sender / Unverified Invoice Request"
            body_msg = "You do not frequently communicate with this external sender. Verify any invoice or banking coordinate changes directly via a trusted phone number."
            bg_color = "#1a1306"
            border_color = "#f59e0b"
            text_color = "#fde68a"
            accent_color = "#f59e0b"
            badge_text = "SUSPICIOUS EXTERNAL"
            badge_bg = "rgba(245, 158, 11, 0.2)"

        else:
            banner_type = "VERIFIED_GREEN"
            title = "✓ Authenticated Organization Stream"
            body_msg = "Cryptographic signatures (SPF, DKIM, DMARC) verified and sender reputation passed all security policies."
            bg_color = "#07170e"
            border_color = "#10b981"
            text_color = "#a7f3d0"
            accent_color = "#10b981"
            badge_text = "VERIFIED SAFE"
            badge_bg = "rgba(16, 185, 129, 0.2)"

        html_markup = f"""<!-- CLOUDNET ICES SECURITY INJECTION -->
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: {bg_color}; border: 1.5px solid {border_color}; border-radius: 8px; padding: 12px 16px; margin: 12px 0 20px 0; color: #ffffff; line-height: 1.4;">
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
    <div style="font-weight: 700; font-size: 13px; color: {accent_color}; letter-spacing: -0.01em;">
      {title}
    </div>
    <div style="background-color: {badge_bg}; color: {accent_color}; border: 1px solid {border_color}; border-radius: 9999px; padding: 2px 8px; font-size: 10px; font-weight: 700; text-transform: uppercase;">
      {badge_text}
    </div>
  </div>
  <div style="font-size: 12px; color: {text_color}; margin-bottom: 8px;">
    {body_msg}
  </div>
  <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 6px; display: flex; align-items: center; justify-content: space-between; font-size: 10px; color: #94a3b8;">
    <span>Protected by <strong>CloudNet ICES Zero-Trust Gateway</strong></span>
    <a href="{callback_url}" target="_blank" style="background-color: {accent_color}; color: #000000; font-weight: 700; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 11px; display: inline-block;">
      Report Phish to SOC
    </a>
  </div>
</div>
"""

        return {
            "banner_type": banner_type,
            "title": title,
            "body_message": body_msg,
            "badge_text": badge_text,
            "accent_color": accent_color,
            "html_markup": html_markup
        }
