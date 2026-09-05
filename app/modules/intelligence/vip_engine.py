import re
import unicodedata
from typing import Dict, Any, List, Optional, Tuple
from app.modules.config.dynamic_config import DynamicConfigManager

# Common homoglyph mapping (Cyrillic, Greek, lookalike Latin digits/chars)

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '@': 'a', '$': 's', 'vv': 'w',
    # Cyrillic lookalikes
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ν': 'v'
}

# Default monitored internal executive directory
DEFAULT_VIP_DIRECTORY = [
    {
        "name": "Alex Mercer",
        "title": "Chief Executive Officer (CEO)",
        "official_email": "alex.mercer@cloudnet.io",
        "monitored_domains": ["cloudnet.io", "cloudnetsecurity.com"],
        "aliases": ["alex", "amercer", "ceo", "chief executive"]
    },
    {
        "name": "Sarah Jenkins",
        "title": "Chief Financial Officer (CFO)",
        "official_email": "sarah.jenkins@cloudnet.io",
        "monitored_domains": ["cloudnet.io", "cloudnetsecurity.com"],
        "aliases": ["sarah", "sjenkins", "cfo", "finance director"]
    },
    {
        "name": "David Miller",
        "title": "VP of Human Resources & Payroll",
        "official_email": "david.miller@cloudnet.io",
        "monitored_domains": ["cloudnet.io", "cloudnetsecurity.com"],
        "aliases": ["david", "dmiller", "payroll", "hr director"]
    }
]

class VipImpersonationEngine:
    """Detects executive display name spoofing, typo-squatting, and homoglyph lookalike domains."""

    @classmethod
    def evaluate_vip_threat(cls, sender_display_name: str, sender_email: str = "", sender_envelope: str = "", reply_to: str = "", custom_vips = None, **kwargs):
        return cls.analyze(sender_display_name=sender_display_name, sender_header_from=sender_email or sender_envelope, reply_to=reply_to, custom_vips=custom_vips)


    @classmethod
    def analyze(
        cls,
        sender_display_name: str,
        sender_header_from: str,
        reply_to: str,
        custom_vips: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates sender identity against the VIP directory and corporate root domains.
        """
        vip_list = custom_vips or DynamicConfigManager.get_vip_directory() or DEFAULT_VIP_DIRECTORY

        sender_email = sender_header_from.lower().strip()
        reply_email = reply_to.lower().strip() if reply_to else sender_email
        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
        display_clean = sender_display_name.lower().strip()

        matched_vip = None
        is_display_spoofing = False
        is_lookalike_domain = False
        lookalike_details = {}
        spoofing_technique = "NONE"

        # 1. Check for Display Name Impersonation against VIPs
        for vip in vip_list:
            vip_name_clean = vip.get("name", "").lower()
            official_email = (vip.get("corporate_email") or vip.get("official_email") or "").lower().strip()
            personal_emails = [pe.lower().strip() for pe in vip.get("personal_emails", [])]
            valid_emails = [official_email] + personal_emails
            
            # Check if display name mentions the full VIP name or alias or role title
            name_matched = False
            if display_clean:
                if vip_name_clean and (vip_name_clean in display_clean or display_clean in vip_name_clean):
                    name_matched = True
                elif any(alias.lower() in display_clean for alias in vip.get("aliases", [])):
                    name_matched = True
                elif vip_name_clean:
                    tokens = [t for t in vip_name_clean.split() if len(t) > 2]
                    if tokens and all(t in display_clean for t in tokens):
                        name_matched = True

            if name_matched:
                matched_vip = vip
                # Check if the actual sender email is DIFFERENT from approved email
                if sender_email not in valid_emails:
                    is_display_spoofing = True
                    spoofing_technique = "DISPLAY_NAME_SPOOFING_FREE_WEBMAIL"
                break


        # 2. Check for Lookalike / Homoglyph Domains against protected corporate domains
        protected_domains = set()
        for vip in vip_list:
            for d in vip.get("monitored_domains", []):
                protected_domains.add(d.lower())
            corp = (vip.get("corporate_email") or vip.get("official_email") or "").lower().strip()
            if "@" in corp:
                protected_domains.add(corp.split("@")[-1])
        try:
            for td in DynamicConfigManager.get_trusted_domains():
                if td.get("domain"):
                    protected_domains.add(td["domain"].lower())
        except Exception:
            pass
        protected_domains.add("cloudnet.io")
        protected_domains.add("cloudnetsecurity.com")

        if sender_domain:
            for target_domain in protected_domains:
                if sender_domain != target_domain:
                    similarity, matched_homoglyph = cls._check_domain_similarity(sender_domain, target_domain)
                    if similarity >= 0.75 or matched_homoglyph:
                        is_lookalike_domain = True
                        lookalike_details = {
                            "sender_domain": sender_domain,
                            "target_domain": target_domain,
                            "similarity_score": round(similarity, 2),
                            "homoglyph_detected": matched_homoglyph,
                            "technique": "HOMOGLYPH_TYPOSQUATTING" if matched_homoglyph else "TYPOSQUATTED_LOOKALIKE"
                        }
                        if not is_display_spoofing:
                            spoofing_technique = lookalike_details["technique"]
                        break

        is_impersonation_threat = is_display_spoofing or is_lookalike_domain

        return {
            "is_impersonation_threat": is_impersonation_threat,
            "display_name_spoofing": is_display_spoofing,
            "lookalike_domain_detected": is_lookalike_domain,
            "spoofing_technique": spoofing_technique,
            "impersonated_vip": {
                "name": matched_vip.get("name", ""),
                "title": matched_vip.get("title", ""),
                "official_email": matched_vip.get("official_email") or matched_vip.get("corporate_email", "")
            } if matched_vip and is_display_spoofing else None,
            "lookalike_details": lookalike_details if is_lookalike_domain else None,
            "recommendation_risk_score": 95 if (is_display_spoofing and is_lookalike_domain) else (85 if is_impersonation_threat else 0)
        }


    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Replaces known Cyrillic/Greek/numeric lookalike characters with standard Latin equivalents."""
        result = []
        for char in text:
            # Check normalized NFKD form
            nfkd = unicodedata.normalize('NFKD', char)
            nfkd_char = nfkd[0] if nfkd else char
            if char in HOMOGLYPH_MAP:
                result.append(HOMOGLYPH_MAP[char])
            elif nfkd_char in HOMOGLYPH_MAP:
                result.append(HOMOGLYPH_MAP[nfkd_char])
            else:
                result.append(nfkd_char)
        return "".join(result).lower()

    @classmethod
    def _check_domain_similarity(cls, domain1: str, domain2: str) -> Tuple[float, bool]:
        """Calculates edit distance and checks if domain1 is a homoglyph of domain2."""
        # Strip TLD for core name comparison
        name1 = domain1.split('.')[0]
        name2 = domain2.split('.')[0]

        norm1 = cls._normalize_homoglyphs(name1)
        norm2 = cls._normalize_homoglyphs(name2)

        homoglyph_match = (norm1 == norm2 and name1 != name2)

        # Levenshtein distance
        dist = cls._levenshtein_distance(norm1, norm2)
        max_len = max(len(norm1), len(norm2), 1)
        similarity = 1.0 - (dist / max_len)

        return similarity, homoglyph_match

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return VipImpersonationEngine._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]
