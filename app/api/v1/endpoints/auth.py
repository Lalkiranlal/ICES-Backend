import logging
import urllib.parse
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
import httpx
from sqlalchemy import select
from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.db.models import MonitoredMailbox, Organization, utc_now

logger = logging.getLogger(__name__)
router = APIRouter()

GOOGLE_AUTH_BASE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

def _resolve_redirect_uri(request: Request) -> str:
    """Dynamically resolves the exact HTTPS callback URI for Google OAuth."""
    if settings.GOOGLE_REDIRECT_URI and ("onrender.com" in settings.GOOGLE_REDIRECT_URI or "https://" in settings.GOOGLE_REDIRECT_URI):
        return settings.GOOGLE_REDIRECT_URI

    base = str(request.base_url).rstrip("/")
    if "onrender.com" in base or request.headers.get("x-forwarded-proto") == "https":
        base = base.replace("http://", "https://")
    return f"{base}/api/v1/auth/google/callback"


@router.get("/google/login")
async def google_login(request: Request, redirect_url: Optional[str] = None):
    """
    Initiates automated Google Workspace / Gmail OAuth 2.0 authorization.
    Redirects the user to Google's consent screen.
    """
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Google Client ID is not configured.")

    redirect_uri = _resolve_redirect_uri(request)
    target_state = redirect_url or settings.FRONTEND_URL

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": target_state
    }
    url = f"{GOOGLE_AUTH_BASE}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=url)


@router.get("/google/callback")
async def google_auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    """
    Receives authorization code from Google, exchanges for access & refresh tokens,
    persists credentials into Neon PostgreSQL database, and redirects user back to SOC dashboard.
    """
    target_redirect = state or settings.FRONTEND_URL
    sep = "&" if "?" in target_redirect else "?"

    if error:
        logger.warning(f"Google OAuth authorization error: {error}")
        return RedirectResponse(url=f"{target_redirect}{sep}auth_error={urllib.parse.quote(error)}")

    if not code:
        return RedirectResponse(url=f"{target_redirect}{sep}auth_error=missing_code")

    try:
        redirect_uri = _resolve_redirect_uri(request)

        # 1. Exchange authorization code for tokens
        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15.0
            )

            if token_resp.status_code != 200:
                logger.error(f"Failed to exchange Google OAuth code: {token_resp.text}")
                return RedirectResponse(url=f"{target_redirect}{sep}auth_error=token_exchange_failed_{token_resp.status_code}")

            token_data = token_resp.json()
            access_token = token_data.get("access_token")

            # 2. Fetch authenticated user profile
            user_info_resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0
            )
            user_info = user_info_resp.json()
            user_email = user_info.get("email", "").lower().strip()
            user_name = user_info.get("name", "Google Workspace Admin")

        if not user_email:
            return RedirectResponse(url=f"{target_redirect}{sep}auth_error=no_user_email_returned")

        # 3. Store or Update in SQL Database (Neon.tech PostgreSQL)
        async with AsyncSessionLocal() as session:
            # Check or create Organization
            domain = user_email.split("@")[-1] if "@" in user_email else "company.internal"
            org_stmt = select(Organization).where(Organization.domain == domain)
            org_res = await session.execute(org_stmt)
            org = org_res.scalar_one_or_none()

            if not org:
                org = Organization(
                    name=f"{domain.split('.')[0].capitalize()} Security",
                    domain=domain,
                    provider="google_workspace",
                    service_account_email=user_email,
                    remediation_score_threshold=settings.AUTO_REMEDIATION_THRESHOLD
                )
                session.add(org)
                await session.flush()

            # Upsert Monitored Mailbox with OAuth credentials
            mb_stmt = select(MonitoredMailbox).where(MonitoredMailbox.user_email == user_email)
            mb_res = await session.execute(mb_stmt)
            mailbox = mb_res.scalar_one_or_none()

            if mailbox:
                mailbox.sync_status = "ACTIVE"
                mailbox.oauth_credentials = token_data
                mailbox.updated_at = utc_now()
            else:
                mailbox = MonitoredMailbox(
                    org_id=org.id,
                    user_email=user_email,
                    sync_status="ACTIVE",
                    is_vip=True,
                    oauth_credentials=token_data
                )
                session.add(mailbox)

            await session.commit()
            logger.info(f"Successfully authenticated and registered mailbox '{user_email}' into SQL database.")

        return RedirectResponse(url=f"{target_redirect}{sep}auth=success&email={urllib.parse.quote(user_email)}")

    except Exception as e:
        logger.error(f"Error handling Google OAuth callback: {e}", exc_info=True)
        return RedirectResponse(url=f"{target_redirect}{sep}auth_error={urllib.parse.quote(str(e))}")
