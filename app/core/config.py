import os
from typing import List, Optional
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic_settings import BaseSettings
    SettingsConfigDict = dict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="allow"
    )

    PROJECT_NAME: str = "CloudNet ICES Forensic Engine"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "*",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "https://*.vercel.app",
        "https://*.onrender.com"
    ]
    
    # Supabase Connection
    SUPABASE_URL: str = "https://placeholder-project.supabase.co"
    SUPABASE_SERVICE_ROLE_KEY: str = "placeholder-key"
    
    # Google Workspace / PubSub & OAuth
    GCP_PROJECT_ID: str = "ices-threat-intelligence"
    GCP_PUBSUB_VERIFICATION_TOKEN: str = "dev-pubsub-token-secret-9948"
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: str = "https://ices-backend.onrender.com/api/v1/auth/google/callback"
    GOOGLE_SERVICE_ACCOUNT_JSON: Optional[str] = None
    GOOGLE_ADMIN_DELEGATED_USER: Optional[str] = "admin@company.com"
    
    # Gemini AI
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL_NAME: str = "gemini-3.5-flash-lite"
    
    # MaxMind GeoIP / IP Intelligence
    MAXMIND_GEOIP_DB_PATH: Optional[str] = None
    
    # Remediation Policy Defaults (Non-Destructive Safety by Design)
    AUTO_REMEDIATION_THRESHOLD: int = 80
    SUSPICIOUS_TAG_LABEL_NAME: str = "[SUSPICIOUS]"
    ENABLE_PERMANENT_DELETE: bool = False # ALWAYS False: Never permanently delete emails
    PRESERVE_IN_INBOX_WITH_LABEL: bool = True # If true, keeps mail in inbox with [SUSPICIOUS] tag without evicting
    NOTIFY_USER_ON_QUARANTINE: bool = True
    SECURITY_ADMIN_EMAIL: str = "security-admin@company.com"
    FRONTEND_URL: str = "http://localhost:3000"
    REPORT_CALLBACK_URL: str = os.getenv("REPORT_CALLBACK_URL") or (os.getenv("RENDER_EXTERNAL_URL", "https://ices-backend.onrender.com") + "/api/v1/remediation/report-phish")
    
    # Database (Self-Hosted SQL: SQLite by default, PostgreSQL for production)
    DATABASE_URL: str = "sqlite+aiosqlite:///./ices.db"

settings = Settings()



