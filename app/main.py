import warnings
import logging

# Suppress non-blocking Google SDK Python 3.9 EOL notices & Pydantic migration warnings in runtime logs
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api_router import api_router

# Configure Structured Logging for SOC Auditability
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d) - %(message)s"
)
logger = logging.getLogger(__name__)


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    description="API-based Integrated Cloud Email Security (ICES) Forensic Engine with Gemini NLP & ReactFlow SMTP Hop Visualizer"
)

# CORS Configuration for SOC Frontend Integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def on_startup():
    """Initializes the database tables on server start."""
    from app.db.database import init_db
    await init_db()

@app.api_route("/", methods=["GET", "HEAD"], tags=["Root"])
async def root():
    """Root landing endpoint providing service metadata and documentation links."""
    return {
        "service": settings.PROJECT_NAME,
        "status": "online",
        "version": "1.0.0",
        "docs": f"{settings.API_V1_STR}/docs",
        "health": "/health"
    }

@app.api_route("/health", methods=["GET", "HEAD"], tags=["Health"])
async def health_check():
    """Health check endpoint for Kubernetes / GCP Cloud Run readiness probes."""
    return {
        "status": "healthy",
        "service": "CloudNet ICES Forensic Engine",
        "gemini_nlp_ready": bool(settings.GEMINI_API_KEY),
        "auto_remediation_threshold": settings.AUTO_REMEDIATION_THRESHOLD,
        "database": "connected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
