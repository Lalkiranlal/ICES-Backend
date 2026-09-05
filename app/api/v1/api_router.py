from fastapi import APIRouter
from app.api.v1.endpoints import webhooks, forensics, remediation, alerts, admin, super_admin, auth

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Automated OAuth Authentication"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Ingestion Webhooks"])
api_router.include_router(forensics.router, prefix="/forensics", tags=["Forensics & Header Analysis"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation Engine"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["SOC Alerts & Metrics"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin & User Directory"])
api_router.include_router(super_admin.router, prefix="/super-admin", tags=["Super Admin Control Plane"])


