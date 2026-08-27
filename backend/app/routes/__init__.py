from app.routes.assets import router as assets_router
from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.reports import router as reports_router
from app.routes.scans import router as scans_router

__all__ = ["auth_router", "assets_router", "dashboard_router", "reports_router", "scans_router"]
