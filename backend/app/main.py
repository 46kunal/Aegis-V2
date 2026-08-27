import logging
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.routes.assets import router as assets_router
from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.reports import router as reports_router
from app.routes.risk import router as risk_router
from app.routes.scans import router as scans_router
from app.routes.attack import router as attack_router
from app.routes.topology import router as topology_router

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("aegis.api")

app = FastAPI(title=settings.project_name, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    started_at = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - started_at) * 1000
        logger.exception(
            "request_failed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "duration_ms": round(duration_ms, 2),
            },
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    duration_ms = (time.perf_counter() - started_at) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 2),
        },
    )
    return response


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.project_name, "environment": settings.environment}


app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(dashboard_router)
app.include_router(reports_router)
app.include_router(risk_router)
app.include_router(attack_router)
app.include_router(scans_router)
app.include_router(topology_router)


@app.on_event("startup")
def bootstrap_kev_catalog() -> None:
    """Refresh the CISA KEV catalog on startup (skipped if cache is fresh)."""
    from app.core.database import SessionLocal
    from app.scanner.kev_client import ensure_loaded

    database = SessionLocal()
    try:
        ensure_loaded(database)
    except Exception:
        logger.exception("startup: KEV catalog refresh failed")
    finally:
        database.close()


@app.on_event("startup")
def cleanup_stale_scans() -> None:
    from sqlalchemy.exc import OperationalError

    from app.core.database import SessionLocal
    from app.services.scan_engine import timeout_stale_scans

    database = SessionLocal()
    try:
        count = timeout_stale_scans(database)
        if count:
            logger.info("startup: timed out %d stale scans", count)
    except OperationalError:
        logger.warning("startup: skipped stale scan cleanup (database not reachable)")
    except Exception:
        logger.exception("startup: failed to clean up stale scans")
    finally:
        database.close()


@app.on_event("startup")
async def start_periodic_stale_scan_cleanup() -> None:
    """Run stale scan cleanup every 5 minutes in the background."""
    import asyncio

    from sqlalchemy.exc import OperationalError

    from app.core.database import SessionLocal
    from app.services.scan_engine import timeout_stale_scans

    async def _loop() -> None:
        while True:
            await asyncio.sleep(300)  # 5 minutes
            database = SessionLocal()
            try:
                count = timeout_stale_scans(database)
                if count:
                    logger.info("periodic_cleanup: timed out %d stale scans", count)
            except OperationalError:
                logger.debug("periodic_cleanup: database not reachable, skipping")
            except Exception:
                logger.exception("periodic_cleanup: failed")
            finally:
                database.close()

    asyncio.create_task(_loop())


if settings.dev_mode:
    logger.warning("=" * 60)
    logger.warning("  DEV_MODE IS ACTIVE — AUTH IS BYPASSED")
    logger.warning("  Set DEV_MODE=false to restore production auth")
    logger.warning("=" * 60)

