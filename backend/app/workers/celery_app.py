from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "aegis_v2",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_track_started=True,
    task_default_queue="scans",
    task_routes={"scan.execute": {"queue": "scans"}},
)
