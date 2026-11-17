"""Separate active use, evidence age and archive storage for API records."""
from datetime import datetime, timedelta, timezone

ARCHIVE_AFTER_DAYS = 90


def as_datetime(value):
    return datetime.fromisoformat(value) if isinstance(value, str) else value


def lifecycle(updated_at, *, active, expires_at=None, archived_at=None, protected=False, now=None):
    now = now or datetime.now(timezone.utc)
    updated_at = as_datetime(updated_at)
    expires_at = as_datetime(expires_at) if expires_at else None
    archived_at = as_datetime(archived_at) if archived_at else None
    stale = updated_at <= now-timedelta(days=ARCHIVE_AFTER_DAYS)
    expired = expires_at is not None and expires_at <= now
    is_active = bool(active and not expired and not archived_at)
    purge_at = None
    if archived_at:
        try:
            purge_at = archived_at.replace(year=archived_at.year+1)
        except ValueError:
            purge_at = archived_at.replace(year=archived_at.year+1, day=28)
    return {"is_active": is_active, "usage_status": "active" if is_active else "expired" if expired else "historical",
            "freshness_status": "old" if stale else "recent", "storage_status": "audit" if archived_at else "live",
            "updated_at": updated_at, "archive_eligible": bool(stale and not is_active and not protected and not archived_at),
            "protected": protected, "purge_at": purge_at,
            "purge_eligible": bool(purge_at and purge_at <= now)}
