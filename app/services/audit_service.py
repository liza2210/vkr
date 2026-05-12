from __future__ import annotations

import getpass
import os
import socket
from pathlib import Path
from typing import Any

from app.models import AuditLogEntry
from app.storage.repositories import AuditLogRepository


DEFAULT_ACTOR = None


def get_default_actor() -> str:
    """Return a stable, human-readable local actor for audit records."""

    global DEFAULT_ACTOR
    if DEFAULT_ACTOR is not None:
        return DEFAULT_ACTOR

    try:
        user = getpass.getuser()
    except Exception:
        user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"

    try:
        host = socket.gethostname()
    except Exception:
        host = "localhost"

    DEFAULT_ACTOR = f"{user}@{host}"
    return DEFAULT_ACTOR


def audit_log(
    session,
    action: str,
    *,
    status: str = "success",
    actor: str | None = None,
    interface: str | None = None,
    target_type: str | None = None,
    target_id: int | str | None = None,
    target_path: str | Path | None = None,
    message: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLogEntry:
    """Append one audit journal entry to the current case database.

    The audit journal is intentionally stored in case.db: this keeps the
    educational project simple and makes the journal travel with the case.
    """

    entry = AuditLogEntry(
        id=None,
        action=action,
        status=status,
        actor=actor or get_default_actor(),
        interface=interface or "service",
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_path=str(target_path) if target_path is not None else None,
        message=message,
        details_json=details or {},
    )
    return AuditLogRepository(session).add(entry)


def audit_success(session, action: str, **kwargs) -> AuditLogEntry:
    return audit_log(session, action, status="success", **kwargs)


def audit_error(session, action: str, error: BaseException | str, **kwargs) -> AuditLogEntry:
    details = dict(kwargs.pop("details", {}) or {})
    details.setdefault("error", str(error))
    return audit_log(session, action, status="error", details=details, **kwargs)
