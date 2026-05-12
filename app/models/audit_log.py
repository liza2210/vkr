from datetime import datetime
from dataclasses import dataclass
from typing import Any


@dataclass
class AuditLogEntry:
    id: int | None
    action: str
    status: str
    actor: str | None
    interface: str | None
    target_type: str | None
    target_id: str | None
    target_path: str | None
    message: str | None
    details_json: dict[str, Any]
    created_at: datetime | None = None
