from datetime import datetime
from dataclasses import dataclass

from app.core.enums import InvestigationStatus


@dataclass
class InvestigationMetadata:
    id: int | None
    title: str
    description: str | None
    status: InvestigationStatus
    examiner: str | None
    organization: str | None
    case_number: str | None
    created_at: datetime | None = None
    updated_at: datetime | None = None
