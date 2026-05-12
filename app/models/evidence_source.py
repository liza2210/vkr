from datetime import datetime
from dataclasses import dataclass

from app.core.enums import EvidenceSourceStatus, EvidenceSourceType


@dataclass
class EvidenceSource:
    id: int | None
    source_type: EvidenceSourceType
    source_name: str
    source_path: str
    description: str | None
    collected_at: datetime | None
    status: EvidenceSourceStatus
