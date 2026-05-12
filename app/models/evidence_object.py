from datetime import datetime
from dataclasses import dataclass

from app.core.enums import EvidenceObjectType


@dataclass
class EvidenceObject:
    id: int | None
    source_id: int
    object_type: EvidenceObjectType
    original_path: str
    original_name: str
    stored_path: str
    stored_name: str
    size_bytes: int
    mime_type: str | None
    sha256: str
    md5: str | None
    ingested_at: datetime | None
    is_original: bool
    is_stored: bool
