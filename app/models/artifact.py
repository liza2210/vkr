from datetime import datetime
from dataclasses import dataclass

from app.core.enums import ArtifactType
from app.core.types import JsonDict


@dataclass
class Artifact:
    id: int | None
    evidence_object_id: int
    artifact_type: ArtifactType
    timestamp: datetime | None
    title: str
    raw_data_json: JsonDict
    parsed_data_json: JsonDict
    timestamp_start: datetime | None = None
    timestamp_end: datetime | None = None
    created_at: datetime | None = None
