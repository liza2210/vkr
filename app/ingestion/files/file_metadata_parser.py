import os
from datetime import datetime, timezone
from pathlib import Path

from app.core.enums import ArtifactType
from app.models import Artifact, EvidenceObject


class FileMetadataParser:
    def parse(self, evidence_object: EvidenceObject) -> list[Artifact]:
        assert evidence_object.id is not None

        return [
            self._file_discovered(evidence_object),
            self._file_metadata(evidence_object),
            self._file_hash_computed(evidence_object),
        ]

    def _file_discovered(self, obj: EvidenceObject) -> Artifact:
        assert obj.id is not None
        return Artifact(
            id=None,
            evidence_object_id=obj.id,
            artifact_type=ArtifactType.FILE_DISCOVERED,
            timestamp=obj.ingested_at,
            title=f"File discovered: {obj.original_name}",
            raw_data_json={
                "original_path": obj.original_path,
                "original_name": obj.original_name,
            },
            parsed_data_json={
                "event": "file_discovered",
                "file_name": obj.original_name,
                "file_path": obj.original_path,
                "stored_name": obj.stored_name,
                "is_stored": obj.is_stored,
            },
        )

    def _file_metadata(self, obj: EvidenceObject) -> Artifact:
        path = Path(obj.original_path)

        if not path.exists():
            path = Path(obj.stored_path)

        stat_result = path.stat()

        modified_at = self._from_timestamp(stat_result.st_mtime)
        accessed_at = self._from_timestamp(stat_result.st_atime)
        metadata_changed_at = self._from_timestamp(stat_result.st_ctime)

        assert obj.id is not None

        return Artifact(
            id=None,
            evidence_object_id=obj.id,
            artifact_type=ArtifactType.FILE_METADATA,
            timestamp=modified_at,
            title=f"File metadata: {obj.original_name}",
            raw_data_json={
                "stat": {
                    "st_size": stat_result.st_size,
                    "st_mode": stat_result.st_mode,
                    "st_atime": stat_result.st_atime,
                    "st_mtime": stat_result.st_mtime,
                    "st_ctime": stat_result.st_ctime,
                }
            },
            parsed_data_json={
                "event": "file_metadata",
                "file_name": obj.original_name,
                "file_path": obj.original_path,
                "extension": Path(obj.original_name).suffix.lower(),
                "size_bytes": obj.size_bytes,
                "mime_type": obj.mime_type,
                "modified_at": modified_at.isoformat(),
                "accessed_at": accessed_at.isoformat(),
                "metadata_changed_at": metadata_changed_at.isoformat(),
                "is_executable": os.access(path, os.X_OK),
            },
        )

    def _file_hash_computed(self, obj: EvidenceObject) -> Artifact:
        assert obj.id is not None
        return Artifact(
            id=None,
            evidence_object_id=obj.id,
            artifact_type=ArtifactType.FILE_HASH_COMPUTED,
            timestamp=obj.ingested_at,
            title=f"Hash computed: {obj.original_name}",
            raw_data_json={
                "stored_path": obj.stored_path,
                "stored_name": obj.stored_name,
            },
            parsed_data_json={
                "event": "file_hash_computed",
                "file_name": obj.original_name,
                "stored_name": obj.stored_name,
                "sha256": obj.sha256,
                "md5": obj.md5,
                "size_bytes": obj.size_bytes,
                "hash_target": "evidence_plaintext_content",
            },
        )

    def _from_timestamp(self, value: float) -> datetime:
        return datetime.fromtimestamp(value, tz=timezone.utc)
