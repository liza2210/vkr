from pathlib import Path

from app.core.enums import (
    EvidenceObjectType,
    EvidenceSourceStatus,
    EvidenceSourceType,
)
from app.ingestion.files.file_metadata_parser import FileMetadataParser
from app.services.audit_service import audit_success
from app.services.ingest_service import IngestService
from app.storage.repositories import ArtifactRepository


class FileIngestor:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
        self.session = session
        self.vault_dir = vault_dir
        self.encryption_key = encryption_key
        self.parser = FileMetadataParser()
        self.artifact_repo = ArtifactRepository(session)

    def collect_file(self, path: str, source_name: str | None = None):
        file_path = Path(path)

        ingest_service = IngestService(self.session, self.vault_dir, encryption_key=self.encryption_key)

        source = ingest_service.register_source(
            source_type=EvidenceSourceType.DIRECTORY,
            source_name=source_name or file_path.name,
            source_path=str(file_path),
            description="Single file source",
        )

        assert source.id is not None

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COLLECTING,
        )

        evidence_object, changed = ingest_service.ingest_file(
            source_id=source.id,
            file_path=str(file_path),
            object_type=EvidenceObjectType.FILE,
        )

        if not changed:
            ingest_service.update_source_status(
                source.id,
                EvidenceSourceStatus.COMPLETED,
            )
            audit_success(
                self.session,
                "file_ingest_completed",
                target_type="file",
                target_id=evidence_object.id,
                target_path=str(file_path),
                message=f"File ingest skipped: {file_path.name}",
                details={"changed": False, "artifacts_created": 0},
            )
            return evidence_object, [], False

        artifacts = self.parser.parse(evidence_object)
        saved_artifacts = self._save_artifacts(artifacts)

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COMPLETED,
        )

        audit_success(
            self.session,
            "file_ingest_completed",
            target_type="file",
            target_id=evidence_object.id,
            target_path=str(file_path),
            message=f"File ingest completed: {file_path.name}",
            details={"changed": True, "artifacts_created": len(saved_artifacts)},
        )

        return evidence_object, saved_artifacts, True

    def collect_directory(self, path: str, source_name: str | None = None):
        directory_path = Path(path)

        ingest_service = IngestService(self.session, self.vault_dir, encryption_key=self.encryption_key)

        source = ingest_service.register_source(
            source_type=EvidenceSourceType.DIRECTORY,
            source_name=source_name or directory_path.name,
            source_path=str(directory_path),
            description="Directory file collection",
        )

        assert source.id is not None

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COLLECTING,
        )

        objects = []
        all_artifacts = []
        changed_count = 0
        skipped_count = 0

        for item in directory_path.rglob("*"):
            if not item.is_file():
                continue

            evidence_object, changed = ingest_service.ingest_file(
                source_id=source.id,
                file_path=str(item),
                object_type=EvidenceObjectType.FILE,
            )

            objects.append(evidence_object)

            if not changed:
                skipped_count += 1
                continue

            artifacts = self.parser.parse(evidence_object)
            saved_artifacts = self._save_artifacts(artifacts)

            all_artifacts.extend(saved_artifacts)
            changed_count += 1

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COMPLETED,
        )

        audit_success(
            self.session,
            "directory_ingest_completed",
            target_type="directory",
            target_id=source.id,
            target_path=str(directory_path),
            message=f"Directory ingest completed: {directory_path}",
            details={
                "files_found": len(objects),
                "files_added_or_updated": changed_count,
                "files_skipped": skipped_count,
                "artifacts_created": len(all_artifacts),
            },
        )

        return objects, all_artifacts, changed_count, skipped_count

    def _save_artifacts(self, artifacts):
        saved = []

        for artifact in artifacts:
            saved.append(self.artifact_repo.add(artifact))

        return saved
