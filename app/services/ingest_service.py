from pathlib import Path

from app.errors import IngestError
from app.services.audit_service import audit_success
from app.storage.vault import Vault
from app.storage.encryption import ProjectEncryptionRepository
from app.core.enums import (
    EvidenceObjectType,
    EvidenceSourceStatus,
    EvidenceSourceType,
)
from app.models import EvidenceObject, EvidenceSource
from app.storage.repositories import (
    ArtifactRepository,
    EvidenceObjectRepository,
    EvidenceSourceRepository,
)
from app.utils.hashing import file_size, md5_file, sha256_file
from app.utils.mime import guess_mime_type


class IngestService:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
        self.session = session
        self.source_repo = EvidenceSourceRepository(session)
        self.object_repo = EvidenceObjectRepository(session)
        self.artifact_repo = ArtifactRepository(session)
        encryption_repo = ProjectEncryptionRepository(session)
        self.encryption_config = encryption_repo.get_config()
        encryption_repo.require_valid_key(encryption_key)
        self.vault = Vault(
            vault_dir,
            encryption_key=encryption_key,
            encryption_config=self.encryption_config,
        )

    def register_source(
        self,
        source_type: EvidenceSourceType,
        source_name: str,
        source_path: str,
        description: str | None = None,
    ) -> EvidenceSource:
        real_path = str(Path(source_path).resolve())

        existing = self.source_repo.get_by_path_and_type(
            source_path=real_path,
            source_type=source_type,
        )

        if existing is not None:
            return existing

        source = EvidenceSource(
            id=None,
            source_type=source_type,
            source_name=source_name,
            source_path=real_path,
            description=description,
            collected_at=None,
            status=EvidenceSourceStatus.PENDING,
        )

        source = self.source_repo.add(source)
        audit_success(
            self.session,
            "source_registered",
            target_type=source_type.value,
            target_id=source.id,
            target_path=real_path,
            message=f"Evidence source registered: {source_name}",
            details={
                "source_name": source_name,
                "source_type": source_type.value,
                "description": description,
            },
        )
        return source

    def update_source_status(
        self,
        source_id: int,
        status: EvidenceSourceStatus,
    ):
        self.source_repo.update_status(source_id, status)
        audit_success(
            self.session,
            "source_status_changed",
            target_type="source",
            target_id=source_id,
            message=f"Evidence source status changed: {status.value}",
            details={"source_id": source_id, "status": status.value},
        )

    def ingest_file(
        self,
        source_id: int,
        file_path: str,
        object_type: EvidenceObjectType = EvidenceObjectType.FILE,
    ) -> tuple[EvidenceObject, bool]:
        path = Path(file_path).resolve()

        new_sha256 = sha256_file(str(path))

        existing = self.object_repo.get_by_original_path_and_type(
            original_path=str(path),
            object_type=object_type,
        )

        if existing is not None and existing.sha256 == new_sha256:
            audit_success(
                self.session,
                "evidence_ingest_skipped",
                target_type=object_type.value,
                target_id=existing.id,
                target_path=str(path),
                message=f"Evidence already exists and was not changed: {path.name}",
                details={
                    "source_id": source_id,
                    "original_name": existing.original_name,
                    "sha256": existing.sha256,
                },
            )
            return existing, False

        old_stored_path = None

        if existing is not None:
            old_stored_path = existing.stored_path

        stored_path, stored_name = self.vault.save_file(str(path))
        stored_sha256 = self.vault.stored_plaintext_sha256(stored_path)

        if stored_sha256 != new_sha256:
            self.vault.delete_file(stored_path)
            raise IngestError("Stored file hash does not match original file hash")

        obj = EvidenceObject(
            id=None,
            source_id=source_id,
            object_type=object_type,
            original_path=str(path),
            original_name=path.name,
            stored_path=stored_path,
            stored_name=stored_name,
            size_bytes=file_size(str(path)),
            mime_type=guess_mime_type(str(path)),
            sha256=stored_sha256,
            md5=md5_file(str(path)),
            ingested_at=None,
            is_original=True,
            is_stored=True,
        )

        try:
            if existing is not None and existing.id is not None:
                self.artifact_repo.delete_by_object(existing.id)
                self.object_repo.delete(existing.id)

            obj = self.object_repo.add(obj)

        except Exception:
            self.vault.delete_file(stored_path)
            raise

        if old_stored_path is not None:
            self.vault.delete_file(old_stored_path)

        audit_success(
            self.session,
            "evidence_ingested" if existing is None else "evidence_updated",
            target_type=object_type.value,
            target_id=obj.id,
            target_path=str(path),
            message=(
                f"Evidence ingested: {obj.original_name}"
                if existing is None
                else f"Evidence updated: {obj.original_name}"
            ),
            details={
                "source_id": source_id,
                "stored_path": obj.stored_path,
                "stored_name": obj.stored_name,
                "size_bytes": obj.size_bytes,
                "mime_type": obj.mime_type,
                "sha256": obj.sha256,
                "md5": obj.md5,
                "vault_encrypted": self.encryption_config.enabled,
                "previous_object_id": existing.id if existing is not None else None,
                "previous_stored_path": old_stored_path,
            },
        )

        return obj, True
