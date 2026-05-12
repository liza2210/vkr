from app.errors import NotFoundError
from app.services.audit_service import audit_success
from app.storage.repositories import ArtifactRepository, EvidenceObjectRepository
from app.storage.vault import Vault
from app.storage.encryption import ProjectEncryptionRepository


class EvidenceService:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
        self.session = session
        self.object_repo = EvidenceObjectRepository(session)
        self.artifact_repo = ArtifactRepository(session)
        encryption_config = ProjectEncryptionRepository(session).get_config()
        self.vault = Vault(
            vault_dir,
            encryption_key=encryption_key,
            encryption_config=encryption_config,
        )

    def delete_evidence(self, object_id: int) -> dict:
        obj = self.object_repo.get(object_id)

        if obj is None:
            raise NotFoundError(f"Evidence object not found: {object_id}")

        stored_path = obj.stored_path
        original_name = obj.original_name
        sha256 = obj.sha256

        self.artifact_repo.delete_by_object(object_id)
        self.object_repo.delete(object_id)

        file_deleted = self.vault.delete_file(stored_path)

        audit_success(
            self.session,
            "evidence_deleted",
            target_type=obj.object_type.value,
            target_id=object_id,
            target_path=obj.original_path,
            message=f"Evidence deleted: {original_name}",
            details={
                "original_name": original_name,
                "sha256": sha256,
                "stored_path": stored_path,
                "vault_file_deleted": file_deleted,
            },
        )

        return {
            "object_id": object_id,
            "original_name": original_name,
            "sha256": sha256,
            "stored_path": stored_path,
            "file_deleted": file_deleted,
        }
