from pathlib import Path

from app.core.enums import ArtifactType, EvidenceObjectType
from app.errors import EncryptionError, IngestError, NotFoundError
from app.models import Artifact, EvidenceObject
from app.services.audit_service import audit_success
from app.storage.repositories import ArtifactRepository, EvidenceObjectRepository
from app.storage.vault import Vault
from app.storage.encryption import ProjectEncryptionRepository
from app.utils.hashing import file_size, md5_file, sha256_file
from app.utils.mime import guess_mime_type
from app.utils.time import utc_now


class FileVerifier:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
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

    def verify_object(self, object_id: int):
        obj = self.object_repo.get(object_id)

        if obj is None:
            raise NotFoundError(f"Evidence object not found: {object_id}")

        result = self._check_object(obj)

        artifact = None
        if result["is_modified"]:
            artifact = self._make_modified_artifact(obj, result)
            artifact = self.artifact_repo.add(artifact)

            refresh_result = self._refresh_object(obj)
            result["refresh_result"] = refresh_result
        else:
            result["refresh_result"] = None

        audit_success(
            self.object_repo.conn,
            "evidence_verified",
            target_type=obj.object_type.value,
            target_id=obj.id,
            target_path=obj.original_path,
            message=f"Evidence verified: {obj.original_name}",
            details={
                "is_modified": result["is_modified"],
                "original_status": result["original_check"]["status"],
                "stored_status": result["stored_check"]["status"],
                "artifact_id": artifact.id if artifact is not None else None,
                "refresh_result": result.get("refresh_result"),
            },
        )

        return result, artifact

    def verify_all(
        self, object_type: EvidenceObjectType | None = EvidenceObjectType.FILE
    ):
        results = []
        artifacts = []

        if object_type is None:
            objects = self.object_repo.list_all()
        else:
            objects = self.object_repo.list_by_type(object_type)

        for obj in objects:
            result = self._check_object(obj)
            artifact = None

            if result["is_modified"]:
                artifact = self._make_modified_artifact(obj, result)
                artifact = self.artifact_repo.add(artifact)
                artifacts.append(artifact)

                refresh_result = self._refresh_object(obj)
                result["refresh_result"] = refresh_result
            else:
                result["refresh_result"] = None

            results.append(result)

        modified = [item for item in results if item["is_modified"]]
        audit_success(
            self.object_repo.conn,
            "evidence_verify_all",
            target_type=object_type.value if object_type is not None else "all",
            message="Evidence verify all completed",
            details={
                "object_type": object_type.value if object_type is not None else "all",
                "objects_checked": len(results),
                "modified_or_missing": len(modified),
                "artifacts_created": len(artifacts),
            },
        )

        return results, artifacts

    def _check_object(self, obj: EvidenceObject) -> dict:
        checked_at = utc_now()

        original_check = self._check_file(
            path=obj.original_path,
            expected_sha256=obj.sha256,
        )

        stored_check = self._check_stored_file(
            path=obj.stored_path,
            expected_sha256=obj.sha256,
        )

        is_modified = original_check["status"] != "ok" or stored_check["status"] != "ok"

        return {
            "object_id": obj.id,
            "object_type": obj.object_type.value,
            "original_name": obj.original_name,
            "original_path": obj.original_path,
            "stored_path": obj.stored_path,
            "expected_sha256": obj.sha256,
            "checked_at": checked_at.isoformat(),
            "original_check": original_check,
            "stored_check": stored_check,
            "is_modified": is_modified,
        }

    def _check_file(self, path: str, expected_sha256: str) -> dict:
        file_path = Path(path)

        if not file_path.exists():
            return {
                "status": "missing",
                "path": str(file_path),
                "sha256": None,
                "size_bytes": None,
            }

        current_sha256 = sha256_file(str(file_path))
        current_size = file_size(str(file_path))

        if current_sha256 == expected_sha256:
            status = "ok"
        else:
            status = "modified"

        return {
            "status": status,
            "path": str(file_path),
            "sha256": current_sha256,
            "size_bytes": current_size,
        }

    def _check_stored_file(self, path: str, expected_sha256: str) -> dict:
        file_path = Path(path)

        if not file_path.exists():
            return {
                "status": "missing",
                "path": str(file_path),
                "sha256": None,
                "size_bytes": None,
            }

        try:
            current_sha256 = self.vault.stored_plaintext_sha256(str(file_path))
            current_size = self.vault.stored_plaintext_size(str(file_path))
        except EncryptionError as exc:
            return {
                "status": "cannot_decrypt",
                "path": str(file_path),
                "sha256": None,
                "size_bytes": None,
                "reason": str(exc),
            }

        if current_sha256 == expected_sha256:
            status = "ok"
        else:
            status = "modified"

        return {
            "status": status,
            "path": str(file_path),
            "sha256": current_sha256,
            "size_bytes": current_size,
        }

    def _refresh_object(self, obj: EvidenceObject) -> dict:
        original_path = Path(obj.original_path)

        if not original_path.exists():
            return {
                "status": "not_refreshed",
                "reason": "original_file_missing",
            }

        old_stored_path = obj.stored_path

        original_sha256 = sha256_file(str(original_path))

        new_stored_path, new_stored_name = self.vault.save_file(str(original_path))
        stored_sha256 = self.vault.stored_plaintext_sha256(new_stored_path)

        if original_sha256 != stored_sha256:
            self.vault.delete_file(new_stored_path)
            raise IngestError("Stored file hash does not match original file hash")

        obj.stored_path = new_stored_path
        obj.stored_name = new_stored_name
        obj.size_bytes = file_size(str(original_path))
        obj.mime_type = guess_mime_type(str(original_path))
        obj.sha256 = stored_sha256
        obj.md5 = md5_file(str(original_path))
        obj.is_original = True
        obj.is_stored = True

        self.object_repo.update_snapshot(obj)

        if old_stored_path != new_stored_path:
            self.vault.delete_file(old_stored_path)

        return {
            "status": "refreshed",
            "new_sha256": obj.sha256,
            "new_stored_path": obj.stored_path,
            "new_stored_name": obj.stored_name,
        }

    def _make_modified_artifact(
        self,
        obj: EvidenceObject,
        result: dict,
    ) -> Artifact:
        assert obj.id is not None
        return Artifact(
            id=None,
            evidence_object_id=obj.id,
            artifact_type=ArtifactType.FILE_MODIFIED_MARKER,
            timestamp=utc_now(),
            title=f"File modification detected: {obj.original_name}",
            raw_data_json={
                "original_path": obj.original_path,
                "stored_path": obj.stored_path,
            },
            parsed_data_json={
                "event": "file_modified_marker",
                "file_name": obj.original_name,
                "object_type": obj.object_type.value,
                "original_path": obj.original_path,
                "stored_path": obj.stored_path,
                "expected_sha256": result["expected_sha256"],
                "checked_at": result["checked_at"],
                "original_check": result["original_check"],
                "stored_check": result["stored_check"],
            },
        )
