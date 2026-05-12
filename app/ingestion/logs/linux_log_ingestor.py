from app.core.enums import (
    EvidenceObjectType,
    EvidenceSourceStatus,
    EvidenceSourceType,
)
from app.ingestion.logs.linux_auth_parser import LinuxAuthLogParser
from app.ingestion.logs.linux_syslog_parser import LinuxSyslogParser
from app.ingestion.logs.linux_kern_parser import LinuxKernLogParser
from app.services.audit_service import audit_success
from app.services.ingest_service import IngestService
from app.storage.repositories import ArtifactRepository


class LinuxLogIngestor:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
        self.session = session
        self.vault_dir = vault_dir
        self.encryption_key = encryption_key

    def collect(
        self,
        path: str,
        log_type: str,
        year: int | None = None,
        source_name: str | None = None,
    ):
        parser = self._get_parser(log_type, year)

        if source_name is None:
            source_name = log_type

        ingest_service = IngestService(self.session, self.vault_dir, encryption_key=self.encryption_key)

        source = ingest_service.register_source(
            source_type=EvidenceSourceType.LOG,
            source_name=source_name,
            source_path=path,
            description=f"Linux {log_type} log",
        )

        assert source.id is not None

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COLLECTING,
        )

        evidence_object, changed = ingest_service.ingest_file(
            source_id=source.id,
            file_path=path,
            object_type=EvidenceObjectType.LOG,
        )

        if not changed:
            ingest_service.update_source_status(
                source.id,
                EvidenceSourceStatus.COMPLETED,
            )
            audit_success(
                self.session,
                "log_ingest_completed",
                target_type="log",
                target_id=evidence_object.id,
                target_path=path,
                message=f"Linux {log_type} log ingest skipped",
                details={"log_type": log_type, "changed": False, "artifacts_created": 0},
            )
            return evidence_object, [], False

        assert evidence_object.id is not None

        # If vault encryption is enabled, stored_path contains encrypted bytes.
        # The source file is still available during ingest, so parsers read the
        # original plaintext file and metadata/hash still points to the vault copy.
        artifacts = parser.parse_file(
            file_path=evidence_object.original_path,
            evidence_object_id=evidence_object.id,
        )

        artifact_repo = ArtifactRepository(self.session)

        saved_artifacts = []
        for artifact in artifacts:
            saved_artifacts.append(artifact_repo.add(artifact))

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COMPLETED,
        )

        audit_success(
            self.session,
            "log_ingest_completed",
            target_type="log",
            target_id=evidence_object.id,
            target_path=path,
            message=f"Linux {log_type} log ingest completed",
            details={
                "log_type": log_type,
                "changed": True,
                "artifacts_created": len(saved_artifacts),
            },
        )

        return evidence_object, saved_artifacts, True

    def _get_parser(self, log_type: str, year: int | None):
        if log_type == "auth":
            return LinuxAuthLogParser(year=year)

        if log_type == "syslog":
            return LinuxSyslogParser(year=year)

        if log_type == "kern":
            return LinuxKernLogParser(year=year)

        raise ValueError(f"Unsupported log type: {log_type}")
