from app.core.enums import (
    EvidenceObjectType,
    EvidenceSourceStatus,
    EvidenceSourceType,
)
from app.ingestion.pcap.pcap_parser import PcapParser
from app.services.audit_service import audit_success
from app.services.ingest_service import IngestService
from app.storage.repositories import ArtifactRepository


class PcapIngestor:
    def __init__(self, session, vault_dir, encryption_key: str | None = None):
        self.session = session
        self.vault_dir = vault_dir
        self.encryption_key = encryption_key

    def collect(self, path: str, source_name: str | None = None):
        ingest_service = IngestService(self.session, self.vault_dir, encryption_key=self.encryption_key)

        source = ingest_service.register_source(
            source_type=EvidenceSourceType.PCAP,
            source_name=source_name or "pcap file",
            source_path=path,
            description="PCAP network traffic capture",
        )

        assert source.id is not None

        ingest_service.update_source_status(
            source.id,
            EvidenceSourceStatus.COLLECTING,
        )

        evidence_object, changed = ingest_service.ingest_file(
            source_id=source.id,
            file_path=path,
            object_type=EvidenceObjectType.PCAP,
        )

        if not changed:
            ingest_service.update_source_status(
                source.id,
                EvidenceSourceStatus.COMPLETED,
            )
            audit_success(
                self.session,
                "pcap_ingest_completed",
                target_type="pcap",
                target_id=evidence_object.id,
                target_path=path,
                message="PCAP ingest skipped",
                details={"changed": False, "artifacts_created": 0},
            )
            return evidence_object, [], False

        assert evidence_object.id is not None

        parser = PcapParser()

        # If vault encryption is enabled, stored_path contains encrypted bytes.
        # PCAP parsing is done from the original plaintext file during ingest.
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
            "pcap_ingest_completed",
            target_type="pcap",
            target_id=evidence_object.id,
            target_path=path,
            message="PCAP ingest completed",
            details={"changed": True, "artifacts_created": len(saved_artifacts)},
        )

        return evidence_object, saved_artifacts, True
