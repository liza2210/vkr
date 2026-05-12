import json

from app.core.enums import (
    ArtifactType,
    EvidenceObjectType,
    EvidenceSourceStatus,
    EvidenceSourceType,
    InvestigationStatus,
)
from app.models import (
    Artifact,
    AuditLogEntry,
    EvidenceObject,
    EvidenceSource,
    InvestigationMetadata,
)
from app.utils.time import datetime_to_timestamp_us, timestamp_us_to_datetime, utc_now


class InvestigationMetadataRepository:
    def __init__(self, conn):
        self.conn = conn

    def create(self, metadata: InvestigationMetadata) -> InvestigationMetadata:
        now = utc_now()
        metadata.id = 1
        metadata.created_at = now
        metadata.updated_at = now

        self.conn.execute(
            """
            INSERT INTO investigation_metadata(
                id, title, description, status, examiner,
                organization, case_number, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metadata.id,
                metadata.title,
                metadata.description,
                metadata.status.value,
                metadata.examiner,
                metadata.organization,
                metadata.case_number,
                datetime_to_timestamp_us(metadata.created_at),
                datetime_to_timestamp_us(metadata.updated_at),
            ),
        )

        return metadata

    def get(self) -> InvestigationMetadata | None:
        row = self.conn.execute(
            "SELECT * FROM investigation_metadata WHERE id = 1"
        ).fetchone()

        return self._from_row(row) if row else None

    def update(self, metadata: InvestigationMetadata) -> InvestigationMetadata:
        metadata.updated_at = utc_now()

        self.conn.execute(
            """
            UPDATE investigation_metadata
            SET title = ?,
                description = ?,
                status = ?,
                examiner = ?,
                organization = ?,
                case_number = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (
                metadata.title,
                metadata.description,
                metadata.status.value,
                metadata.examiner,
                metadata.organization,
                metadata.case_number,
                datetime_to_timestamp_us(metadata.updated_at),
            ),
        )

        return metadata

    def _from_row(self, row) -> InvestigationMetadata:
        return InvestigationMetadata(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            status=InvestigationStatus(row["status"]),
            examiner=row["examiner"],
            organization=row["organization"],
            case_number=row["case_number"],
            created_at=timestamp_us_to_datetime(row["created_at"]),
            updated_at=timestamp_us_to_datetime(row["updated_at"]),
        )


class EvidenceSourceRepository:
    def __init__(self, conn):
        self.conn = conn

    def add(self, source: EvidenceSource) -> EvidenceSource:
        if source.collected_at is None:
            source.collected_at = utc_now()

        cur = self.conn.execute(
            """
            INSERT INTO evidence_sources(
                source_type, source_name, source_path,
                description, collected_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                source.source_type.value,
                source.source_name,
                source.source_path,
                source.description,
                datetime_to_timestamp_us(source.collected_at),
                source.status.value,
            ),
        )
        source.id = cur.lastrowid
        return source

    def update_status(
        self,
        source_id: int,
        status: EvidenceSourceStatus,
    ):
        self.conn.execute(
            """
            UPDATE evidence_sources
            SET status = ?
            WHERE id = ?
            """,
            (
                status.value,
                source_id,
            ),
        )

    def get_by_path_and_type(
        self,
        source_path: str,
        source_type: EvidenceSourceType,
    ) -> EvidenceSource | None:
        row = self.conn.execute(
            """
            SELECT * FROM evidence_sources
            WHERE source_path = ? AND source_type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (source_path, source_type.value),
        ).fetchone()

        return self._from_row(row) if row else None

    def get(self, source_id: int) -> EvidenceSource | None:
        row = self.conn.execute(
            "SELECT * FROM evidence_sources WHERE id = ?",
            (source_id,),
        ).fetchone()

        return self._from_row(row) if row else None

    def list_all(self) -> list[EvidenceSource]:
        rows = self.conn.execute(
            "SELECT * FROM evidence_sources ORDER BY id"
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def _from_row(self, row) -> EvidenceSource:
        return EvidenceSource(
            id=row["id"],
            source_type=EvidenceSourceType(row["source_type"]),
            source_name=row["source_name"],
            source_path=row["source_path"],
            description=row["description"],
            collected_at=timestamp_us_to_datetime(row["collected_at"]),
            status=EvidenceSourceStatus(row["status"]),
        )


class EvidenceObjectRepository:
    def __init__(self, conn):
        self.conn = conn

    def add(self, obj: EvidenceObject) -> EvidenceObject:
        if obj.ingested_at is None:
            obj.ingested_at = utc_now()

        cur = self.conn.execute(
            """
            INSERT INTO evidence_objects(
                source_id, object_type, original_path, original_name,
                stored_path, stored_name, size_bytes, mime_type,
                sha256, md5, ingested_at, is_original, is_stored
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                obj.source_id,
                obj.object_type.value,
                obj.original_path,
                obj.original_name,
                obj.stored_path,
                obj.stored_name,
                obj.size_bytes,
                obj.mime_type,
                obj.sha256,
                obj.md5,
                datetime_to_timestamp_us(obj.ingested_at),
                int(obj.is_original),
                int(obj.is_stored),
            ),
        )

        obj.id = cur.lastrowid

        return obj

    def get(self, object_id: int) -> EvidenceObject | None:
        row = self.conn.execute(
            "SELECT * FROM evidence_objects WHERE id = ?",
            (object_id,),
        ).fetchone()

        return self._from_row(row) if row else None

    def get_by_original_path_and_type(
        self,
        original_path: str,
        object_type: EvidenceObjectType,
    ) -> EvidenceObject | None:
        row = self.conn.execute(
            """
            SELECT * FROM evidence_objects
            WHERE original_path = ? AND object_type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (original_path, object_type.value),
        ).fetchone()

        return self._from_row(row) if row else None

    def update_snapshot(self, obj: EvidenceObject) -> EvidenceObject:
        obj.ingested_at = utc_now()

        self.conn.execute(
            """
            UPDATE evidence_objects
            SET stored_path = ?,
                stored_name = ?,
                size_bytes = ?,
                mime_type = ?,
                sha256 = ?,
                md5 = ?,
                ingested_at = ?,
                is_original = ?,
                is_stored = ?
            WHERE id = ?
            """,
            (
                obj.stored_path,
                obj.stored_name,
                obj.size_bytes,
                obj.mime_type,
                obj.sha256,
                obj.md5,
                datetime_to_timestamp_us(obj.ingested_at),
                int(obj.is_original),
                int(obj.is_stored),
                obj.id,
            ),
        )

        return obj

    def list_by_type(self, object_type: EvidenceObjectType) -> list[EvidenceObject]:
        rows = self.conn.execute(
            """
            SELECT * FROM evidence_objects
            WHERE object_type = ?
            ORDER BY id
            """,
            (object_type.value,),
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def list_all(self) -> list[EvidenceObject]:
        rows = self.conn.execute(
            "SELECT * FROM evidence_objects ORDER BY id"
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def list_by_source(self, source_id: int) -> list[EvidenceObject]:
        rows = self.conn.execute(
            "SELECT * FROM evidence_objects WHERE source_id = ? ORDER BY id",
            (source_id,),
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def delete(self, object_id: int):
        self.conn.execute(
            "DELETE FROM evidence_objects WHERE id = ?",
            (object_id,),
        )

    def _from_row(self, row) -> EvidenceObject:
        return EvidenceObject(
            id=row["id"],
            source_id=row["source_id"],
            object_type=EvidenceObjectType(row["object_type"]),
            original_path=row["original_path"],
            original_name=row["original_name"],
            stored_path=row["stored_path"],
            stored_name=row["stored_name"],
            size_bytes=row["size_bytes"],
            mime_type=row["mime_type"],
            sha256=row["sha256"],
            md5=row["md5"],
            ingested_at=timestamp_us_to_datetime(row["ingested_at"]),
            is_original=bool(row["is_original"]),
            is_stored=bool(row["is_stored"]),
        )


class ArtifactRepository:
    def __init__(self, conn):
        self.conn = conn

    def add(self, artifact: Artifact) -> Artifact:
        if artifact.created_at is None:
            artifact.created_at = utc_now()

        if artifact.timestamp_start is None:
            artifact.timestamp_start = artifact.timestamp

        cur = self.conn.execute(
            """
            INSERT INTO artifacts(
                evidence_object_id, artifact_type, timestamp,
                timestamp_start, timestamp_end,
                title, raw_data_json, parsed_data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.evidence_object_id,
                artifact.artifact_type.value,
                datetime_to_timestamp_us(artifact.timestamp),
                datetime_to_timestamp_us(artifact.timestamp_start),
                datetime_to_timestamp_us(artifact.timestamp_end),
                artifact.title,
                json.dumps(artifact.raw_data_json, ensure_ascii=False),
                json.dumps(artifact.parsed_data_json, ensure_ascii=False),
                datetime_to_timestamp_us(artifact.created_at),
            ),
        )

        artifact.id = cur.lastrowid
        return artifact

    def get(self, artifact_id: int) -> Artifact | None:
        row = self.conn.execute(
            "SELECT * FROM artifacts WHERE id = ?",
            (artifact_id,),
        ).fetchone()

        return self._from_row(row) if row else None

    def list_all(self) -> list[Artifact]:
        rows = self.conn.execute(
            "SELECT * FROM artifacts ORDER BY timestamp_start, id"
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def list_by_object(self, evidence_object_id: int) -> list[Artifact]:
        rows = self.conn.execute(
            """
            SELECT * FROM artifacts
            WHERE evidence_object_id = ?
            ORDER BY timestamp_start, id
            """,
            (evidence_object_id,),
        ).fetchall()

        return [self._from_row(row) for row in rows]

    def delete_by_object(self, evidence_object_id: int):
        self.conn.execute(
            "DELETE FROM artifacts WHERE evidence_object_id = ?",
            (evidence_object_id,),
        )

    def _from_row(self, row) -> Artifact:
        return Artifact(
            id=row["id"],
            evidence_object_id=row["evidence_object_id"],
            artifact_type=ArtifactType(row["artifact_type"]),
            timestamp=timestamp_us_to_datetime(row["timestamp"]),
            timestamp_start=timestamp_us_to_datetime(row["timestamp_start"]),
            timestamp_end=timestamp_us_to_datetime(row["timestamp_end"]),
            title=row["title"],
            raw_data_json=json.loads(row["raw_data_json"]),
            parsed_data_json=json.loads(row["parsed_data_json"]),
            created_at=timestamp_us_to_datetime(row["created_at"]),
        )


class AuditLogRepository:
    def __init__(self, conn):
        self.conn = conn
        self._ensure_table()

    def add(self, entry: AuditLogEntry) -> AuditLogEntry:
        if entry.created_at is None:
            entry.created_at = utc_now()

        details = entry.details_json if entry.details_json is not None else {}

        cur = self.conn.execute(
            """
            INSERT INTO audit_log(
                action, status, actor, interface, target_type, target_id,
                target_path, message, details_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.action,
                entry.status,
                entry.actor,
                entry.interface,
                entry.target_type,
                entry.target_id,
                entry.target_path,
                entry.message,
                json.dumps(details, ensure_ascii=False, default=str),
                datetime_to_timestamp_us(entry.created_at),
            ),
        )
        entry.id = cur.lastrowid
        return entry

    def list_all(self, limit: int | None = None) -> list[AuditLogEntry]:
        query = "SELECT * FROM audit_log ORDER BY created_at DESC, id DESC"
        params: tuple = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        rows = self.conn.execute(query, params).fetchall()
        return [self._from_row(row) for row in rows]

    def list_filtered(
        self,
        action: str | None = None,
        status: str | None = None,
        query: str | None = None,
        limit: int | None = None,
    ) -> list[AuditLogEntry]:
        clauses = []
        params: list[str | int] = []

        if action and action != "all":
            clauses.append("action = ?")
            params.append(action)

        if status and status != "all":
            clauses.append("status = ?")
            params.append(status)

        if query:
            pattern = f"%{query}%"
            clauses.append(
                "(" 
                "action LIKE ? OR status LIKE ? OR actor LIKE ? OR interface LIKE ? "
                "OR target_type LIKE ? OR target_id LIKE ? OR target_path LIKE ? "
                "OR message LIKE ? OR details_json LIKE ?"
                ")"
            )
            params.extend([pattern] * 9)

        sql = "SELECT * FROM audit_log"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        rows = self.conn.execute(sql, tuple(params)).fetchall()
        return [self._from_row(row) for row in rows]

    def list_actions(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT action FROM audit_log ORDER BY action"
        ).fetchall()
        return [row["action"] for row in rows]

    def _from_row(self, row) -> AuditLogEntry:
        return AuditLogEntry(
            id=row["id"],
            action=row["action"],
            status=row["status"],
            actor=row["actor"],
            interface=row["interface"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            target_path=row["target_path"],
            message=row["message"],
            details_json=json.loads(row["details_json"] or "{}"),
            created_at=timestamp_us_to_datetime(row["created_at"]),
        )

    def _ensure_table(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                actor TEXT,
                interface TEXT,
                target_type TEXT,
                target_id TEXT,
                target_path TEXT,
                message TEXT,
                details_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
            ON audit_log(created_at)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_log_action_status
            ON audit_log(action, status)
            """
        )
