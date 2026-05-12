import sqlite3
from contextlib import contextmanager
from pathlib import Path


def get_connection(db_path: str):
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


@contextmanager
def get_session(db_path: str):
    conn = get_connection(db_path)

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str):
    with get_session(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                examiner TEXT,
                organization TEXT,
                case_number TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS project_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                source_name TEXT NOT NULL,
                source_path TEXT NOT NULL,
                description TEXT,
                collected_at INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence_objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                object_type TEXT NOT NULL,
                original_path TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mime_type TEXT,
                sha256 TEXT NOT NULL,
                md5 TEXT,
                ingested_at INTEGER NOT NULL,
                is_original INTEGER NOT NULL,
                is_stored INTEGER NOT NULL,
                FOREIGN KEY(source_id) REFERENCES evidence_sources(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_object_id INTEGER NOT NULL,
                artifact_type TEXT NOT NULL,
                timestamp INTEGER,
                timestamp_start INTEGER,
                timestamp_end INTEGER,
                title TEXT NOT NULL,
                raw_data_json TEXT NOT NULL,
                parsed_data_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(evidence_object_id) REFERENCES evidence_objects(id)
            )
        """)



        conn.execute("""
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
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
            ON audit_log(created_at)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_log_action_status
            ON audit_log(action, status)
        """)

        _add_column_if_missing(conn, "artifacts", "timestamp_start", "INTEGER")
        _add_column_if_missing(conn, "artifacts", "timestamp_end", "INTEGER")

        conn.execute("""
            UPDATE artifacts
            SET timestamp_start = timestamp
            WHERE timestamp_start IS NULL
        """)


def _add_column_if_missing(
    conn,
    table_name: str,
    column_name: str,
    column_type: str,
):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()

    for row in rows:
        if row["name"] == column_name:
            return

    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
