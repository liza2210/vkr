import argparse
import os

from app.core.enums import EvidenceObjectType, InvestigationStatus
from app.ingestion.files import FileIngestor, FileVerifier
from app.ingestion.logs.linux_log_ingestor import LinuxLogIngestor
from app.models import InvestigationMetadata
from app.services.audit_service import audit_error, audit_success
from app.services.report_service import ReportService
from app.storage.db import get_session, init_db
from app.storage.encryption import ProjectEncryptionRepository
from app.storage.repositories import AuditLogRepository, InvestigationMetadataRepository
from app.utils.paths import get_case_db_path, get_case_dir, get_case_vault_dir
from app.services.evidence_service import EvidenceService


def get_encryption_key(args) -> str | None:
    return getattr(args, "encryption_key", None) or os.getenv("FORENSIC_MVP_KEY")

def add_encryption_key_argument(parser):
    parser.add_argument(
        "--encryption-key",
        default=None,
        help="Project vault encryption key. Can also be supplied via FORENSIC_MVP_KEY",
    )


def cmd_init_db(args):
    case_dir = get_case_dir(args.case_dir)
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    init_db(db_path)

    with get_session(db_path) as session:
        encryption_config = ProjectEncryptionRepository(session).configure(get_encryption_key(args))
        audit_success(
            session,
            "project_db_initialized",
            interface="cli",
            target_type="project",
            target_path=case_dir,
            message="Project database initialized",
            details={"vault_encryption_enabled": encryption_config.enabled},
        )

    print(f"Investigation directory created: {case_dir}")
    print(f"Database initialized: {db_path}")
    print(f"Vault directory created: {vault_dir}")
    print(f"Vault encryption: {'enabled' if encryption_config.enabled else 'disabled'}")


def cmd_init_investigation(args):
    db_path = get_case_db_path(args.case_dir)

    init_db(db_path)

    with get_session(db_path) as session:
        encryption_config = ProjectEncryptionRepository(session).configure(get_encryption_key(args))
        audit_success(
            session,
            "project_db_initialized",
            interface="cli",
            target_type="project",
            target_path=get_case_dir(args.case_dir),
            message="Project database initialized",
            details={"vault_encryption_enabled": encryption_config.enabled},
        )
        repo = InvestigationMetadataRepository(session)

        existing = repo.get()
        if existing is not None:
            audit_success(
                session,
                "investigation_init_skipped",
                interface="cli",
                target_type="project",
                target_path=get_case_dir(args.case_dir),
                message="Investigation metadata already exists",
                details={"title": existing.title},
            )
            print("Investigation metadata already exists")
            print(f"Title: {existing.title}")
            return

        metadata = InvestigationMetadata(
            id=None,
            title=args.title,
            description=args.description,
            status=InvestigationStatus.OPEN,
            examiner=args.examiner,
            organization=args.organization,
            case_number=args.case_number,
        )

        metadata = repo.create(metadata)
        audit_success(
            session,
            "investigation_created",
            interface="cli",
            target_type="project",
            target_path=get_case_dir(args.case_dir),
            message=f"Investigation created: {metadata.title}",
            details={
                "title": metadata.title,
                "case_number": metadata.case_number,
                "examiner": metadata.examiner,
                "organization": metadata.organization,
                "vault_encryption_enabled": encryption_config.enabled,
            },
        )

        print("Investigation created")
        print(f"Case directory: {get_case_dir(args.case_dir)}")
        print(f"Title: {metadata.title}")
        print(f"Vault encryption: {'enabled' if encryption_config.enabled else 'disabled'}")


def cmd_show_investigation(args):
    db_path = get_case_db_path(args.case_dir)

    with get_session(db_path) as session:
        repo = InvestigationMetadataRepository(session)
        metadata = repo.get()
        encryption_config = ProjectEncryptionRepository(session).get_config()

        if metadata is None:
            print("Investigation metadata not found")
            return

        print(f"Case directory: {get_case_dir(args.case_dir)}")
        print(f"Title: {metadata.title}")
        print(f"Status: {metadata.status.value}")
        print(f"Description: {metadata.description}")
        print(f"Examiner: {metadata.examiner}")
        print(f"Organization: {metadata.organization}")
        print(f"Case number: {metadata.case_number}")
        print(f"Created at: {metadata.created_at}")
        print(f"Updated at: {metadata.updated_at}")
        print(f"Vault encryption: {'enabled' if encryption_config.enabled else 'disabled'}")
        audit_success(
            session,
            "investigation_shown",
            interface="cli",
            target_type="project",
            target_path=get_case_dir(args.case_dir),
            message="Investigation metadata shown",
            details={"title": metadata.title, "vault_encryption_enabled": encryption_config.enabled},
        )


def cmd_delete_evidence(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        service = EvidenceService(session, vault_dir)

        result = service.delete_evidence(args.object_id)

        print("Evidence deleted")
        print(f"Evidence object id: {result['object_id']}")
        print(f"Original name: {result['original_name']}")
        print(f"SHA-256: {result['sha256']}")
        print(f"Stored path: {result['stored_path']}")
        print(f"Vault file deleted: {result['file_deleted']}")


def cmd_ingest_file(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        ingestor = FileIngestor(session, vault_dir, encryption_key=get_encryption_key(args))

        evidence_object, artifacts, changed = ingestor.collect_file(
            path=args.path,
            source_name=args.source_name,
        )

        if not changed:
            print("File already exists and was not changed")
            print(f"Evidence object id: {evidence_object.id}")
            print(f"SHA-256: {evidence_object.sha256}")
            return

        print("File ingested")
        print(f"Evidence object id: {evidence_object.id}")
        print(f"Original name: {evidence_object.original_name}")
        print(f"Stored name: {evidence_object.stored_name}")
        print(f"SHA-256: {evidence_object.sha256}")
        print(f"Artifacts created: {len(artifacts)}")


def cmd_ingest_directory(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        ingestor = FileIngestor(session, vault_dir, encryption_key=get_encryption_key(args))

        objects, artifacts, changed_count, skipped_count = ingestor.collect_directory(
            path=args.path,
            source_name=args.source_name,
        )

        print("Directory ingested")
        print(f"Files found: {len(objects)}")
        print(f"Files added or updated: {changed_count}")
        print(f"Files skipped: {skipped_count}")
        print(f"Artifacts created: {len(artifacts)}")


def cmd_ingest_log(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        ingestor = LinuxLogIngestor(session, vault_dir, encryption_key=get_encryption_key(args))

        evidence_object, artifacts, changed = ingestor.collect(
            path=args.path,
            log_type=args.log_type,
            year=args.year,
            source_name=args.source_name,
        )

        if not changed:
            print("Log already exists and was not changed")
            print(f"Evidence object id: {evidence_object.id}")
            print(f"SHA-256: {evidence_object.sha256}")
            return

        print("Linux log ingested")
        print(f"Log type: {args.log_type}")
        print(f"Evidence object id: {evidence_object.id}")
        print(f"Original name: {evidence_object.original_name}")
        print(f"Stored name: {evidence_object.stored_name}")
        print(f"SHA-256: {evidence_object.sha256}")
        print(f"Artifacts found: {len(artifacts)}")


def cmd_verify_file(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        verifier = FileVerifier(session, vault_dir, encryption_key=get_encryption_key(args))

        result, artifact = verifier.verify_object(args.object_id)

        print(f"Evidence object id: {result['object_id']}")
        print(f"File: {result['original_name']}")
        print(f"Original status: {result['original_check']['status']}")
        print(f"Stored status: {result['stored_check']['status']}")

        if result["is_modified"]:
            print("Result: modified or missing")

            if artifact is not None:
                print(f"Modification artifact created: id={artifact.id}")

            refresh_result = result["refresh_result"]

            if refresh_result["status"] == "refreshed":
                print("Vault updated with current file version")
                print(f"New SHA-256: {refresh_result['new_sha256']}")
            else:
                print("Vault was not updated")
                print(f"Reason: {refresh_result['reason']}")
        else:
            print("Result: not modified")


def cmd_verify_files(args):
    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    if args.object_type == "all":
        object_type = None
    else:
        object_type = EvidenceObjectType(args.object_type)

    with get_session(db_path) as session:
        verifier = FileVerifier(session, vault_dir, encryption_key=get_encryption_key(args))

        results, artifacts = verifier.verify_all(object_type=object_type)

        modified = [r for r in results if r["is_modified"]]
        refreshed = [
            r
            for r in modified
            if r["refresh_result"] is not None
            and r["refresh_result"]["status"] == "refreshed"
        ]

        print(f"Object type filter: {args.object_type}")
        print(f"Objects checked: {len(results)}")
        print(f"Modified or missing: {len(modified)}")
        print(f"Vault refreshed: {len(refreshed)}")
        print(f"Artifacts created: {len(artifacts)}")

        for result in modified:
            print("")
            print(f"Evidence object id: {result['object_id']}")
            print(f"Object type: {result['object_type']}")
            print(f"File: {result['original_name']}")
            print(f"Original status: {result['original_check']['status']}")
            print(f"Stored status: {result['stored_check']['status']}")

            refresh_result = result["refresh_result"]
            if refresh_result["status"] == "refreshed":
                print("Vault updated: yes")
                print(f"New SHA-256: {refresh_result['new_sha256']}")
            else:
                print("Vault updated: no")
                print(f"Reason: {refresh_result['reason']}")


def cmd_ingest_pcap(args):
    from app.ingestion.pcap.pcap_ingestor import PcapIngestor

    db_path = get_case_db_path(args.case_dir)
    vault_dir = get_case_vault_dir(args.case_dir)

    with get_session(db_path) as session:
        ingestor = PcapIngestor(session, vault_dir, encryption_key=get_encryption_key(args))

        evidence_object, artifacts, changed = ingestor.collect(
            path=args.path,
            source_name=args.source_name,
        )

        if not changed:
            print("PCAP already exists and was not changed")
            print(f"Evidence object id: {evidence_object.id}")
            print(f"SHA-256: {evidence_object.sha256}")
            return

        print("PCAP ingested")
        print(f"Evidence object id: {evidence_object.id}")
        print(f"Original name: {evidence_object.original_name}")
        print(f"Stored name: {evidence_object.stored_name}")
        print(f"SHA-256: {evidence_object.sha256}")
        print(f"Artifacts found: {len(artifacts)}")


def cmd_gui(args):
    from app.gui import main as gui_main

    gui_main()


def cmd_report(args):
    db_path = get_case_db_path(args.case_dir)

    with get_session(db_path) as session:
        service = ReportService(session)
        report = service.make_text_report()
        audit_success(
            session,
            "report_generated",
            interface="cli",
            target_type="project",
            target_path=get_case_dir(args.case_dir),
            message="Text report generated",
            details={"report_length_chars": len(report)},
        )

        print(report)


def cmd_journal(args):
    db_path = get_case_db_path(args.case_dir)

    with get_session(db_path) as session:
        repo = AuditLogRepository(session)
        entries = repo.list_filtered(
            action=args.action,
            status=args.status,
            query=args.query,
            limit=args.limit,
        )

        for entry in entries:
            created = entry.created_at.isoformat(sep=" ", timespec="seconds") if entry.created_at else ""
            target = ""
            if entry.target_type or entry.target_id or entry.target_path:
                target = f" target={entry.target_type or ''}:{entry.target_id or ''} {entry.target_path or ''}".rstrip()
            print(
                f"[{created}] {entry.status.upper()} {entry.action}"
                f" actor={entry.actor or ''} interface={entry.interface or ''}{target}"
            )
            if entry.message:
                print(f"  {entry.message}")
            if args.details:
                import json

                print(json.dumps(entry.details_json, ensure_ascii=False, indent=2, default=str))


def _log_cli_failure(args, exc: BaseException) -> None:
    case_dir = getattr(args, "case_dir", None)
    if not case_dir:
        return

    db_path = get_case_db_path(case_dir)
    if not os.path.exists(db_path):
        return

    try:
        with get_session(db_path) as session:
            audit_error(
                session,
                f"cli_{getattr(args, 'command', 'unknown')}_failed",
                exc,
                interface="cli",
                target_type="project",
                target_path=get_case_dir(case_dir),
                message=f"CLI command failed: {getattr(args, 'command', 'unknown')}",
            )
    except Exception:
        # Audit logging must not hide the original error.
        pass


def add_case_dir_argument(parser):
    parser.add_argument(
        "--case-dir",
        default="./investigations/default",
        help="Path to investigation directory",
    )


def build_parser():
    parser = argparse.ArgumentParser(prog="forensic-mvp")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("init-db")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("init-investigation")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("title")
    p.add_argument("--description", default=None)
    p.add_argument("--examiner", default=None)
    p.add_argument("--organization", default=None)
    p.add_argument("--case-number", default=None)
    p.set_defaults(func=cmd_init_investigation)

    p = sub.add_parser("show-investigation")
    add_case_dir_argument(p)
    p.set_defaults(func=cmd_show_investigation)

    p = sub.add_parser("delete-evidence")
    add_case_dir_argument(p)
    p.add_argument("object_id", type=int)
    p.set_defaults(func=cmd_delete_evidence)

    p = sub.add_parser("ingest-file")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("path")
    p.add_argument("--source-name", default=None)
    p.set_defaults(func=cmd_ingest_file)

    p = sub.add_parser("ingest-directory")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("path")
    p.add_argument("--source-name", default=None)
    p.set_defaults(func=cmd_ingest_directory)

    p = sub.add_parser("verify-file")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("object_id", type=int)
    p.set_defaults(func=cmd_verify_file)

    p = sub.add_parser("verify-files")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument(
        "--object-type",
        default="file",
        choices=["file", "log", "pcap", "all"],
        help="Which evidence objects should be verified",
    )
    p.set_defaults(func=cmd_verify_files)

    p = sub.add_parser("ingest-log")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("path")
    p.add_argument(
        "--log-type",
        required=True,
        choices=["auth", "syslog", "kern"],
    )
    p.add_argument("--source-name", default=None)
    p.add_argument("--year", type=int, default=None)
    p.set_defaults(func=cmd_ingest_log)

    p = sub.add_parser("ingest-pcap")
    add_case_dir_argument(p)
    add_encryption_key_argument(p)
    p.add_argument("path")
    p.add_argument("--source-name", default=None)
    p.set_defaults(func=cmd_ingest_pcap)

    p = sub.add_parser("gui")
    p.set_defaults(func=cmd_gui)


    p = sub.add_parser("journal")
    add_case_dir_argument(p)
    p.add_argument("--action", default="all", help="Filter by action")
    p.add_argument("--status", default="all", choices=["all", "success", "error"], help="Filter by status")
    p.add_argument("--query", default=None, help="Search in journal fields")
    p.add_argument("--limit", type=int, default=100, help="Max entries to print")
    p.add_argument("--details", action="store_true", help="Print details_json")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser("report")
    add_case_dir_argument(p)
    p.set_defaults(func=cmd_report)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return

    try:
        args.func(args)
    except Exception as exc:
        _log_cli_failure(args, exc)
        raise


if __name__ == "__main__":
    main()
