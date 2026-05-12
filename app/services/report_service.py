from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from app.models import Artifact, EvidenceObject
from app.storage.encryption import ProjectEncryptionRepository
from app.storage.repositories import (
    ArtifactRepository,
    EvidenceObjectRepository,
    EvidenceSourceRepository,
    InvestigationMetadataRepository,
)
from app.utils.time import utc_now


class ReportService:
    def __init__(self, session):
        self.metadata_repo = InvestigationMetadataRepository(session)
        self.source_repo = EvidenceSourceRepository(session)
        self.object_repo = EvidenceObjectRepository(session)
        self.artifact_repo = ArtifactRepository(session)
        self.encryption_repo = ProjectEncryptionRepository(session)

    def make_text_report(self) -> str:
        metadata = self.metadata_repo.get()
        sources = self.source_repo.list_all()
        objects = self.object_repo.list_all()
        artifacts = self.artifact_repo.list_all()
        encryption_config = self.encryption_repo.get_config()

        lines = []

        if metadata is not None:
            lines.append(f"Report for investigation: {metadata.title}")
            lines.append(f"Status: {metadata.status.value}")

            if metadata.case_number:
                lines.append(f"Case number: {metadata.case_number}")

            if metadata.examiner:
                lines.append(f"Examiner: {metadata.examiner}")
        else:
            lines.append("Report for investigation")

        lines.append("")
        lines.append(f"Sources: {len(sources)}")
        lines.append(f"Evidence objects: {len(objects)}")
        lines.append(f"Artifacts: {len(artifacts)}")
        lines.append(f"Vault encryption: {'enabled' if encryption_config.enabled else 'disabled'}")
        lines.append("")

        lines.append("Evidence objects:")

        for obj in objects:
            lines.append(
                f"- id: {obj.id}; name: {obj.original_name}; vault: {obj.stored_path}; sha256={obj.sha256}"
            )

        return "\n".join(lines)

    def make_timeline_text_report(
        self,
        *,
        title: str | None = None,
        description: str | None = None,
        artifact_ids: Iterable[int] | None = None,
    ) -> str:
        """Build a plain-text preview for the PDF timeline report."""
        metadata = self.metadata_repo.get()
        objects = self.object_repo.list_all()
        artifacts = self._select_artifacts(artifact_ids)
        encryption_config = self.encryption_repo.get_config()
        objects_by_id = {obj.id: obj for obj in objects if obj.id is not None}
        selected_counts_by_object = self._artifact_counts_by_object(artifacts)

        report_title = title or (f"{metadata.title} - timeline report" if metadata else "Forensic timeline report")
        lines: list[str] = [report_title]
        lines.append(f"Generated at: {self._dt(utc_now())}")
        lines.append("")

        if description:
            lines.append("Description:")
            lines.append(description)
            lines.append("")

        if metadata is not None:
            lines.append("Investigation:")
            lines.append(f"- Title: {metadata.title}")
            lines.append(f"- Status: {metadata.status.value}")
            if metadata.case_number:
                lines.append(f"- Case number: {metadata.case_number}")
            if metadata.examiner:
                lines.append(f"- Examiner: {metadata.examiner}")
            if metadata.organization:
                lines.append(f"- Organization: {metadata.organization}")
            lines.append("")

        lines.append("Summary:")
        lines.append(f"- Evidence objects in project: {len(objects)}")
        lines.append(f"- Artifacts included in timeline: {len(artifacts)}")
        lines.append(f"- Vault encryption: {'enabled' if encryption_config.enabled else 'disabled'}")
        lines.append("")

        lines.append("Evidence Objects:")
        for obj in objects:
            included = selected_counts_by_object.get(obj.id or -1, 0)
            lines.append(
                f"- id={obj.id}; type={obj.object_type.value}; name={obj.original_name}; "
                f"selected_artifacts={included}; sha256={obj.sha256}; path={obj.original_path}"
            )
        lines.append("")

        lines.append("Timeline:")
        if not artifacts:
            lines.append("No artifacts selected.")
        for artifact in artifacts:
            obj = objects_by_id.get(artifact.evidence_object_id)
            lines.append("")
            lines.append(f"[{self._artifact_dt(artifact)}] {artifact.title}")
            lines.append(f"  Artifact: id={artifact.id}; type={artifact.artifact_type.value}")
            lines.append(
                f"  Evidence object: id={artifact.evidence_object_id}; "
                f"name={obj.original_name if obj else 'unknown'}"
            )
            preview = self._artifact_payload_preview(artifact, max_len=900)
            if preview:
                lines.append(f"  Data: {preview}")

        return "\n".join(lines)

    def export_timeline_pdf(
        self,
        output_path: str | Path,
        *,
        title: str | None = None,
        description: str | None = None,
        artifact_ids: Iterable[int] | None = None,
    ) -> dict[str, Any]:
        """Export selected artifacts as a PDF timeline report.

        The PDF contains an investigation summary, an Evidence Objects section,
        and a chronological artifact timeline. `artifact_ids` controls which
        artifacts are included in the timeline; if it is None, all artifacts are
        included. Passing an empty list produces an empty timeline.
        """
        # Lazy imports keep the old text report usable even if reportlab is not
        # installed yet. pyproject.toml declares reportlab for normal installs.
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        metadata = self.metadata_repo.get()
        objects = self.object_repo.list_all()
        artifacts = self._select_artifacts(artifact_ids)
        encryption_config = self.encryption_repo.get_config()
        objects_by_id = {obj.id: obj for obj in objects if obj.id is not None}
        selected_counts_by_object = self._artifact_counts_by_object(artifacts)

        font_name, bold_font_name = self._register_pdf_fonts()
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="ForensicTitle",
                parent=styles["Title"],
                fontName=bold_font_name,
                fontSize=20,
                leading=24,
                alignment=TA_CENTER,
                spaceAfter=8,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ForensicHeading",
                parent=styles["Heading2"],
                fontName=bold_font_name,
                fontSize=13,
                leading=16,
                spaceBefore=10,
                spaceAfter=6,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ForensicBody",
                parent=styles["BodyText"],
                fontName=font_name,
                fontSize=8.5,
                leading=11,
                alignment=TA_LEFT,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ForensicSmall",
                parent=styles["BodyText"],
                fontName=font_name,
                fontSize=7.5,
                leading=9.5,
                alignment=TA_LEFT,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ForensicTableHeader",
                parent=styles["BodyText"],
                fontName=bold_font_name,
                fontSize=7.5,
                leading=9,
                alignment=TA_LEFT,
            )
        )

        report_title = title or (f"{metadata.title} - timeline report" if metadata else "Forensic timeline report")

        def p(text: Any, style_name: str = "ForensicBody") -> Paragraph:
            return Paragraph(self._html(str(text or "")), styles[style_name])

        story: list[Any] = []
        story.append(p(report_title, "ForensicTitle"))
        story.append(p(f"Generated at: {self._dt(utc_now())}", "ForensicBody"))
        story.append(Spacer(1, 5 * mm))

        if description:
            story.append(p("Description", "ForensicHeading"))
            story.append(p(description, "ForensicBody"))
            story.append(Spacer(1, 3 * mm))

        story.append(p("Investigation summary", "ForensicHeading"))
        summary_rows = [
            [p("Field", "ForensicTableHeader"), p("Value", "ForensicTableHeader")],
        ]
        if metadata is not None:
            summary_rows.extend(
                [
                    [p("Title"), p(metadata.title)],
                    [p("Status"), p(metadata.status.value)],
                    [p("Case number"), p(metadata.case_number or "")],
                    [p("Examiner"), p(metadata.examiner or "")],
                    [p("Organization"), p(metadata.organization or "")],
                    [p("Created at"), p(self._dt(metadata.created_at))],
                ]
            )
        summary_rows.extend(
            [
                [p("Evidence objects in project"), p(str(len(objects)))],
                [p("Artifacts included in timeline"), p(str(len(artifacts)))],
                [p("Vault encryption"), p("enabled" if encryption_config.enabled else "disabled")],
            ]
        )
        story.append(self._make_table(summary_rows, [55 * mm, 170 * mm]))

        story.append(p("Evidence Objects", "ForensicHeading"))
        object_rows = [
            [
                p("ID", "ForensicTableHeader"),
                p("Type", "ForensicTableHeader"),
                p("Name", "ForensicTableHeader"),
                p("Size", "ForensicTableHeader"),
                p("Selected artifacts", "ForensicTableHeader"),
                p("SHA-256", "ForensicTableHeader"),
                p("Original path", "ForensicTableHeader"),
            ]
        ]
        for obj in objects:
            object_rows.append(
                [
                    p(obj.id, "ForensicSmall"),
                    p(obj.object_type.value, "ForensicSmall"),
                    p(obj.original_name, "ForensicSmall"),
                    p(str(obj.size_bytes), "ForensicSmall"),
                    p(str(selected_counts_by_object.get(obj.id or -1, 0)), "ForensicSmall"),
                    p(self._shorten(obj.sha256, 28), "ForensicSmall"),
                    p(obj.original_path, "ForensicSmall"),
                ]
            )
        story.append(self._make_table(object_rows, [11 * mm, 20 * mm, 48 * mm, 18 * mm, 26 * mm, 38 * mm, 105 * mm]))

        story.append(PageBreak())
        story.append(p("Artifact timeline", "ForensicHeading"))
        if not artifacts:
            story.append(p("No artifacts selected.", "ForensicBody"))
        else:
            for index, artifact in enumerate(artifacts, start=1):
                obj = objects_by_id.get(artifact.evidence_object_id)
                data_preview = self._artifact_payload_preview(artifact, max_len=1200)
                timeline_rows = [
                    [p("Time", "ForensicTableHeader"), p(self._artifact_dt(artifact), "ForensicSmall")],
                    [p("Artifact", "ForensicTableHeader"), p(f"#{artifact.id} / {artifact.artifact_type.value}", "ForensicSmall")],
                    [p("Title", "ForensicTableHeader"), p(artifact.title, "ForensicSmall")],
                    [
                        p("Evidence object", "ForensicTableHeader"),
                        p(
                            f"#{artifact.evidence_object_id} / {obj.original_name if obj else 'unknown'}",
                            "ForensicSmall",
                        ),
                    ],
                ]
                if data_preview:
                    timeline_rows.append([p("Data", "ForensicTableHeader"), p(data_preview, "ForensicSmall")])

                block = [
                    p(f"{index}. {artifact.title}", "ForensicHeading"),
                    self._make_table(timeline_rows, [30 * mm, 235 * mm]),
                    Spacer(1, 4 * mm),
                ]
                story.append(KeepTogether(block))

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=landscape(A4),
            rightMargin=12 * mm,
            leftMargin=12 * mm,
            topMargin=13 * mm,
            bottomMargin=14 * mm,
            title=report_title,
            author="forensic-mvp",
        )

        def footer(canvas, document):
            canvas.saveState()
            canvas.setFont(font_name, 7)
            canvas.drawString(12 * mm, 7 * mm, f"forensic-mvp / {report_title}")
            canvas.drawRightString(285 * mm, 7 * mm, f"Page {document.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return {
            "path": str(output_path),
            "title": report_title,
            "artifacts_included": len(artifacts),
            "evidence_objects": len(objects),
        }

    def _select_artifacts(self, artifact_ids: Iterable[int] | None) -> list[Artifact]:
        artifacts = self.artifact_repo.list_all()
        if artifact_ids is None:
            selected = artifacts
        else:
            ids = {int(item) for item in artifact_ids}
            selected = [artifact for artifact in artifacts if artifact.id in ids]

        max_dt = datetime.max.replace(tzinfo=timezone.utc)
        return sorted(
            selected,
            key=lambda artifact: (
                artifact.timestamp_start or artifact.timestamp or artifact.created_at or max_dt,
                artifact.id or 0,
            ),
        )

    @staticmethod
    def _artifact_counts_by_object(artifacts: list[Artifact]) -> dict[int, int]:
        counts: dict[int, int] = {}
        for artifact in artifacts:
            counts[artifact.evidence_object_id] = counts.get(artifact.evidence_object_id, 0) + 1
        return counts

    def _make_table(self, rows: list[list[Any]], col_widths: list[float]):
        from reportlab.lib import colors
        from reportlab.platypus import Table, TableStyle

        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#bdbdbd")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return table

    @staticmethod
    def _register_pdf_fonts() -> tuple[str, str]:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        def existing(path: str | None) -> str | None:
            if path and Path(path).is_file():
                return path
            return None

        def fc_match(query: str) -> str | None:
            try:
                result = subprocess.run(
                    ["fc-match", "-f", "%{file}", query],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=1.5,
                )
            except Exception:
                return None
            return existing(result.stdout.strip())

        regular_candidates = [
            existing(os.getenv("FORENSIC_MVP_REPORT_FONT")),
            fc_match("Noto Sans"),
            fc_match("DejaVu Sans"),
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        ]
        bold_candidates = [
            existing(os.getenv("FORENSIC_MVP_REPORT_BOLD_FONT")),
            fc_match("Noto Sans Bold"),
            fc_match("DejaVu Sans Bold"),
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
        ]

        regular = next((path for path in regular_candidates if existing(path)), None)
        bold = next((path for path in bold_candidates if existing(path)), None) or regular

        if not regular:
            # Helvetica is ASCII-oriented but keeps PDF export working on very
            # minimal systems. Ubuntu users should install fonts-noto-core or
            # fonts-dejavu-core for proper Cyrillic output.
            return "Helvetica", "Helvetica-Bold"

        try:
            pdfmetrics.registerFont(TTFont("ForensicSans", regular))
            pdfmetrics.registerFont(TTFont("ForensicSansBold", bold or regular))
            return "ForensicSans", "ForensicSansBold"
        except Exception:
            return "Helvetica", "Helvetica-Bold"

    @staticmethod
    def _html(value: str) -> str:
        return escape(value).replace("\n", "<br/>")

    @staticmethod
    def _dt(value: Any) -> str:
        return value.isoformat(sep=" ", timespec="seconds") if value else ""

    def _artifact_dt(self, artifact: Artifact) -> str:
        return self._dt(artifact.timestamp_start or artifact.timestamp or artifact.created_at) or "no timestamp"

    def _artifact_payload_preview(self, artifact: Artifact, max_len: int = 700) -> str:
        payload = artifact.parsed_data_json or artifact.raw_data_json or {}
        if isinstance(payload, dict):
            priority_keys = [
                "event",
                "username",
                "user",
                "src_ip",
                "dst_ip",
                "domain",
                "host",
                "process",
                "pid",
                "message",
                "method",
                "path",
                "status",
                "protocol",
            ]
            compact = []
            for key in priority_keys:
                if key in payload and payload[key] not in (None, ""):
                    compact.append(f"{key}={payload[key]}")
            if compact:
                value = "; ".join(compact)
            else:
                value = json.dumps(payload, ensure_ascii=False, default=str)
        else:
            value = json.dumps(payload, ensure_ascii=False, default=str)

        return self._shorten(str(value).replace("\n", " "), max_len)

    @staticmethod
    def _shorten(value: str, max_len: int) -> str:
        value = str(value or "")
        if len(value) <= max_len:
            return value
        return value[: max_len - 1] + "…"
