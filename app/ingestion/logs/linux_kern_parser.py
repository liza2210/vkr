"""
Модуль для парсинга логов ядра Linux (обычно /var/log/kern.log или /var/log/messages) с целью извлечения событий,
связанных с ошибками файловой системы, проблемами оборудования, сетевыми событиями и другими важными сообщениями ядра.
"""

import re
from datetime import datetime, timezone

from app.core.enums import ArtifactType
from app.models import Artifact

ISO_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?):\s+"
    r"(?P<message>.*)$"
)

OLD_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?):\s+"
    r"(?P<message>.*)$"
)

KERNEL_PREFIX_RE = re.compile(r"^\[\s*\d+\.\d+\]\s*")

USB_RE = re.compile(
    r"\b(usb|USB device|new .*USB|USB disconnect|Mass Storage)\b",
    re.IGNORECASE,
)

NETWORK_RE = re.compile(
    r"(link is up|link is down|renamed from|NIC Link|"
    r"\beth\d+\b|\benp\S+\b|\bwlan\d+\b|\bwlp\S+\b|"
    r"iwlwifi|r8169|e1000e|IPv6: ADDRCONF)",
    re.IGNORECASE,
)

FILESYSTEM_RE = re.compile(
    r"(EXT4-fs error|XFS.*error|BTRFS.*error|filesystem error|"
    r"fsck|journal has aborted)",
    re.IGNORECASE,
)

STORAGE_RE = re.compile(
    r"(I/O error|Buffer I/O|blk_update_request|sector \d+|"
    r"\bsda\b|\bsdb\b|\bnvme\d+n\d+\b|ata\d+|SMART|disk error)",
    re.IGNORECASE,
)

WARNING_RE = re.compile(
    r"\b(warning|warn|tainted)\b",
    re.IGNORECASE,
)

ERROR_RE = re.compile(
    r"\b(error|failed|failure|critical|unable|BUG|Oops)\b",
    re.IGNORECASE,
)

HARDWARE_RE = re.compile(
    r"\b(ACPI|BIOS|firmware|thermal|temperature|CPU|GPU|battery)\b",
    re.IGNORECASE,
)


class LinuxKernLogParser:
    def __init__(self, year: int | None = None):
        self.year = year or datetime.now(timezone.utc).year

    def parse_file(self, file_path: str, evidence_object_id: int) -> list[Artifact]:
        artifacts = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                artifact = self.parse_line(
                    line=line.strip(),
                    line_number=line_number,
                    evidence_object_id=evidence_object_id,
                )

                if artifact is not None:
                    artifacts.append(artifact)

        return artifacts

    def parse_line(
        self,
        line: str,
        line_number: int,
        evidence_object_id: int,
    ) -> Artifact | None:
        base = self._parse_syslog_line(line)

        if base is None:
            return None

        message = self._clean_kernel_message(base["message"])

        if FILESYSTEM_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "filesystem_error",
                "Filesystem error",
            )

        if STORAGE_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "storage_error",
                "Storage error",
            )

        if USB_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "usb_event",
                "USB/device event",
            )

        if NETWORK_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "network_event",
                "Kernel network event",
            )

        if ERROR_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "kernel_error",
                "Kernel error",
            )

        if WARNING_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "kernel_warning",
                "Kernel warning",
            )

        if HARDWARE_RE.search(message):
            return self._event(
                evidence_object_id,
                line,
                line_number,
                base,
                "hardware_event",
                "Hardware event",
            )

        return None

    def _parse_syslog_line(self, line: str) -> dict | None:
        match = ISO_SYSLOG_RE.match(line)

        if match:
            data = match.groupdict()
            process, pid = self._parse_process(data["process"])

            return {
                "timestamp": self._parse_iso_timestamp(data["timestamp"]),
                "host": data["host"],
                "process": process,
                "pid": pid,
                "message": data["message"],
            }

        match = OLD_SYSLOG_RE.match(line)

        if match:
            data = match.groupdict()
            process, pid = self._parse_process(data["process"])

            return {
                "timestamp": self._parse_old_timestamp(
                    data["month"],
                    data["day"],
                    data["time"],
                ),
                "host": data["host"],
                "process": process,
                "pid": pid,
                "message": data["message"],
            }

        return None

    def _parse_process(self, value: str) -> tuple[str, int | None]:
        value = value.strip()

        match = re.match(r"^(?P<name>[^\[]+)\[(?P<pid>\d+)\]$", value)

        if not match:
            return value, None

        return match.group("name"), int(match.group("pid"))

    def _parse_iso_timestamp(self, value: str) -> datetime | None:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _parse_old_timestamp(
        self,
        month: str,
        day: str,
        time_value: str,
    ) -> datetime | None:
        value = f"{self.year} {month} {day} {time_value}"

        try:
            dt = datetime.strptime(value, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _clean_kernel_message(self, message: str) -> str:
        return KERNEL_PREFIX_RE.sub("", message)

    def _event(
        self,
        evidence_object_id: int,
        line: str,
        line_number: int,
        base: dict,
        event: str,
        title: str,
    ) -> Artifact:
        message = self._clean_kernel_message(base["message"])

        return Artifact(
            id=None,
            evidence_object_id=evidence_object_id,
            artifact_type=ArtifactType.LOG_ENTRY,
            timestamp=base["timestamp"],
            title=title,
            raw_data_json={
                "line": line,
                "line_number": line_number,
                "host": base["host"],
                "process": base["process"],
                "pid": base["pid"],
                "message": base["message"],
            },
            parsed_data_json={
                "event": event,
                "host": base["host"],
                "process": base["process"],
                "pid": base["pid"],
                "message": message,
            },
        )
