"""
Модуль для парсинга системных логов Linux (syslog, journalctl) и извлечения из них артефактов, таких как
события запуска/остановки служб, ошибки демонов, сетевые события и аппаратные/хранительные ошибки.

service start/stop       -> ArtifactType.SERVICE_EVENT
daemon errors            -> ArtifactType.LOG_ENTRY
network events           -> ArtifactType.LOG_ENTRY
system warnings          -> ArtifactType.LOG_ENTRY (отключено)
hardware/storage errors  -> ArtifactType.LOG_ENTRY (отключено)
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


SERVICE_STARTED_RE = re.compile(r"\bStarted\s+(?P<service>.+?)(?:\.|$)")
SERVICE_STOPPED_RE = re.compile(r"\bStopped\s+(?P<service>.+?)(?:\.|$)")

DAEMON_ERROR_RE = re.compile(
    r"\b(error|failed|failure|timeout|crash|exception|segfault)\b",
    re.IGNORECASE,
)

WARNING_RE = re.compile(
    r"\b(warning|warn|deprecated)\b",
    re.IGNORECASE,
)

NETWORK_RE = re.compile(
    r"(NetworkManager|systemd-networkd|dhclient|wpa_supplicant|"
    r"link is up|link is down|carrier|DHCP|IPv6|"
    r"\beth\d+\b|\benp\S+\b|\bwlan\d+\b|\bwlp\S+\b)",
    re.IGNORECASE,
)

HARDWARE_STORAGE_RE = re.compile(
    r"(I/O error|Buffer I/O|EXT4-fs error|XFS.*error|BTRFS.*error|"
    r"filesystem|disk|SMART|nvme|sda|sdb|ata\d+|usb)",
    re.IGNORECASE,
)


class LinuxSyslogParser:
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

        message = base["message"]
        process = base["process"]

        match = SERVICE_STARTED_RE.search(message)
        if match and process == "systemd":
            return self._service_event(
                evidence_object_id,
                line,
                line_number,
                base,
                "service_started",
                match.group("service"),
            )

        match = SERVICE_STOPPED_RE.search(message)
        if match and process == "systemd":
            return self._service_event(
                evidence_object_id,
                line,
                line_number,
                base,
                "service_stopped",
                match.group("service"),
            )

        # if HARDWARE_STORAGE_RE.search(message):
        #     return self._log_event(
        #         evidence_object_id,
        #         line,
        #         line_number,
        #         base,
        #         "hardware_storage_error",
        #         "Hardware/storage error",
        #     )

        if NETWORK_RE.search(line):
            return self._log_event(
                evidence_object_id,
                line,
                line_number,
                base,
                "network_event",
                "Network event",
            )

        # if WARNING_RE.search(message):
        #     return self._log_event(
        #         evidence_object_id,
        #         line,
        #         line_number,
        #         base,
        #         "system_warning",
        #         "System warning",
        #     )

        # if DAEMON_ERROR_RE.search(message):
        #     return self._log_event(
        #         evidence_object_id,
        #         line,
        #         line_number,
        #         base,
        #         "daemon_error",
        #         "Daemon error",
        #     )

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
        self, month: str, day: str, time_value: str
    ) -> datetime | None:
        value = f"{self.year} {month} {day} {time_value}"

        try:
            dt = datetime.strptime(value, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _service_event(
        self,
        evidence_object_id: int,
        line: str,
        line_number: int,
        base: dict,
        event: str,
        service_name: str,
    ) -> Artifact:
        return self._artifact(
            evidence_object_id,
            ArtifactType.SERVICE_EVENT,
            service_name,
            line,
            line_number,
            base,
            {
                "event": event,
                "service_name": service_name,
            },
        )

    def _log_event(
        self,
        evidence_object_id: int,
        line: str,
        line_number: int,
        base: dict,
        event: str,
        title: str,
    ) -> Artifact:
        return self._artifact(
            evidence_object_id,
            ArtifactType.LOG_ENTRY,
            title,
            line,
            line_number,
            base,
            {
                "event": event,
            },
        )

    def _artifact(
        self,
        evidence_object_id: int,
        artifact_type: ArtifactType,
        title: str,
        line: str,
        line_number: int,
        base: dict,
        parsed_data: dict,
    ) -> Artifact:
        parsed_data["host"] = base["host"]
        parsed_data["process"] = base["process"]
        parsed_data["pid"] = base["pid"]

        return Artifact(
            id=None,
            evidence_object_id=evidence_object_id,
            artifact_type=artifact_type,
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
            parsed_data_json=parsed_data,
        )
