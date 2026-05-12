"""
Модуль для парсинга логов аутентификации Linux (обычно /var/log/auth.log или /var/log/secure)
и извлечения артефактов, связанных с событиями входа и привилегированными действиями. Он использует
регулярные выражения для распознавания различных типов событий, таких как неудачные попытки входа,
успешные входы и использование sudo. Артефакты создаются с подробной информацией о событии, включая
имя пользователя, IP-адрес источника, используемый протокол и другие детали.

Failed password       -> ArtifactType.LOGIN_FAILED
Accepted password     -> ArtifactType.LOGIN_SUCCESS
Accepted publickey    -> ArtifactType.LOGIN_SUCCESS
sudo                  -> ArtifactType.PRIVILEGE_EVENT
ssh connection        -> ArtifactType.LOG_ENTRY
su event              -> ArtifactType.PRIVILEGE_EVENT
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

FAILED_LOGIN_RE = re.compile(
    r"Failed password for "
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<username>\S+) "
    r"from (?P<src_ip>\S+) "
    r"port (?P<src_port>\d+) "
    r"(?P<protocol>\S+)"
)

SUCCESS_LOGIN_RE = re.compile(
    r"Accepted (?P<method>password|publickey) "
    r"for (?P<username>\S+) "
    r"from (?P<src_ip>\S+) "
    r"port (?P<src_port>\d+) "
    r"(?P<protocol>\S+)"
)

SUDO_SESSION_RE = re.compile(
    r"pam_unix\(sudo:session\): "
    r"session (?P<action>opened|closed) "
    r"for user (?P<target_user>[^\s\(]+)"
    r"(?:\(uid=(?P<target_uid>\d+)\))?"
    r"(?: by (?P<username>[^\s\(]+)"
    r"(?:\(uid=(?P<uid>\d+)\))?)?"
)

SUDO_RE = re.compile(r"^\s*(?P<username>\S+)\s*:\s*(?P<details>.*COMMAND=.*)$")

SSH_CONNECTION_RE = re.compile(
    r"Connection from (?P<src_ip>\S+) "
    r"port (?P<src_port>\d+)"
    r"(?: on (?P<dst_ip>\S+) port (?P<dst_port>\d+))?"
)

SU_SUCCESS_RE = re.compile(
    r"Successful su for (?P<target_user>\S+) by (?P<username>\S+)"
)

SU_FAILED_RE = re.compile(r"FAILED SU \(to (?P<target_user>\S+)\) (?P<username>\S+)")

SU_SESSION_RE = re.compile(
    r"pam_unix\(su:session\): "
    r"session (?P<action>opened|closed) for user (?P<target_user>\S+)"
    r"(?:\(uid=(?P<target_uid>\d+)\))?"
    r"(?: by (?P<username>\S+)\(uid=(?P<uid>\d+)\))?"
)


class LinuxAuthLogParser:
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

        match = FAILED_LOGIN_RE.search(message)
        if match:
            return self._login_failed(
                evidence_object_id, line, line_number, base, match
            )

        match = SUCCESS_LOGIN_RE.search(message)
        if match:
            return self._login_success(
                evidence_object_id, line, line_number, base, match
            )

        if process == "sudo":
            match = SUDO_RE.search(message)
            if match:
                return self._sudo_event(
                    evidence_object_id, line, line_number, base, match
                )

            match = SUDO_SESSION_RE.search(message)
            if match:
                return self._sudo_session_event(
                    evidence_object_id, line, line_number, base, match
                )

        if process == "sshd":
            match = SSH_CONNECTION_RE.search(message)
            if match:
                return self._ssh_connection(
                    evidence_object_id, line, line_number, base, match
                )

        if process == "su":
            for regex in (SU_SUCCESS_RE, SU_FAILED_RE, SU_SESSION_RE):
                match = regex.search(message)
                if match:
                    return self._su_event(
                        evidence_object_id, line, line_number, base, match
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
        self, month: str, day: str, time_value: str
    ) -> datetime | None:
        value = f"{self.year} {month} {day} {time_value}"

        try:
            dt = datetime.strptime(value, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _login_failed(self, object_id, line, line_number, base, match):
        username = match.group("username")
        src_ip = match.group("src_ip")

        return self._artifact(
            object_id,
            ArtifactType.LOGIN_FAILED,
            f"Failed login for {username} from {src_ip}",
            line,
            line_number,
            base,
            {
                "event": "login_failed",
                "username": username,
                "src_ip": src_ip,
                "src_port": int(match.group("src_port")),
                "protocol": match.group("protocol"),
                "is_invalid_user": match.group("invalid") is not None,
            },
        )

    def _login_success(self, object_id, line, line_number, base, match):
        username = match.group("username")
        src_ip = match.group("src_ip")

        return self._artifact(
            object_id,
            ArtifactType.LOGIN_SUCCESS,
            f"Successful login for {username} from {src_ip}",
            line,
            line_number,
            base,
            {
                "event": "login_success",
                "username": username,
                "src_ip": src_ip,
                "src_port": int(match.group("src_port")),
                "protocol": match.group("protocol"),
                "method": match.group("method"),
            },
        )

    def _sudo_event(self, object_id, line, line_number, base, match):
        username = match.group("username")
        details = self._parse_sudo_details(match.group("details"))
        command = details.get("COMMAND")

        return self._artifact(
            object_id,
            ArtifactType.PRIVILEGE_EVENT,
            f"Sudo command by {username}",
            line,
            line_number,
            base,
            {
                "event": "sudo",
                "username": username,
                "tty": details.get("TTY"),
                "pwd": details.get("PWD"),
                "target_user": details.get("USER"),
                "command": command,
            },
        )

    def _sudo_session_event(self, object_id, line, line_number, base, match):
        action = match.group("action")
        target_user = match.group("target_user")
        username = match.group("username")

        return self._artifact(
            object_id,
            ArtifactType.PRIVILEGE_EVENT,
            f"sudo session {action} for {target_user}",
            line,
            line_number,
            base,
            {
                "event": f"sudo_session_{action}",
                "username": username,
                "target_user": target_user,
                "uid": self._to_int(match.group("uid")),
                "target_uid": self._to_int(match.group("target_uid")),
            },
        )

    def _ssh_connection(self, object_id, line, line_number, base, match):
        src_ip = match.group("src_ip")

        return self._artifact(
            object_id,
            ArtifactType.LOG_ENTRY,
            f"SSH connection from {src_ip}",
            line,
            line_number,
            base,
            {
                "event": "ssh_connection",
                "src_ip": src_ip,
                "src_port": int(match.group("src_port")),
                "dst_ip": match.group("dst_ip"),
                "dst_port": self._to_int(match.group("dst_port")),
            },
        )

    def _su_event(self, object_id, line, line_number, base, match):
        data = match.groupdict()
        event = "su_event"

        if "action" in data and data.get("action"):
            event = f"su_session_{data['action']}"
        elif "target_user" in data and data.get("username"):
            event = "su"

        parsed = {
            "event": event,
            "username": data.get("username"),
            "target_user": data.get("target_user"),
            "uid": self._to_int(data.get("uid")),
            "target_uid": self._to_int(data.get("target_uid")),
        }

        return self._artifact(
            object_id,
            ArtifactType.PRIVILEGE_EVENT,
            "su event",
            line,
            line_number,
            base,
            parsed,
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

    def _parse_sudo_details(self, text: str) -> dict:
        result = {}

        for part in text.split(";"):
            part = part.strip()

            if "=" not in part:
                continue

            key, value = part.split("=", 1)
            result[key.strip()] = value.strip()

        return result

    def _to_int(self, value: str | None) -> int | None:
        if value is None:
            return None

        try:
            return int(value)
        except ValueError:
            return None
