"""Project-level encryption helpers for vault files.

The MVP stores only encryption metadata in SQLite. The user key is never saved.
When encryption is enabled, vault files are encrypted with a key derived from the
user-provided text key via PBKDF2-HMAC-SHA256 and Fernet.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from app.errors import EncryptionError

try:  # Keep non-GUI / non-encrypted CLI commands importable if dependency is absent.
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _CRYPTOGRAPHY_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - depends on user environment.
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment]
    PBKDF2HMAC = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    _CRYPTOGRAPHY_IMPORT_ERROR = exc


ENCRYPTION_VERSION = "1"
KDF_NAME = "pbkdf2-sha256"
DEFAULT_ITERATIONS = 390_000
KEY_CHECK_PLAINTEXT = b"forensic-mvp-vault-key-check-v1"


@dataclass(frozen=True)
class ProjectEncryptionConfig:
    enabled: bool
    version: str = ENCRYPTION_VERSION
    kdf: str = KDF_NAME
    iterations: int = DEFAULT_ITERATIONS
    salt_b64: str | None = None
    key_check_token: str | None = None

    @property
    def salt(self) -> bytes | None:
        if not self.salt_b64:
            return None
        return base64.b64decode(self.salt_b64.encode("ascii"))


class ProjectEncryptionRepository:
    """Stores and validates project encryption settings in SQLite."""

    def __init__(self, conn):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

    def get_config(self) -> ProjectEncryptionConfig:
        enabled_raw = self._get("encryption.enabled")

        # Backward compatibility: old projects have no encryption settings.
        if enabled_raw is None:
            return ProjectEncryptionConfig(enabled=False)

        enabled = enabled_raw == "1"
        if not enabled:
            return ProjectEncryptionConfig(enabled=False)

        return ProjectEncryptionConfig(
            enabled=True,
            version=self._get("encryption.version") or ENCRYPTION_VERSION,
            kdf=self._get("encryption.kdf") or KDF_NAME,
            iterations=int(self._get("encryption.iterations") or DEFAULT_ITERATIONS),
            salt_b64=self._get("encryption.salt_b64"),
            key_check_token=self._get("encryption.key_check_token"),
        )

    def configure(self, encryption_key: str | None) -> ProjectEncryptionConfig:
        """Configure encryption for a new/empty project.

        Reconfiguration is intentionally allowed only while there are no evidence
        objects yet. This is enough for the educational project and prevents a
        mixed vault with both encrypted and plaintext files.
        """

        requested_enabled = bool(encryption_key)
        existing_enabled_raw = self._get("encryption.enabled")

        if existing_enabled_raw is not None:
            existing = self.get_config()
            # No key means "keep current project mode" for already configured projects.
            if encryption_key is None:
                return existing
            if existing.enabled == requested_enabled:
                if existing.enabled and encryption_key and not self.verify_key(encryption_key):
                    raise EncryptionError("Указан неверный ключ шифрования проекта")
                return existing

            if not self._project_has_no_objects():
                raise EncryptionError(
                    "Нельзя изменить режим шифрования: в проекте уже есть evidence objects"
                )

            self._clear_encryption_settings()

        if not requested_enabled:
            self._set("encryption.enabled", "0")
            self._set("encryption.version", ENCRYPTION_VERSION)
            return ProjectEncryptionConfig(enabled=False)

        assert encryption_key is not None
        self._ensure_crypto_available()

        salt = os.urandom(16)
        config = ProjectEncryptionConfig(
            enabled=True,
            version=ENCRYPTION_VERSION,
            kdf=KDF_NAME,
            iterations=DEFAULT_ITERATIONS,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            key_check_token=None,
        )
        token = make_fernet(encryption_key, config).encrypt(KEY_CHECK_PLAINTEXT).decode("ascii")

        self._set("encryption.enabled", "1")
        self._set("encryption.version", config.version)
        self._set("encryption.kdf", config.kdf)
        self._set("encryption.iterations", str(config.iterations))
        self._set("encryption.salt_b64", config.salt_b64 or "")
        self._set("encryption.key_check_token", token)

        return ProjectEncryptionConfig(
            enabled=True,
            version=config.version,
            kdf=config.kdf,
            iterations=config.iterations,
            salt_b64=config.salt_b64,
            key_check_token=token,
        )

    def verify_key(self, encryption_key: str | None) -> bool:
        config = self.get_config()
        if not config.enabled:
            return True
        if not encryption_key:
            return False
        if not config.key_check_token:
            return False

        self._ensure_crypto_available()
        try:
            plaintext = make_fernet(encryption_key, config).decrypt(
                config.key_check_token.encode("ascii")
            )
        except InvalidToken:
            return False
        return plaintext == KEY_CHECK_PLAINTEXT

    def require_valid_key(self, encryption_key: str | None) -> None:
        config = self.get_config()
        if not config.enabled:
            return
        if not encryption_key:
            raise EncryptionError("Проект зашифрован. Укажите ключ шифрования")
        if not self.verify_key(encryption_key):
            raise EncryptionError("Указан неверный ключ шифрования проекта")

    def _get(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM project_settings WHERE key = ?",
            (key,),
        ).fetchone()
        return row["value"] if row else None

    def _set(self, key: str, value: str) -> None:
        self.conn.execute(
            """
            INSERT INTO project_settings(key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _clear_encryption_settings(self) -> None:
        self.conn.execute("DELETE FROM project_settings WHERE key LIKE 'encryption.%'")

    def _project_has_no_objects(self) -> bool:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM evidence_objects").fetchone()
        return int(row["count"]) == 0

    @staticmethod
    def _ensure_crypto_available() -> None:
        if _CRYPTOGRAPHY_IMPORT_ERROR is not None:
            raise EncryptionError(
                "Для шифрования нужна зависимость cryptography. "
                "Установите зависимости через uv sync или pip install cryptography"
            ) from _CRYPTOGRAPHY_IMPORT_ERROR


def make_fernet(encryption_key: str, config: ProjectEncryptionConfig):
    ProjectEncryptionRepository._ensure_crypto_available()

    if not config.enabled:
        raise EncryptionError("Шифрование проекта выключено")
    if config.kdf != KDF_NAME:
        raise EncryptionError(f"Неподдерживаемый KDF: {config.kdf}")
    if not config.salt:
        raise EncryptionError("В проекте нет salt для шифрования")

    key_bytes = encryption_key.encode("utf-8")
    kdf = PBKDF2HMAC(  # type: ignore[misc]
        algorithm=hashes.SHA256(),  # type: ignore[union-attr]
        length=32,
        salt=config.salt,
        iterations=config.iterations,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    return Fernet(derived_key)  # type: ignore[operator]
