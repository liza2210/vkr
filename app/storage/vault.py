import hashlib
import shutil
import uuid
from pathlib import Path

from app.errors import EncryptionError
from app.storage.encryption import ProjectEncryptionConfig, make_fernet


class Vault:
    def __init__(
        self,
        base_dir: Path,
        encryption_key: str | None = None,
        encryption_config: ProjectEncryptionConfig | None = None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.encryption_key = encryption_key
        self.encryption_config = encryption_config or ProjectEncryptionConfig(enabled=False)

    @property
    def is_encrypted(self) -> bool:
        return self.encryption_config.enabled

    def save_file(self, source_file: str) -> tuple[str, str]:
        src = Path(source_file)

        suffix = src.suffix.lower()
        if self.is_encrypted:
            suffix = f"{suffix}.enc" if suffix else ".enc"

        stored_name = f"{uuid.uuid4().hex}{suffix}"
        dst = self.base_dir / stored_name

        if self.is_encrypted:
            encrypted = self._cipher().encrypt(src.read_bytes())
            dst.write_bytes(encrypted)
            try:
                shutil.copystat(src, dst)
            except OSError:
                pass
        else:
            shutil.copy2(src, dst)

        return str(dst), stored_name

    def delete_file(self, path: str) -> bool:
        file_path = Path(path).resolve()

        if not self._is_inside_vault(file_path):
            return False

        if not file_path.exists():
            return False

        if not file_path.is_file():
            return False

        file_path.unlink()
        return True

    def stored_plaintext_bytes(self, path: str) -> bytes:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(path)

        data = file_path.read_bytes()
        if not self.is_encrypted:
            return data

        try:
            return self._cipher().decrypt(data)
        except Exception as exc:
            raise EncryptionError("Не удалось расшифровать файл vault. Проверьте ключ") from exc

    def stored_plaintext_sha256(self, path: str) -> str:
        data = self.stored_plaintext_bytes(path)
        return hashlib.sha256(data).hexdigest()

    def stored_plaintext_size(self, path: str) -> int:
        return len(self.stored_plaintext_bytes(path))

    def _cipher(self):
        if not self.encryption_key:
            raise EncryptionError("Проект зашифрован. Укажите ключ шифрования")
        return make_fernet(self.encryption_key, self.encryption_config)

    def _is_inside_vault(self, file_path: Path) -> bool:
        try:
            file_path.relative_to(self.base_dir)
            return True
        except ValueError:
            return False
