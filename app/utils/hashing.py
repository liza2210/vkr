import hashlib
from pathlib import Path


def _file_hash(path: str, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: str) -> str:
    return _file_hash(path, "sha256")


def md5_file(path: str) -> str:
    return _file_hash(path, "md5")


def file_size(path: str) -> int:
    return Path(path).stat().st_size
