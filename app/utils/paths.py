from pathlib import Path

from app.settings import CASE_DB_NAME, DEFAULT_INVESTIGATIONS_DIR, VAULT_DIR_NAME


def get_case_dir(case_dir: str | None = None) -> Path:
    if case_dir is None:
        return Path(DEFAULT_INVESTIGATIONS_DIR) / "default"

    return Path(case_dir)


def get_case_db_path(case_dir: str | None = None) -> str:
    path = get_case_dir(case_dir)
    path.mkdir(parents=True, exist_ok=True)

    return str(path / CASE_DB_NAME)


def get_case_vault_dir(case_dir: str | None = None) -> Path:
    path = get_case_dir(case_dir)
    vault_dir = path / VAULT_DIR_NAME
    vault_dir.mkdir(parents=True, exist_ok=True)

    return vault_dir
