import os

DEFAULT_INVESTIGATIONS_DIR = os.getenv("INVESTIGATIONS_DIR", "./investigations")

CASE_DB_NAME = "case.db"
VAULT_DIR_NAME = "vault"

# Project vault encryption is configured per case in case.db.
# See app/storage/encryption.py.
