from __future__ import annotations

import os
from pathlib import Path


CONFIG_ERROR = (
    "ERROR: ASF_ROOT or ASF_AUDIT_DB must be set. Example:\n"
    "ASF_ROOT=/path/to/agent-security-framework ase-dashboard"
)

ASF_ROOT_ERROR = (
    "ERROR: ASF_ROOT must be set to import ASF modules. Example:\n"
    "ASF_ROOT=/path/to/agent-security-framework ase-dashboard"
)


def require_asf_root() -> Path:
    value = os.environ.get("ASF_ROOT")
    if not value:
        raise RuntimeError(ASF_ROOT_ERROR)
    return Path(value).expanduser()


def resolve_audit_db_path() -> Path:
    audit_db = os.environ.get("ASF_AUDIT_DB")
    if audit_db:
        return Path(audit_db).expanduser()

    root = os.environ.get("ASF_ROOT")
    if root:
        return Path(root).expanduser() / "asf_local.db"

    raise RuntimeError(CONFIG_ERROR)
