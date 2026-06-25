from __future__ import annotations

import os
import sys
from pathlib import Path


CONFIG_ERROR = (
    "ERROR: ASF_ROOT or ASF_AUDIT_DB must be set. Example:\n"
    "ASF_ROOT=/path/to/agent-security-framework ase-dashboard"
)

ASF_ROOT_ERROR = (
    "ERROR: ASF_ROOT must be set to import ASF modules. Example:\n"
    "ASF_ROOT=/path/to/agent-security-framework python -m suite --target asf"
)


def require_asf_root() -> Path:
    value = os.environ.get("ASF_ROOT")
    if not value:
        raise RuntimeError(ASF_ROOT_ERROR)
    return Path(value).expanduser()


def add_asf_to_sys_path() -> Path:
    root = require_asf_root()
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return root


def resolve_audit_db_path() -> Path:
    audit_db = os.environ.get("ASF_AUDIT_DB")
    if audit_db:
        return Path(audit_db).expanduser()

    root = os.environ.get("ASF_ROOT")
    if root:
        return Path(root).expanduser() / "asf_local.db"

    raise RuntimeError(CONFIG_ERROR)
