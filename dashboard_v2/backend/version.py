from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 compatibility
    tomllib = None  # type: ignore[assignment]


DASHBOARD_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = DASHBOARD_ROOT.parent
DEFAULT_SEMVER = "0.0.0"


def _normalize_semver(value: str | None) -> str | None:
    version = (value or "").strip()
    if not version:
        return None
    if version.lower().startswith("asf v"):
        version = version[5:]
    elif version.lower().startswith("v"):
        version = version[1:]
    return version.strip() or None


def _read_pyproject_version(path: Path) -> str | None:
    if tomllib is None or not path.exists():
        return None
    try:
        with path.open("rb") as fh:
            data: dict[str, Any] = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if isinstance(project, dict):
        version = _normalize_semver(project.get("version"))
        if version:
            return version
    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        return _normalize_semver(poetry.get("version"))
    return None


def _read_package_json_version(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        return _normalize_semver(data.get("version"))
    return None


def _read_version_file(path: Path) -> str | None:
    try:
        return _normalize_semver(path.read_text())
    except OSError:
        return None


@lru_cache(maxsize=1)
def get_asf_semver() -> str:
    for root in (DASHBOARD_ROOT, PROJECT_ROOT):
        version = _read_pyproject_version(root / "pyproject.toml")
        if version:
            return version
        version = _read_package_json_version(root / "package.json")
        if version:
            return version
    return _read_version_file(DASHBOARD_ROOT / "VERSION") or DEFAULT_SEMVER


@lru_cache(maxsize=1)
def get_short_git_hash() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(DASHBOARD_ROOT),
            timeout=2,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


@lru_cache(maxsize=1)
def get_asf_version() -> str:
    semver = get_asf_semver()
    git_hash = get_short_git_hash()
    if git_hash:
        return f"ASF v{semver}-{git_hash}"
    return f"ASF v{semver}"


def get_asf_version_info() -> dict[str, str]:
    git_hash = get_short_git_hash()
    return {
        "version": get_asf_semver(),
        "git_hash": git_hash or "unknown",
        "asf_version": get_asf_version(),
    }
