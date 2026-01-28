import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .paths import resolve_device_auth_path


@dataclass
class DeviceAuthEntry:
    token: str
    role: str
    scopes: list[str]
    updated_at_ms: int


def _normalize_role(role: str) -> str:
    return role.strip()


def _normalize_scopes(scopes: list[str] | None) -> list[str]:
    if not scopes:
        return []
    normalized = sorted({scope.strip() for scope in scopes if scope.strip()})
    return normalized


def _read_store(path: Path) -> Optional[dict]:
    try:
        if not path.exists():
            return None
        parsed = json.loads(path.read_text("utf-8"))
        if not isinstance(parsed, dict) or parsed.get("version") != 1:
            return None
        if not isinstance(parsed.get("deviceId"), str):
            return None
        tokens = parsed.get("tokens")
        if not isinstance(tokens, dict):
            return None
        return parsed
    except Exception:
        return None


def _write_store(path: Path, store: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_device_token(
    device_id: str, role: str, env: os._Environ[str] | None = None
) -> Optional[DeviceAuthEntry]:
    path = resolve_device_auth_path(env)
    store = _read_store(path)
    if not store or store.get("deviceId") != device_id:
        return None
    role_key = _normalize_role(role)
    raw_entry = store.get("tokens", {}).get(role_key)
    if not isinstance(raw_entry, dict):
        return None
    token = raw_entry.get("token")
    if not isinstance(token, str) or not token:
        return None
    scopes = raw_entry.get("scopes")
    scopes_list = scopes if isinstance(scopes, list) else []
    return DeviceAuthEntry(
        token=token,
        role=role_key,
        scopes=_normalize_scopes([str(scope) for scope in scopes_list]),
        updated_at_ms=int(raw_entry.get("updatedAtMs") or raw_entry.get("updated_at_ms") or 0),
    )


def store_device_token(
    device_id: str,
    role: str,
    token: str,
    scopes: list[str] | None = None,
    env: os._Environ[str] | None = None,
) -> DeviceAuthEntry:
    path = resolve_device_auth_path(env)
    existing = _read_store(path)
    normalized_role = _normalize_role(role)
    next_store = (
        existing
        if existing and existing.get("deviceId") == device_id and isinstance(existing.get("tokens"), dict)
        else {"version": 1, "deviceId": device_id, "tokens": {}}
    )
    entry = DeviceAuthEntry(
        token=token,
        role=normalized_role,
        scopes=_normalize_scopes(scopes),
        updated_at_ms=int(time.time() * 1000),
    )
    next_store["tokens"][normalized_role] = {
        "token": entry.token,
        "role": entry.role,
        "scopes": entry.scopes,
        "updatedAtMs": entry.updated_at_ms,
    }
    _write_store(path, next_store)
    return entry


def clear_device_token(
    device_id: str, role: str, env: os._Environ[str] | None = None
) -> None:
    path = resolve_device_auth_path(env)
    store = _read_store(path)
    if not store or store.get("deviceId") != device_id:
        return
    tokens = store.get("tokens") or {}
    role_key = _normalize_role(role)
    if role_key not in tokens:
        return
    next_store = {
        "version": 1,
        "deviceId": store["deviceId"],
        "tokens": {k: v for k, v in tokens.items() if k != role_key},
    }
    _write_store(path, next_store)
