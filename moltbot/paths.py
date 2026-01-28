import os
from pathlib import Path
from typing import Iterable


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


def _unique(paths: Iterable[Path]) -> list[Path]:
    seen = set()
    out: list[Path] = []
    for path in paths:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def resolve_state_dir(env: os._Environ[str] | None = None) -> Path:
    env = env or os.environ
    override = env.get("MOLTBOT_STATE_DIR") or env.get("CLAWDBOT_STATE_DIR")
    if override:
        return _expand(override)
    home = Path.home()
    legacy = home / ".clawdbot"
    new = home / ".moltbot"
    if not legacy.exists() and new.exists():
        return new
    return legacy


def resolve_identity_path(env: os._Environ[str] | None = None) -> Path:
    env = env or os.environ
    override = env.get("MOLTBOT_STATE_DIR") or env.get("CLAWDBOT_STATE_DIR")
    candidates: list[Path] = []
    if override:
        candidates.append(_expand(override) / "identity" / "device.json")
    home = Path.home()
    candidates.append(home / ".clawdbot" / "identity" / "device.json")
    candidates.append(home / ".moltbot" / "identity" / "device.json")
    state_dir = resolve_state_dir(env)
    candidates.append(state_dir / "identity" / "device.json")
    for path in _unique(candidates):
        if path.exists():
            return path
    return _unique(candidates)[0]


def resolve_device_auth_path(env: os._Environ[str] | None = None) -> Path:
    env = env or os.environ
    state_dir = resolve_state_dir(env)
    return state_dir / "identity" / "device-auth.json"
