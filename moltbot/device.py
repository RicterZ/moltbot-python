import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .paths import resolve_identity_path


@dataclass
class DeviceIdentity:
    device_id: str
    public_key_pem: str
    private_key_pem: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _raw_public_key(public_key_pem: str) -> bytes:
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("expected ed25519 public key")
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _fingerprint(public_key_pem: str) -> str:
    return hashlib.sha256(_raw_public_key(public_key_pem)).hexdigest()


def _load_identity_file(path: Path) -> Optional[DeviceIdentity]:
    try:
        if not path.exists():
            return None
        parsed = json.loads(path.read_text("utf-8"))
        if (
            isinstance(parsed, dict)
            and parsed.get("version") == 1
            and isinstance(parsed.get("deviceId"), str)
            and isinstance(parsed.get("publicKeyPem"), str)
            and isinstance(parsed.get("privateKeyPem"), str)
        ):
            device_id = parsed["deviceId"]
            public_key_pem = parsed["publicKeyPem"]
            private_key_pem = parsed["privateKeyPem"]
            derived = _fingerprint(public_key_pem)
            if derived != device_id:
                stored = {
                    **parsed,
                    "deviceId": derived,
                }
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                return DeviceIdentity(
                    device_id=derived,
                    public_key_pem=public_key_pem,
                    private_key_pem=private_key_pem,
                )
            return DeviceIdentity(
                device_id=device_id,
                public_key_pem=public_key_pem,
                private_key_pem=private_key_pem,
            )
    except Exception:
        return None
    return None


def _write_identity_file(path: Path, identity: DeviceIdentity) -> None:
    stored = {
        "version": 1,
        "deviceId": identity.device_id,
        "publicKeyPem": identity.public_key_pem,
        "privateKeyPem": identity.private_key_pem,
        "createdAtMs": int(time.time() * 1000),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stored, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_or_create_identity(path: Path | None = None) -> DeviceIdentity:
    resolved_path = path or resolve_identity_path()
    loaded = _load_identity_file(resolved_path)
    if loaded:
        return loaded

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    device_id = _fingerprint(public_key_pem)
    identity = DeviceIdentity(
        device_id=device_id,
        public_key_pem=public_key_pem,
        private_key_pem=private_key_pem,
    )
    _write_identity_file(resolved_path, identity)
    return identity


def public_key_base64url(identity: DeviceIdentity) -> str:
    return _b64url(_raw_public_key(identity.public_key_pem))


def sign_payload(identity: DeviceIdentity, payload: str) -> str:
    private_key = serialization.load_pem_private_key(
        identity.private_key_pem.encode(),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("expected ed25519 private key")
    signature = private_key.sign(payload.encode())
    return _b64url(signature)
