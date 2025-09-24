from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from cryptography.fernet import Fernet


_FERNET: Fernet | None = None


def _load_or_create_key() -> bytes:
    env_key = os.getenv("CM_ENCRYPTION_KEY")
    if env_key:
        try:
            # If provided as base64 urlsafe (standard Fernet), use directly
            return env_key.encode("utf-8")
        except Exception as e:  # pragma: no cover
            raise RuntimeError("Invalid CM_ENCRYPTION_KEY provided") from e

    # Fallback to local file for dev envs
    key_path = Path(".secrets/fernet.key")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    return key


def _get_fernet() -> Fernet:
    global _FERNET
    if _FERNET is None:
        _FERNET = Fernet(_load_or_create_key())
    return _FERNET


def encrypt_dict(data: Dict[str, Any]) -> str:
    token = _get_fernet().encrypt(json.dumps(data).encode("utf-8"))
    return token.decode("utf-8")


def decrypt_dict(token: str) -> Dict[str, Any]:
    raw = _get_fernet().decrypt(token.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))
