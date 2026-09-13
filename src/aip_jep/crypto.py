"""Ed25519 signatures for the versioned AIP sidecar receipt envelope.

The legacy sorted-ASCII JSON encoding is retained; this is not JEP-Core JCS/JWS.
"""

import base64
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_uuid7() -> str:
    ms = int(time.time() * 1000)
    rand = os.urandom(10)
    part_a = 0x7000 | (int.from_bytes(rand[:2], "big") & 0x0FFF)
    part_b = 0x8000000000000000 | (int.from_bytes(rand[2:], "big") & 0x3FFFFFFFFFFFFFFF)
    return f"{ms >> 16:08x}-{ms & 0xFFFF:04x}-{part_a:04x}-{part_b >> 48:04x}-{part_b & 0xFFFFFFFFFFFF:012x}"


def canonical_payload(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Expected unpadded base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(raw) != value:
        raise ValueError("Non-canonical base64url")
    return raw


def key_id(raw_public_key: bytes) -> str:
    return "jep-key-" + hashlib.sha256(raw_public_key).hexdigest()


class JEPAsymmetricSigner:
    def __init__(self, private_key_hex: Optional[str] = None):
        self._private_key = (
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
            if private_key_hex is not None
            else ed25519.Ed25519PrivateKey.generate()
        )
        self._public_key = self._private_key.public_key()

    def get_public_key_jwk(self) -> Dict[str, str]:
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(raw),
            "kid": key_id(raw),
            "alg": "Ed25519",
            "use": "sig",
        }

    def sign_payload(self, data: Dict[str, Any]) -> str:
        return "ed25519:" + b64(self._private_key.sign(canonical_payload(data)))

    def export_private_key(self) -> str:
        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()


def verify_payload(
    data: Dict[str, Any], signature: str, trusted_jwk: Dict[str, Any]
) -> bool:
    """Verify integrity using a caller-trusted key; this does not grant authority."""
    try:
        if (
            not isinstance(trusted_jwk, dict)
            or trusted_jwk.get("kty") != "OKP"
            or trusted_jwk.get("crv") != "Ed25519"
        ):
            return False
        if (
            trusted_jwk.get("alg", "Ed25519") != "Ed25519"
            or trusted_jwk.get("use", "sig") != "sig"
        ):
            return False
        if "key_ops" in trusted_jwk:
            ops = trusted_jwk["key_ops"]
            if (
                not isinstance(ops, list)
                or not all(isinstance(op, str) for op in ops)
                or len(ops) != len(set(ops))
                or "verify" not in ops
            ):
                return False
        raw = decode(trusted_jwk["x"])
        if (
            len(raw) != 32
            or trusted_jwk.get("kid") != key_id(raw)
            or data.get("key_id") != trusted_jwk["kid"]
        ):
            return False
        if not isinstance(signature, str) or not signature.startswith("ed25519:"):
            return False
        ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(
            decode(signature[8:]), canonical_payload(data)
        )
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False


def compute_content_hash(data: Any) -> str:
    return hashlib.sha256(canonical_payload(data)).hexdigest()
