import os
import time
import json
import base64
import hashlib
from typing import Dict, Any, Tuple, Optional

# 注意：生产环境建议安装 cryptography 库
# pip install cryptography
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

def generate_uuid7() -> str:
    """
    Generate a RFC 9562 compliant UUIDv7.
    Provides time-ordered, collision-resistant identifiers for HJS audit trails.
    """
    # 1. 48-bit Unix timestamp (milliseconds)
    ms = int(time.time() * 1000)
    
    # 2. 10 bytes of randomness
    rand_bytes = os.urandom(10)
    
    # 3. Bit manipulation for Version 7 and Variant 2
    # Part A: Version 7 (0111) + 12 bits randomness
    rand_a = int.from_bytes(rand_bytes[:2], 'big') & 0x0FFF
    part_a = 0x7000 | rand_a
    
    # Part B: Variant 2 (10xx) + 62 bits randomness
    rand_b = int.from_bytes(rand_bytes[2:], 'big')
    part_b = (0x8000000000000000 | (rand_b & 0x3FFFFFFFFFFFFFFF))
    
    # 4. Format: 8-4-4-4-12
    return f"{ms >> 16:08x}-{(ms & 0xFFFF):04x}-{part_a:04x}-{(part_b >> 48):04x}-{(part_b & 0xFFFFFFFFFFFF):012x}"

class HJSAsymmetricSigner:
    """
    Ed25519 Multi-channel Signer for HJS Receipts.
    Allows third-party public verification without sharing secrets.
    """
    def __init__(self, private_key_hex: Optional[str] = None):
        if not HAS_CRYPTO:
            raise ImportError("Please install 'cryptography' library for asymmetric signing.")
            
        if private_key_hex:
            # Load existing key
            priv_bytes = bytes.fromhex(private_key_hex)
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        else:
            # Generate new key pair for demo/initialization
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            
        self._public_key = self._private_key.public_key()

    def get_public_key_jwk(self) -> Dict[str, str]:
        """Returns the public key in RFC 7517 JWK format."""
        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(pub_bytes).decode('ascii').rstrip('='),
            "kid": f"hjs-key-{int(time.time())}",
            "alg": "EdDSA",
            "use": "sig"
        }

    def sign_payload(self, data: Dict[str, Any]) -> str:
        """Signs a dictionary payload and returns a base64-encoded signature."""
        # Canonicalize JSON to ensure deterministic hashing
        canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
        signature = self._private_key.sign(canonical_json.encode('utf-8'))
        
        sig_b64 = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
        return f"ed25519:{sig_b64}"

    def export_private_key(self) -> str:
        """Exports private key as hex string (Keep this secret!)"""
        priv_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return priv_bytes.hex()

def compute_content_hash(data: Any) -> str:
    """Computes a SHA-256 hash for context binding."""
    content = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(content.encode('utf-8')).hexdigest()
