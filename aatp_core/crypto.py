"""
aatp_core/crypto.py — Cryptographic primitives for AATP.

Uses Python `cryptography` library exclusively. No custom crypto.
- SHA-256 for record hashing
- Ed25519 for signing/verification
- did:key generation for self-certifying identities (Memo 2)

All functions are deterministic and have no side effects.
"""

from __future__ import annotations

import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    """Serialize private key to PEM bytes."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: Ed25519PublicKey) -> bytes:
    """Serialize public key to PEM bytes."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_from_pem(pem_data: bytes) -> Ed25519PrivateKey:
    """Deserialize private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")
    return key


def public_key_from_pem(pem_data: bytes) -> Ed25519PublicKey:
    """Deserialize public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")
    return key


def public_key_to_raw(key: Ed25519PublicKey) -> bytes:
    """Extract raw 32-byte public key."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign data with Ed25519 private key. Returns hex-encoded signature."""
    signature = private_key.sign(data)
    return signature.hex()


def verify_signature(
    public_key: Ed25519PublicKey, data: bytes, signature_hex: str
) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DID:key generation (Execution Plan Memo 2)
# ---------------------------------------------------------------------------

# Multicodec prefix for Ed25519 public key
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def public_key_to_did_key(key: Ed25519PublicKey) -> str:
    """Generate a did:key identifier from an Ed25519 public key.

    Format: did:key:z{base58btc(multicodec_prefix + raw_public_key)}

    did:key is a self-certifying DID method — no identity server needed,
    fully offline, W3C compliant. Ideal for v0.x development.

    Reference: https://w3c-ccg.github.io/did-method-key/
    """
    raw_key = public_key_to_raw(key)
    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + raw_key
    encoded = _base58btc_encode(multicodec_bytes)
    return f"did:key:z{encoded}"


def _base58btc_encode(data: bytes) -> str:
    """Base58btc encoding (Bitcoin alphabet).

    Used by did:key for the multibase-encoded public key.
    """
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    # Convert bytes to integer
    n = int.from_bytes(data, "big")

    # Encode
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(alphabet[remainder])

    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break

    return "".join(reversed(result))
