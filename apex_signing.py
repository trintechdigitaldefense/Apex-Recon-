"""Detached Ed25519 signatures for verified ApexRecon engagement records.

Private keys are stored as encrypted PKCS#8 PEM files. Signing and verification
are offline operations; this module never initiates assessments or network access.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apex_engagement import EngagementError, _canonical, verify_engagement_record

SIGNATURE_SCHEMA = "1.0"
SIGNATURE_ALGORITHM = "Ed25519"


class SigningDependencyError(RuntimeError):
    """Raised when the optional cryptography dependency is unavailable."""


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as exc:
        raise SigningDependencyError(
            "Evidence signing requires the optional cryptography package"
        ) from exc
    return InvalidSignature, UnsupportedAlgorithm, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise EngagementError("private-key passphrase must contain at least 12 characters")
    return passphrase.encode("utf-8")


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> str:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        if os.name == "posix":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return str(path)


def _public_key_fingerprint(public_key: Any, serialization: Any) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def generate_ed25519_keypair(
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    passphrase: str,
) -> dict:
    """Create an encrypted private key and matching public key, without overwrite."""
    _, _, serialization, Ed25519PrivateKey, _ = _crypto()
    password = _passphrase_bytes(passphrase)
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    if private_path.resolve() == public_path.resolve():
        raise EngagementError("private and public key paths must be different")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_written = False
    try:
        _write_exclusive(private_path, private_pem, 0o600)
        private_written = True
        _write_exclusive(public_path, public_pem, 0o600)
    except Exception:
        if private_written:
            try:
                private_path.unlink()
            except OSError:
                pass
        raise
    return {
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "public_key_sha256": _public_key_fingerprint(public_key, serialization),
    }


def sign_engagement_record(
    record: dict,
    private_key_path: str | os.PathLike[str],
    passphrase: str,
) -> dict:
    """Sign the complete canonical engagement JSON record using Ed25519."""
    if not verify_engagement_record(record):
        raise EngagementError("cannot sign an invalid or checksum-mismatched engagement record")
    InvalidSignature, UnsupportedAlgorithm, serialization, Ed25519PrivateKey, Ed25519PublicKey = _crypto()
    password = _passphrase_bytes(passphrase)
    try:
        private_key = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=password
        )
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise EngagementError("private key could not be loaded; check its path and passphrase") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise EngagementError("private key must use Ed25519")
    public_key = private_key.public_key()
    payload = _canonical(record)
    signature = private_key.sign(payload)
    return {
        "schema_version": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "engagement_id": record["engagement"]["id"],
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key_sha256": _public_key_fingerprint(public_key, serialization),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_engagement_signature(
    record: dict,
    signature_envelope: dict,
    public_key_path: str | os.PathLike[str],
) -> bool:
    """Verify record integrity, key identity, payload binding and Ed25519 signature.

    This proves possession of the private key corresponding to the supplied
    public key. It does not establish that the key belongs to a claimed person
    or organization; public-key trust must be established out of band.
    """
    if not verify_engagement_record(record) or not isinstance(signature_envelope, dict):
        return False
    if signature_envelope.get("schema_version") != SIGNATURE_SCHEMA:
        return False
    if signature_envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        return False
    if signature_envelope.get("engagement_id") != record.get("engagement", {}).get("id"):
        return False
    InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey = _crypto()
    try:
        public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        payload = _canonical(record)
        payload_digest = hashlib.sha256(payload).hexdigest()
        fingerprint = _public_key_fingerprint(public_key, serialization)
        if signature_envelope.get("payload_sha256") != payload_digest:
            return False
        if signature_envelope.get("public_key_sha256") != fingerprint:
            return False
        signed_at = signature_envelope.get("signed_at")
        if not isinstance(signed_at, str):
            return False
        parsed = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return False
        signature_text = signature_envelope.get("signature")
        if not isinstance(signature_text, str):
            return False
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            return False
        public_key.verify(signature, payload)
        return True
    except (InvalidSignature, OSError, ValueError, TypeError, UnsupportedAlgorithm, binascii.Error):
        return False


def export_signature_envelope(
    signature_envelope: dict,
    path: str | os.PathLike[str],
) -> str:
    """Write a detached signature envelope without overwriting an existing file."""
    if not isinstance(signature_envelope, dict):
        raise EngagementError("signature envelope must be an object")
    data = json.dumps(
        signature_envelope, indent=2, ensure_ascii=False, sort_keys=True
    ).encode("utf-8") + b"\n"
    return _write_exclusive(Path(path), data, 0o600)
