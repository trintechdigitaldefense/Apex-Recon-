"""Detached Ed25519 signatures for Phase 2P audit backup checkpoints.

The signature authenticates the detached checkpoint, which binds the backup
bytes and audit-chain metadata. Public-key fingerprints must be trusted out
of band. All operations are offline.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from apex_audit import _canonical
from apex_audit_backup import verify_audit_backup, AuditBackupError

SIGNATURE_SCHEMA = "1.0"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_CHECKPOINT_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024


class AuditBackupSignatureError(RuntimeError):
    """Raised when audit-backup signing or verification fails."""


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as exc:
        raise AuditBackupSignatureError(
            "Audit backup signatures require the optional cryptography package"
        ) from exc
    return InvalidSignature, UnsupportedAlgorithm, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _read_regular(path, limit, private=False):
    if os.path.islink(path):
        raise AuditBackupSignatureError("symlink paths are not accepted for key or metadata files")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise AuditBackupSignatureError(f"cannot safely open key or metadata file: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditBackupSignatureError("key or metadata path is not a regular file")
        if private and os.name == "posix" and info.st_mode & 0o077:
            raise AuditBackupSignatureError("private-key file permissions must not grant group or other access")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise AuditBackupSignatureError("key or metadata file exceeds size limit")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_exclusive(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise AuditBackupSignatureError(f"cannot create signature exclusively: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditBackupSignatureError("signature destination is not a regular file")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            Path(path).unlink()
        except OSError:
            pass
        raise
    return str(path)


def _fingerprint(public_key, serialization):
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def _load_checkpoint(checkpoint_path):
    raw = _read_regular(checkpoint_path, MAX_CHECKPOINT_BYTES)
    try:
        checkpoint = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditBackupSignatureError("checkpoint is not valid UTF-8 JSON") from exc
    if not isinstance(checkpoint, dict) or _canonical(checkpoint) + b"\n" != raw:
        raise AuditBackupSignatureError("checkpoint must be canonical JSON")
    return raw, checkpoint


def sign_audit_backup_checkpoint(
    backup_path, checkpoint_path, private_key_path, passphrase, signature_path
):
    """Verify a backup/checkpoint pair, then sign the exact checkpoint bytes."""
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise AuditBackupSignatureError("private-key passphrase must contain at least 12 characters")
    try:
        verified = verify_audit_backup(backup_path, checkpoint_path)
    except AuditBackupError as exc:
        raise AuditBackupSignatureError(f"backup/checkpoint verification failed: {exc}") from exc
    checkpoint_bytes, checkpoint = _load_checkpoint(checkpoint_path)
    InvalidSignature, UnsupportedAlgorithm, serialization, Ed25519PrivateKey, Ed25519PublicKey = _crypto()
    try:
        key_bytes = _read_regular(private_key_path, 1024 * 1024, private=True)
        private_key = serialization.load_pem_private_key(key_bytes, password=passphrase.encode("utf-8"))
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise AuditBackupSignatureError("private key could not be loaded; check its path, permissions and passphrase") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AuditBackupSignatureError("private key must use Ed25519")
    public_key = private_key.public_key()
    fingerprint = _fingerprint(public_key, serialization)
    envelope = {
        "schema_version": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "checkpoint_sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
        "backup_sha256": verified["backup_sha256"],
        "audit_head_hash": verified["head_hash"],
        "public_key_sha256": fingerprint,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "signature": base64.b64encode(private_key.sign(checkpoint_bytes)).decode("ascii"),
    }
    data = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    saved = _write_exclusive(signature_path, data)
    return {
        "signature_path": saved,
        "public_key_sha256": fingerprint,
        "checkpoint_sha256": envelope["checkpoint_sha256"],
        "backup_sha256": verified["backup_sha256"],
        "entries": verified["entries"],
    }


def verify_signed_audit_backup(
    backup_path, checkpoint_path, signature_path, public_key_path, trusted_fingerprint
):
    """Verify backup integrity and Ed25519 signature against a pinned fingerprint."""
    if not isinstance(trusted_fingerprint, str) or len(trusted_fingerprint) != 64 or any(
        char not in "0123456789abcdef" for char in trusted_fingerprint
    ):
        raise AuditBackupSignatureError("trusted public-key fingerprint must be 64 lowercase hexadecimal characters")
    try:
        verified = verify_audit_backup(backup_path, checkpoint_path)
    except AuditBackupError as exc:
        raise AuditBackupSignatureError(f"backup/checkpoint verification failed: {exc}") from exc
    checkpoint_bytes, _ = _load_checkpoint(checkpoint_path)
    signature_bytes = _read_regular(signature_path, MAX_SIGNATURE_BYTES)
    try:
        envelope = json.loads(signature_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditBackupSignatureError("signature envelope is not valid UTF-8 JSON") from exc
    if not isinstance(envelope, dict) or _canonical(envelope) + b"\n" != signature_bytes:
        raise AuditBackupSignatureError("signature envelope must be canonical JSON")
    expected_keys = {
        "schema_version", "algorithm", "checkpoint_sha256", "backup_sha256",
        "audit_head_hash", "public_key_sha256", "signed_at", "signature",
    }
    if set(envelope) != expected_keys:
        raise AuditBackupSignatureError("unsupported signature envelope fields")
    if envelope["schema_version"] != SIGNATURE_SCHEMA or envelope["algorithm"] != SIGNATURE_ALGORITHM:
        raise AuditBackupSignatureError("unsupported signature schema or algorithm")
    if envelope["checkpoint_sha256"] != hashlib.sha256(checkpoint_bytes).hexdigest():
        raise AuditBackupSignatureError("signature does not bind the supplied checkpoint")
    if envelope["backup_sha256"] != verified["backup_sha256"] or envelope["audit_head_hash"] != verified["head_hash"]:
        raise AuditBackupSignatureError("signature metadata does not match verified backup")
    if envelope["public_key_sha256"] != trusted_fingerprint:
        raise AuditBackupSignatureError("signature key fingerprint does not match independently trusted fingerprint")
    signed_at = envelope["signed_at"]
    if not isinstance(signed_at, str):
        raise AuditBackupSignatureError("signed_at must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditBackupSignatureError("signed_at is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditBackupSignatureError("signed_at must include a timezone")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise AuditBackupSignatureError("signature is not valid base64") from exc
    if len(signature) != 64:
        raise AuditBackupSignatureError("Ed25519 signature must contain 64 bytes")
    InvalidSignature, UnsupportedAlgorithm, serialization, Ed25519PrivateKey, Ed25519PublicKey = _crypto()
    try:
        public_bytes = _read_regular(public_key_path, 1024 * 1024)
        public_key = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise AuditBackupSignatureError("public key must use Ed25519")
        actual_fingerprint = _fingerprint(public_key, serialization)
        if actual_fingerprint != trusted_fingerprint:
            raise AuditBackupSignatureError("public key does not match independently trusted fingerprint")
        public_key.verify(signature, checkpoint_bytes)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm, InvalidSignature) as exc:
        raise AuditBackupSignatureError("audit backup signature verification failed") from exc
    return {
        "valid": True,
        "entries": verified["entries"],
        "head_hash": verified["head_hash"],
        "backup_sha256": verified["backup_sha256"],
        "checkpoint_sha256": hashlib.sha256(checkpoint_bytes).hexdigest(),
        "public_key_sha256": actual_fingerprint,
        "signed_at": signed_at,
    }
