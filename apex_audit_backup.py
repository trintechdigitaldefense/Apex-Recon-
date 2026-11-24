"""Offline export, independent checkpointing, verification and recovery for ApexRecon audit trails."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from apex_audit import MAX_AUDIT_BYTES, _canonical, _verify_bytes

BACKUP_SCHEMA = "1.0"
CHECKPOINT_SCHEMA = "1.0"
MAX_BACKUP_BYTES = MAX_AUDIT_BYTES * 2

class AuditBackupError(RuntimeError):
    """Raised when an audit backup cannot be safely created, verified or restored."""


def _valid_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _validate_created_at(value):
    if not isinstance(value, str):
        raise AuditBackupError("created_at must be a timezone-aware ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditBackupError("created_at is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditBackupError("created_at must include a timezone")

def _read_regular(path, limit):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise AuditBackupError(f"cannot safely open file: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditBackupError("path is not a regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise AuditBackupError("file exceeds size limit")
        return b"".join(chunks)
    finally:
        os.close(fd)

def _write_exclusive(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise AuditBackupError(f"cannot create file exclusively: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditBackupError("destination is not a regular file")
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

def create_audit_backup(audit_path, backup_path, checkpoint_path):
    """Create a portable JSON backup and detached checkpoint, without overwrite."""
    paths = [
        os.path.normcase(os.path.abspath(os.fspath(path)))
        for path in (audit_path, backup_path, checkpoint_path)
    ]
    if len(set(paths)) != 3:
        raise AuditBackupError("audit, backup and checkpoint paths must be distinct")
    if os.path.islink(audit_path):
        raise AuditBackupError("source audit path must not be a symlink")
    if os.path.lexists(audit_path):
        audit_data = _read_regular(audit_path, MAX_AUDIT_BYTES)
    else:
        audit_data = b""
    audit_result = _verify_bytes(audit_data)
    if not audit_result["valid"]:
        raise AuditBackupError("source audit trail is invalid: " + str(audit_result["error"]))
    backup = {
        "schema_version": BACKUP_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "audit_entries": audit_result["entries"],
        "audit_head_hash": audit_result["head_hash"],
        "audit_sha256": hashlib.sha256(audit_data).hexdigest(),
        "audit_jsonl_base64": base64.b64encode(audit_data).decode("ascii"),
    }
    backup_bytes = _canonical(backup) + b"\n"
    if len(backup_bytes) > MAX_BACKUP_BYTES:
        raise AuditBackupError("encoded backup exceeds size limit")
    backup_digest = hashlib.sha256(backup_bytes).hexdigest()
    checkpoint = {
        "schema_version": CHECKPOINT_SCHEMA,
        "created_at": backup["created_at"],
        "backup_sha256": backup_digest,
        "audit_sha256": backup["audit_sha256"],
        "audit_entries": backup["audit_entries"],
        "audit_head_hash": backup["audit_head_hash"],
    }
    checkpoint_bytes = _canonical(checkpoint) + b"\n"
    backup_written = False
    try:
        _write_exclusive(backup_path, backup_bytes)
        backup_written = True
        _write_exclusive(checkpoint_path, checkpoint_bytes)
    except Exception:
        if backup_written:
            try:
                Path(backup_path).unlink()
            except OSError:
                pass
        raise
    return {
        "backup_path": str(backup_path), "checkpoint_path": str(checkpoint_path),
        "backup_sha256": backup_digest, "audit_sha256": backup["audit_sha256"],
        "entries": backup["audit_entries"], "head_hash": backup["audit_head_hash"],
    }

def verify_audit_backup(backup_path, checkpoint_path):
    """Verify backup bytes against a separately retained checkpoint and audit chain."""
    backup_bytes = _read_regular(backup_path, MAX_BACKUP_BYTES)
    checkpoint_bytes = _read_regular(checkpoint_path, 64 * 1024)
    try:
        backup = json.loads(backup_bytes.decode("utf-8"))
        checkpoint = json.loads(checkpoint_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditBackupError("backup or checkpoint is not valid UTF-8 JSON") from exc
    if not isinstance(backup, dict) or _canonical(backup) + b"\n" != backup_bytes:
        raise AuditBackupError("backup is not canonical JSON")
    if not isinstance(checkpoint, dict) or _canonical(checkpoint) + b"\n" != checkpoint_bytes:
        raise AuditBackupError("checkpoint is not canonical JSON")
    backup_keys = {"schema_version", "created_at", "audit_entries", "audit_head_hash", "audit_sha256", "audit_jsonl_base64"}
    checkpoint_keys = {"schema_version", "created_at", "backup_sha256", "audit_sha256", "audit_entries", "audit_head_hash"}
    if set(backup) != backup_keys or set(checkpoint) != checkpoint_keys:
        raise AuditBackupError("unsupported backup or checkpoint fields")
    if backup["schema_version"] != BACKUP_SCHEMA or checkpoint["schema_version"] != CHECKPOINT_SCHEMA:
        raise AuditBackupError("unsupported backup or checkpoint schema")
    _validate_created_at(backup["created_at"])
    if checkpoint["created_at"] != backup["created_at"]:
        raise AuditBackupError("backup/checkpoint creation timestamp mismatch")
    if (isinstance(backup["audit_entries"], bool)
            or not isinstance(backup["audit_entries"], int)
            or backup["audit_entries"] < 0):
        raise AuditBackupError("audit_entries must be a non-negative integer")
    if (not _valid_digest(backup["audit_head_hash"])
            or not _valid_digest(backup["audit_sha256"])
            or not _valid_digest(checkpoint["backup_sha256"])
            or not _valid_digest(checkpoint["audit_sha256"])
            or not _valid_digest(checkpoint["audit_head_hash"])):
        raise AuditBackupError("backup or checkpoint contains an invalid SHA-256 digest")
    if not isinstance(backup["audit_jsonl_base64"], str):
        raise AuditBackupError("audit payload must be a base64 string")
    backup_digest = hashlib.sha256(backup_bytes).hexdigest()
    if checkpoint["backup_sha256"] != backup_digest:
        raise AuditBackupError("backup does not match detached checkpoint")
    try:
        audit_data = base64.b64decode(backup["audit_jsonl_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise AuditBackupError("audit payload is not valid base64") from exc
    if len(audit_data) > MAX_AUDIT_BYTES:
        raise AuditBackupError("audit payload exceeds size limit")
    audit_digest = hashlib.sha256(audit_data).hexdigest()
    if backup["audit_sha256"] != audit_digest or checkpoint["audit_sha256"] != audit_digest:
        raise AuditBackupError("audit payload checksum mismatch")
    audit_result = _verify_bytes(audit_data)
    if not audit_result["valid"]:
        raise AuditBackupError("embedded audit chain is invalid: " + str(audit_result["error"]))
    expected = {
        "created_at": backup["created_at"], "audit_entries": audit_result["entries"],
        "audit_head_hash": audit_result["head_hash"], "audit_sha256": audit_digest,
    }
    for key, value in expected.items():
        if backup.get(key) != value or checkpoint.get(key) != value:
            raise AuditBackupError(f"backup/checkpoint metadata mismatch: {key}")
    return {
        "valid": True, "entries": audit_result["entries"], "head_hash": audit_result["head_hash"],
        "audit_sha256": audit_digest, "backup_sha256": backup_digest,
    }

def restore_audit_backup(backup_path, checkpoint_path, destination_path):
    """Restore a verified backup to a new file; never overwrite existing evidence."""
    verified = verify_audit_backup(backup_path, checkpoint_path)
    backup = json.loads(_read_regular(backup_path, MAX_BACKUP_BYTES).decode("utf-8"))
    audit_data = base64.b64decode(backup["audit_jsonl_base64"], validate=True)
    _write_exclusive(destination_path, audit_data)
    restored = _read_regular(destination_path, MAX_AUDIT_BYTES)
    result = _verify_bytes(restored)
    if not result["valid"] or result["head_hash"] != verified["head_hash"]:
        try:
            Path(destination_path).unlink()
        except OSError:
            pass
        raise AuditBackupError("restored audit trail failed post-write verification")
    return {
        "restored_path": str(destination_path), "entries": result["entries"],
        "head_hash": result["head_hash"], "audit_sha256": hashlib.sha256(restored).hexdigest(),
    }
