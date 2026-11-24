"""Local hash-chained audit trail for ApexRecon evidence operations.

The trail is tamper-evident, not immutable. Preserve trusted checkpoints
outside the assessment workstation if independent audit assurance is needed.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

AUDIT_SCHEMA = "1.0"
GENESIS_HASH = "0" * 64
MAX_AUDIT_BYTES = 5 * 1024 * 1024
MAX_AUDIT_EVENTS = 50000
EVENT_TYPES = {
    "KEYPAIR_CREATED",
    "ENGAGEMENT_SIGNED",
    "SIGNATURE_VERIFIED",
    "SIGNATURE_REJECTED",
}
RESULTS = {"SUCCESS", "INVALID"}


class AuditTrailError(RuntimeError):
    """Raised when an audit trail cannot be safely read or extended."""


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _valid_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _verification_result(
    data: bytes,
    valid: bool,
    entries: int,
    head_hash: str | None,
    error: str | None,
    failure_code: str | None = None,
    failure_sequence: int | None = None,
    verified_bytes: int = 0,
) -> dict:
    prefix = data[:verified_bytes]
    return {
        "valid": valid,
        "entries": entries,
        "head_hash": head_hash,
        "error": error,
        "failure_code": failure_code,
        "failure_sequence": failure_sequence,
        "verified_bytes": verified_bytes,
        "verified_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
        "original_bytes": len(data),
        "original_sha256": hashlib.sha256(data).hexdigest(),
    }


def _verify_bytes(data: bytes) -> dict:
    """Verify a JSONL chain and report the exact verified prefix without repair."""
    if len(data) > MAX_AUDIT_BYTES:
        return _verification_result(
            data, False, 0, None, "audit trail exceeds size limit",
            "size_limit", 1, 0,
        )

    last_newline = data.rfind(b"\\n")
    complete_end = last_newline + 1 if last_newline >= 0 else 0
    complete_data = data[:complete_end]
    trailing = data[complete_end:]
    lines = complete_data[:-1].split(b"\\n") if complete_data else []
    if len(lines) > MAX_AUDIT_EVENTS:
        return _verification_result(
            data, False, 0, None, "audit trail exceeds event limit",
            "event_limit", 1, 0,
        )

    previous = GENESIS_HASH
    verified_bytes = 0
    seen_hashes = set()
    expected_keys = {
        "schema_version", "sequence", "timestamp", "event_type",
        "engagement_id", "result", "signer_fingerprint",
        "previous_hash", "entry_hash",
    }

    for index, raw_line in enumerate(lines, start=1):
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            return _verification_result(
                data, False, index - 1, previous, f"event {index}: audit event is not UTF-8",
                "invalid_utf8", index, verified_bytes,
            )
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict) or set(entry) != expected_keys:
                raise ValueError("invalid event fields")
            if _canonical(entry).decode("utf-8") != line:
                raise ValueError("event JSON is not canonical")
            if entry["schema_version"] != AUDIT_SCHEMA:
                raise ValueError("unsupported audit schema")
            if entry["event_type"] not in EVENT_TYPES or entry["result"] not in RESULTS:
                raise ValueError("unsupported event type or result")
            if entry["engagement_id"] is not None:
                parsed = uuid.UUID(str(entry["engagement_id"]))
                if str(parsed) != entry["engagement_id"]:
                    raise ValueError("invalid engagement UUID")
            fingerprint = entry["signer_fingerprint"]
            if fingerprint is not None and not _valid_fingerprint(fingerprint):
                raise ValueError("invalid signer fingerprint")
            timestamp = entry["timestamp"]
            if not isinstance(timestamp, str):
                raise ValueError("invalid timestamp")
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                raise ValueError("timestamp must include a timezone")
            claimed_hash = entry["entry_hash"]
            unsigned = dict(entry)
            unsigned.pop("entry_hash")
            calculated = hashlib.sha256(_canonical(unsigned)).hexdigest()
            if not _valid_fingerprint(claimed_hash) or not hmac.compare_digest(calculated, claimed_hash):
                raise ValueError("event hash mismatch")
            if claimed_hash in seen_hashes:
                raise ValueError("duplicate audit event hash")
            if (isinstance(entry["sequence"], bool)
                    or not isinstance(entry["sequence"], int)
                    or entry["sequence"] != index):
                raise ValueError("sequence is duplicated, missing or out of order")
            if entry["previous_hash"] != previous:
                raise ValueError("broken hash-chain link")
            seen_hashes.add(claimed_hash)
            previous = claimed_hash
            verified_bytes += len(raw_line) + 1
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            message = str(exc)
            if "duplicate audit event hash" in message:
                code = "duplicate_event"
            elif "sequence is duplicated" in message:
                code = "sequence_error"
            elif "hash-chain" in message:
                code = "broken_hash_chain"
            elif "event hash mismatch" in message:
                code = "event_hash_mismatch"
            elif "unsupported audit schema" in message:
                code = "unsupported_schema"
            elif "unsupported event" in message:
                code = "unsupported_event"
            elif "timestamp" in message:
                code = "invalid_timestamp"
            elif "engagement UUID" in message:
                code = "invalid_engagement_id"
            elif "fingerprint" in message:
                code = "invalid_fingerprint"
            elif "canonical" in message:
                code = "non_canonical_json"
            elif "Expecting" in message or "JSON" in message:
                code = "invalid_json"
            else:
                code = "invalid_event"
            return _verification_result(
                data, False, index - 1, previous, f"event {index}: {exc}",
                code, index, verified_bytes,
            )

    if trailing:
        return _verification_result(
            data, False, len(lines), previous,
            "audit trail has an incomplete final event",
            "incomplete_final_event", len(lines) + 1, verified_bytes,
        )
    return _verification_result(
        data, True, len(lines), previous, None, None, None, verified_bytes,
    )

def _read_fd(fd: int) -> bytes:
    chunks = []
    total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, min(65536, MAX_AUDIT_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_AUDIT_BYTES:
            raise AuditTrailError("audit trail exceeds size limit")
    return b"".join(chunks)


def verify_audit_trail(path: str | os.PathLike[str]) -> dict:
    """Verify the complete local hash chain without changing the file."""
    audit_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(audit_path), flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise AuditTrailError("audit path is not a regular file")
            return _verify_bytes(_read_fd(fd))
        finally:
            os.close(fd)
    except FileNotFoundError:
        return _verify_bytes(b"")
    except OSError as exc:
        raise AuditTrailError(f"cannot safely read audit trail: {exc}") from exc


def append_audit_event(
    path: str | os.PathLike[str],
    event_type: str,
    engagement_id: str | None,
    result: str,
    signer_fingerprint: str | None = None,
) -> dict:
    """Append one validated event, refusing to extend a damaged trail."""
    if (not isinstance(event_type, str) or event_type not in EVENT_TYPES
            or not isinstance(result, str) or result not in RESULTS):
        raise AuditTrailError("unsupported audit event type or result")
    if engagement_id is not None:
        try:
            parsed = uuid.UUID(str(engagement_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise AuditTrailError("engagement_id must be a canonical UUID") from exc
        if str(parsed) != engagement_id:
            raise AuditTrailError("engagement_id must be a canonical UUID")
    if signer_fingerprint is not None and not _valid_fingerprint(signer_fingerprint):
        raise AuditTrailError("signer fingerprint must be a lowercase SHA-256 hex digest")

    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise AuditTrailError(f"cannot safely open audit trail: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditTrailError("audit path is not a regular file")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        existing = _read_fd(fd)
        verified = _verify_bytes(existing)
        if not verified["valid"]:
            raise AuditTrailError("refusing to append to invalid audit trail: " + str(verified["error"]))
        if verified["entries"] >= MAX_AUDIT_EVENTS:
            raise AuditTrailError("audit trail event limit reached")
        unsigned = {
            "schema_version": AUDIT_SCHEMA,
            "sequence": verified["entries"] + 1,
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event_type": event_type,
            "engagement_id": engagement_id,
            "result": result,
            "signer_fingerprint": signer_fingerprint,
            "previous_hash": verified["head_hash"],
        }
        entry = dict(unsigned)
        entry["entry_hash"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
        payload = _canonical(entry) + b"\n"
        if len(existing) + len(payload) > MAX_AUDIT_BYTES:
            raise AuditTrailError("audit trail size limit reached")
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count <= 0:
                raise OSError("audit event write made no progress")
            written += count
        os.fsync(fd)
        return entry
    except OSError as exc:
        raise AuditTrailError(f"cannot append audit event: {exc}") from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
