"""Append-only execution journal for recoverable engagement status.

The journal records module start/finish boundaries. It never stores targets,
credentials, findings, or scan instructions, and it never resumes assessments.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apex_storage import write_exclusive_atomic

JOURNAL_SCHEMA = "1.0"
MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MODULES = (
    "External Footprinting (OSINT)",
    "SMB Network Auditor",
    "HTTP Security Assessment",
    "TLS Security Assessment",
)
TERMINAL_STATUSES = {"COMPLETED", "PARTIAL", "FAILED", "NOT_RUN"}
EVENT_TYPES = {
    "ENGAGEMENT_STARTED",
    "MODULE_STARTED",
    "MODULE_FINISHED",
    "ENGAGEMENT_FINALIZED",
    "ENGAGEMENT_FINALIZATION_FAILED",
}
GENESIS_HASH = "0" * 64


class ExecutionJournalError(RuntimeError):
    """Raised when an execution journal cannot be safely read or extended."""


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash_event(unsigned: dict) -> str:
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _new_event(sequence: int, execution_id: str, event_type: str,
               previous_hash: str, module: str | None = None,
               status: str | None = None,
               selected_modules: list[str] | None = None) -> dict:
    unsigned = {
        "schema_version": JOURNAL_SCHEMA,
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "execution_id": execution_id,
        "event_type": event_type,
        "module": module,
        "status": status,
        "selected_modules": selected_modules,
        "artifact_file": None,
        "artifact_sha256": None,
        "previous_hash": previous_hash,
    }
    event = dict(unsigned)
    event["event_hash"] = _hash_event(unsigned)
    return event


def _verify_bytes(data: bytes) -> dict:
    empty = {
        "valid": False, "events": 0, "execution_id": None,
        "selected_modules": [], "module_states": {}, "artifact_refs": [],
        "execution_status": "INVALID", "head_hash": None, "error": "journal is empty",
    }
    if not data:
        return empty
    if len(data) > MAX_JOURNAL_BYTES:
        return {**empty, "error": "journal exceeds size limit"}
    if not data.endswith(b"\n"):
        return {**empty, "error": "journal has an incomplete final event"}
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return {**empty, "error": "journal is not UTF-8"}

    previous = GENESIS_HASH
    execution_id = None
    selected = []
    states = {}
    artifact_refs = []
    finalized = None
    expected_keys = {
        "schema_version", "sequence", "timestamp", "execution_id",
        "event_type", "module", "status", "selected_modules",
        "artifact_file", "artifact_sha256", "previous_hash", "event_hash",
    }
    for index, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict) or set(event) != expected_keys:
                raise ValueError("invalid event fields")
            if _canonical(event).decode("utf-8") != line:
                raise ValueError("event JSON is not canonical")
            if event["schema_version"] != JOURNAL_SCHEMA:
                raise ValueError("unsupported journal schema")
            if isinstance(event["sequence"], bool) or event["sequence"] != index:
                raise ValueError("invalid event sequence")
            timestamp = event["timestamp"]
            if not isinstance(timestamp, str):
                raise ValueError("invalid timestamp")
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timestamp must include a timezone")
            if event["previous_hash"] != previous:
                raise ValueError("broken journal hash-chain link")
            unsigned = dict(event)
            claimed_hash = unsigned.pop("event_hash")
            calculated = _hash_event(unsigned)
            if not isinstance(claimed_hash, str) or not hmac.compare_digest(calculated, claimed_hash):
                raise ValueError("event hash mismatch")
            current_id = event["execution_id"]
            if not isinstance(current_id, str) or not current_id or len(current_id) > 80:
                raise ValueError("invalid execution identifier")
            if index == 1:
                if event["event_type"] != "ENGAGEMENT_STARTED":
                    raise ValueError("first event must start an engagement")
                modules = event["selected_modules"]
                if (not isinstance(modules, list) or not modules
                        or len(modules) != len(set(modules))
                        or not set(modules).issubset(set(MODULES))):
                    raise ValueError("invalid selected module list")
                if (event["module"] is not None or event["status"] is not None
                        or event["artifact_file"] is not None
                        or event["artifact_sha256"] is not None):
                    raise ValueError("engagement start cannot carry module state")
                execution_id = current_id
                selected = list(modules)
                states = {name: "NOT_STARTED" for name in selected}
            else:
                if current_id != execution_id:
                    raise ValueError("execution identifier changed")
                if event["selected_modules"] is not None:
                    raise ValueError("selected modules may appear only in the first event")
                kind = event["event_type"]
                artifact_file = event["artifact_file"]
                artifact_sha256 = event["artifact_sha256"]
                module = event["module"]
                status = event["status"]
                if finalized is not None:
                    raise ValueError("event appears after engagement finalization")
                if kind == "MODULE_STARTED":
                    if (module not in states or status is not None or states[module] != "NOT_STARTED"
                            or artifact_file is not None or artifact_sha256 is not None):
                        raise ValueError("invalid module start transition")
                    states[module] = "STARTED"
                elif kind == "MODULE_FINISHED":
                    if module not in states or status not in TERMINAL_STATUSES or states[module] != "STARTED":
                        raise ValueError("invalid module finish transition")
                    if artifact_file is None:
                        if artifact_sha256 is not None:
                            raise ValueError("artifact checksum has no artifact path")
                    else:
                        if (not isinstance(artifact_file, str) or Path(artifact_file).name != artifact_file
                                or not artifact_file.endswith(".json")
                                or not isinstance(artifact_sha256, str)
                                or len(artifact_sha256) != 64
                                or any(char not in "0123456789abcdef" for char in artifact_sha256)):
                            raise ValueError("invalid module artifact reference")
                    states[module] = status
                    if artifact_file is not None:
                        artifact_refs.append({"module": module, "file": artifact_file, "sha256": artifact_sha256})
                elif kind in {"ENGAGEMENT_FINALIZED", "ENGAGEMENT_FINALIZATION_FAILED"}:
                    if (module is not None or status is not None
                            or artifact_file is not None or artifact_sha256 is not None):
                        raise ValueError("finalization event cannot carry module state")
                    if any(value == "STARTED" for value in states.values()):
                        raise ValueError("cannot finalize while a module is still active")
                    finalized = "FINALIZED" if kind == "ENGAGEMENT_FINALIZED" else "FINALIZATION_FAILED"
                else:
                    raise ValueError("unsupported event type")
            previous = claimed_hash
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return {
                "valid": False, "events": index - 1, "execution_id": execution_id,
                "selected_modules": selected, "module_states": states,
                "artifact_refs": artifact_refs,
                "execution_status": "INVALID", "head_hash": previous,
                "error": f"event {index}: {exc}",
            }

    if finalized:
        execution_status = finalized
    elif states and all(value == "NOT_STARTED" for value in states.values()):
        execution_status = "READY"
    elif any(value in {"STARTED", "NOT_STARTED"} for value in states.values()):
        execution_status = "INCOMPLETE"
    else:
        execution_status = "AWAITING_FINALIZATION"
    return {
        "valid": True, "events": len(lines), "execution_id": execution_id,
        "selected_modules": selected, "module_states": states,
        "artifact_refs": artifact_refs,
        "execution_status": execution_status, "head_hash": previous, "error": None,
    }


def inspect_execution_journal(path: str | os.PathLike[str]) -> dict:
    """Read and verify a journal without changing it."""
    journal_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(journal_path), flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ExecutionJournalError("journal path is not a regular file")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, MAX_JOURNAL_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_JOURNAL_BYTES:
                    raise ExecutionJournalError("journal exceeds size limit")
            return _verify_bytes(b"".join(chunks))
        finally:
            os.close(fd)
    except FileNotFoundError:
        return _verify_bytes(b"")
    except OSError as exc:
        raise ExecutionJournalError(f"cannot safely read execution journal: {exc}") from exc


def load_completed_module_artifacts(path: str | os.PathLike[str]) -> dict:
    """Verify and load completed module sidecars referenced by a valid journal.

    Returned outcomes are evidence for manual report reconstruction only.
    This function never invokes assessment modules or resumes network activity.
    """
    journal_path = Path(path)
    report = inspect_execution_journal(journal_path)
    if not report["valid"]:
        raise ExecutionJournalError("cannot load outcomes from an invalid journal")
    artifacts = []
    for reference in report["artifact_refs"]:
        artifact_name = reference["file"]
        if Path(artifact_name).name != artifact_name:
            raise ExecutionJournalError("unsafe module artifact path in journal")
        artifact_path = journal_path.parent / artifact_name
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(artifact_path), flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ExecutionJournalError("module artifact is not a regular file")
                chunks = []
                total = 0
                while True:
                    chunk = os.read(fd, min(65536, 4 * 1024 * 1024 + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 4 * 1024 * 1024:
                        raise ExecutionJournalError("module artifact exceeds size limit")
                payload = b"".join(chunks)
            finally:
                os.close(fd)
        except OSError as exc:
            raise ExecutionJournalError(f"cannot safely read module artifact: {type(exc).__name__}") from exc
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), reference["sha256"]):
            raise ExecutionJournalError("module artifact checksum mismatch")
        try:
            item = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutionJournalError("module artifact is not valid UTF-8 JSON") from exc
        if (not isinstance(item, dict) or item.get("schema_version") != "1.0"
                or item.get("execution_id") != report["execution_id"]
                or item.get("module") != reference["module"]
                or item.get("status") != report["module_states"][reference["module"]]
                or not isinstance(item.get("outcome"), dict)):
            raise ExecutionJournalError("module artifact metadata does not match its journal event")
        artifacts.append(item)
    return {
        "valid": True,
        "execution_id": report["execution_id"],
        "execution_status": report["execution_status"],
        "module_states": report["module_states"],
        "artifacts": artifacts,
    }


class ExecutionJournal:
    """Create and append one local engagement execution journal."""

    def __init__(self, path: str | os.PathLike[str], execution_id: str):
        self.path = Path(path)
        self.execution_id = str(execution_id)

    @classmethod
    def create(cls, path: str | os.PathLike[str], execution_id: str,
               selected_modules: list[str]) -> "ExecutionJournal":
        if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 80:
            raise ExecutionJournalError("execution_id must be non-empty text")
        if (not isinstance(selected_modules, list) or not selected_modules
                or len(selected_modules) != len(set(selected_modules))
                or not set(selected_modules).issubset(set(MODULES))):
            raise ExecutionJournalError("selected_modules must be a non-empty unique supported module list")
        journal = cls(path, execution_id)
        event = _new_event(1, execution_id, "ENGAGEMENT_STARTED", GENESIS_HASH,
                           selected_modules=list(selected_modules))
        try:
            write_exclusive_atomic(journal.path, _canonical(event) + b"\n")
        except OSError as exc:
            raise ExecutionJournalError(f"cannot create execution journal: {type(exc).__name__}") from exc
        return journal

    def _append(self, event_type: str, module: str | None = None,
                status: str | None = None, artifact_file: str | None = None,
                artifact_sha256: str | None = None) -> dict:
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise ExecutionJournalError(f"cannot safely open execution journal: {type(exc).__name__}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ExecutionJournalError("journal path is not a regular file")
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.lseek(fd, 0, os.SEEK_SET)
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, MAX_JOURNAL_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_JOURNAL_BYTES:
                    raise ExecutionJournalError("journal exceeds size limit")
            current = _verify_bytes(b"".join(chunks))
            if not current["valid"] or current["execution_id"] != self.execution_id:
                raise ExecutionJournalError("refusing to extend an invalid or mismatched execution journal")
            if event_type == "MODULE_STARTED":
                if module not in current["module_states"] or current["module_states"][module] != "NOT_STARTED":
                    raise ExecutionJournalError("module cannot enter STARTED from its current state")
                if artifact_file is not None or artifact_sha256 is not None:
                    raise ExecutionJournalError("module start cannot include an evidence artifact")
            elif event_type == "MODULE_FINISHED":
                if (module not in current["module_states"]
                        or current["module_states"][module] != "STARTED"
                        or status not in TERMINAL_STATUSES):
                    raise ExecutionJournalError("module cannot enter the requested terminal state")
            elif event_type in {"ENGAGEMENT_FINALIZED", "ENGAGEMENT_FINALIZATION_FAILED"}:
                if any(value in {"STARTED", "NOT_STARTED"} for value in current["module_states"].values()):
                    raise ExecutionJournalError("all selected modules must be resolved before finalization")
                module = status = artifact_file = artifact_sha256 = None
            else:
                raise ExecutionJournalError("unsupported event type")

            event = _new_event(
                current["events"] + 1, self.execution_id, event_type,
                current["head_hash"], module=module, status=status,
            )
            event["artifact_file"] = artifact_file
            event["artifact_sha256"] = artifact_sha256
            unsigned = dict(event)
            unsigned.pop("event_hash")
            event["event_hash"] = _hash_event(unsigned)
            payload = _canonical(event) + b"\n"
            if total + len(payload) > MAX_JOURNAL_BYTES:
                raise ExecutionJournalError("journal size limit reached")
            written = 0
            while written < len(payload):
                count = os.write(fd, payload[written:])
                if count <= 0:
                    raise OSError("journal write made no progress")
                written += count
            os.fsync(fd)
            return event
        except OSError as exc:
            raise ExecutionJournalError(f"cannot append execution journal event: {type(exc).__name__}") from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def start_module(self, module: str) -> dict:
        return self._append("MODULE_STARTED", module=module)

    def finish_module(self, module: str, status: str, outcome: dict | None = None) -> dict:
        artifact_file = None
        artifact_sha256 = None
        if outcome is not None:
            if not isinstance(outcome, dict):
                raise ExecutionJournalError("module outcome artifact must be an object")
            payload_object = {
                "schema_version": "1.0",
                "execution_id": self.execution_id,
                "module": module,
                "status": status,
                "outcome": outcome,
            }
            try:
                payload = (json.dumps(
                    payload_object, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False,
                ) + "\n").encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ExecutionJournalError("module outcome is not safely serializable") from exc
            module_index = MODULES.index(module) + 1 if module in MODULES else 0
            artifact_file = f"{self.path.stem}_module_{module_index}.json"
            try:
                write_exclusive_atomic(self.path.parent / artifact_file, payload)
            except OSError as exc:
                raise ExecutionJournalError(f"cannot persist module outcome: {type(exc).__name__}") from exc
            artifact_sha256 = hashlib.sha256(payload).hexdigest()
        return self._append(
            "MODULE_FINISHED", module=module, status=status,
            artifact_file=artifact_file, artifact_sha256=artifact_sha256,
        )

    def finalize(self) -> dict:
        return self._append("ENGAGEMENT_FINALIZED")

    def fail_finalization(self) -> dict:
        return self._append("ENGAGEMENT_FINALIZATION_FAILED")
