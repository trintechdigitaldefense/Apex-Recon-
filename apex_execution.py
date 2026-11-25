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
MAX_MODULE_ARTIFACT_BYTES = 4 * 1024 * 1024
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
    """Verify the journal and report its exact verified prefix without repair."""
    empty = {
        "valid": False, "events": 0, "execution_id": None,
        "selected_modules": [], "module_states": {}, "artifact_refs": [],
        "execution_status": "INVALID", "head_hash": None, "error": "journal is empty",
    }

    def result(valid, events, execution_id, selected, states, artifact_refs,
               head_hash, error, failure_code, failure_sequence, prefix_bytes):
        prefix = data[:prefix_bytes]
        return {
            "valid": valid,
            "events": events,
            "execution_id": execution_id,
            "selected_modules": selected,
            "module_states": states,
            "artifact_refs": artifact_refs,
            "execution_status": execution_status if valid else "INVALID",
            "head_hash": head_hash,
            "error": error,
            "failure_code": failure_code,
            "failure_sequence": failure_sequence,
            "original_bytes": len(data),
            "original_sha256": hashlib.sha256(data).hexdigest(),
            "verified_prefix_bytes": len(prefix),
            "verified_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
        }

    if not data:
        return {
            **empty,
            "failure_code": "empty_journal",
            "failure_sequence": 1,
            "original_bytes": 0,
            "original_sha256": hashlib.sha256(data).hexdigest(),
            "verified_prefix_bytes": 0,
            "verified_prefix_sha256": hashlib.sha256(data).hexdigest(),
        }
    if len(data) > MAX_JOURNAL_BYTES:
        return result(
            False, 0, None, [], {}, [], None, "journal exceeds size limit",
            "size_limit", None, 0,
        )

    last_newline = data.rfind(b"\n")
    complete_end = last_newline + 1
    complete_data = data[:complete_end]
    trailing = data[complete_end:]
    lines = complete_data[:-1].split(b"\n") if complete_data else []

    previous = GENESIS_HASH
    execution_id = None
    selected = []
    states = {}
    artifact_refs = []
    finalized = None
    verified_bytes = 0
    expected_keys = {
        "schema_version", "sequence", "timestamp", "execution_id",
        "event_type", "module", "status", "selected_modules",
        "artifact_file", "artifact_sha256", "previous_hash", "event_hash",
    }

    for index, raw_line in enumerate(lines, start=1):
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            return result(
                False, index - 1, execution_id, selected, states, artifact_refs,
                previous, f"event {index}: journal event is not UTF-8",
                "invalid_utf8", index, verified_bytes,
            )
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
                                or "/" in artifact_file or "\\" in artifact_file
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
                    if any(value in {"STARTED", "NOT_STARTED"} for value in states.values()):
                        raise ValueError("cannot finalize while selected modules remain unresolved")
                    finalized = "FINALIZED" if kind == "ENGAGEMENT_FINALIZED" else "FINALIZATION_FAILED"
                else:
                    raise ValueError("unsupported event type")
            previous = claimed_hash
            verified_bytes += len(raw_line) + 1
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            message = str(exc)
            if "canonical" in message:
                code = "non_canonical_json"
            elif "hash-chain" in message:
                code = "broken_hash_chain"
            elif "hash mismatch" in message:
                code = "event_hash_mismatch"
            elif "timestamp" in message:
                code = "invalid_timestamp"
            elif "sequence" in message:
                code = "invalid_sequence"
            elif "schema" in message:
                code = "unsupported_schema"
            elif "finalization" in message or "finalize" in message:
                code = "invalid_finalization"
            elif "JSON" in message or "Expecting" in message:
                code = "invalid_json"
            else:
                code = "invalid_event"
            return result(
                False, index - 1, execution_id, selected, states, artifact_refs,
                previous, f"event {index}: {exc}", code, index, verified_bytes,
            )

    if trailing:
        return result(
            False, len(lines), execution_id, selected, states, artifact_refs,
            previous, "journal has an incomplete final event",
            "incomplete_final_event", len(lines) + 1, verified_bytes,
        )

    if finalized:
        execution_status = finalized
    elif states and all(value == "NOT_STARTED" for value in states.values()):
        execution_status = "READY"
    elif any(value in {"STARTED", "NOT_STARTED"} for value in states.values()):
        execution_status = "INCOMPLETE"
    else:
        execution_status = "AWAITING_FINALIZATION"
    return result(
        True, len(lines), execution_id, selected, states, artifact_refs,
        previous, None, None, None, verified_bytes,
    )

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


def _read_module_artifact(journal_path: Path, reference: dict,
                          execution_id: str, module_status: str) -> dict:
    """Read one sidecar and verify its bytes and journal-bound metadata."""
    artifact_name = reference.get("file")
    if not isinstance(artifact_name, str) or Path(artifact_name).name != artifact_name:
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
                chunk = os.read(fd, min(65536, MAX_MODULE_ARTIFACT_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_MODULE_ARTIFACT_BYTES:
                    raise ExecutionJournalError("module artifact exceeds size limit")
            payload = b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ExecutionJournalError(
            f"cannot safely read module artifact: {type(exc).__name__}"
        ) from exc
    expected_digest = reference.get("sha256")
    if not isinstance(expected_digest, str) or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), expected_digest
    ):
        raise ExecutionJournalError("module artifact checksum mismatch")
    try:
        item = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionJournalError("module artifact is not valid UTF-8 JSON") from exc
    if (not isinstance(item, dict) or item.get("schema_version") != "1.0"
            or item.get("execution_id") != execution_id
            or item.get("module") != reference.get("module")
            or item.get("status") != module_status
            or not isinstance(item.get("outcome"), dict)):
        raise ExecutionJournalError("module artifact metadata does not match its journal event")
    outcome_status = item["outcome"].get("status")
    if not isinstance(outcome_status, str) or outcome_status.strip().upper() != item["status"]:
        raise ExecutionJournalError(
            "module outcome status does not match its journal completion status"
        )
    return item


def load_completed_module_artifacts(path: str | os.PathLike[str]) -> dict:
    """Verify and load completed module sidecars for manual report reconstruction.

    This function never invokes assessment modules or resumes network activity.
    """
    journal_path = Path(path)
    report = inspect_execution_journal(journal_path)
    if not report["valid"]:
        raise ExecutionJournalError("cannot load outcomes from an invalid journal")
    artifacts = []
    for reference in report["artifact_refs"]:
        module = reference["module"]
        artifacts.append(_read_module_artifact(
            journal_path, reference, report["execution_id"],
            report["module_states"][module],
        ))
    return {
        "valid": True,
        "execution_id": report["execution_id"],
        "execution_status": report["execution_status"],
        "module_states": report["module_states"],
        "artifacts": artifacts,
    }


def _inspect_unreferenced_module_artifact(journal_path: Path, module: str) -> dict:
    """Inspect only the expected sidecar path without opening or following it."""
    try:
        module_index = MODULES.index(module) + 1
    except ValueError:
        return {"status": "INSPECTION_ERROR", "file": None, "error": "unknown_module"}
    artifact_name = f"{journal_path.stem}_module_{module_index}.json"
    artifact_path = journal_path.parent / artifact_name
    try:
        metadata = os.lstat(artifact_path)
    except FileNotFoundError:
        return {"status": "ABSENT", "file": artifact_name, "kind": None}
    except OSError as exc:
        return {"status": "INSPECTION_ERROR", "file": artifact_name, "error": type(exc).__name__}
    if stat.S_ISLNK(metadata.st_mode):
        kind = "SYMLINK"
    elif stat.S_ISREG(metadata.st_mode):
        kind = "REGULAR_FILE"
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "DIRECTORY"
    else:
        kind = "OTHER"
    return {"status": "PRESENT", "file": artifact_name, "kind": kind}

def inspect_execution_recovery(path: str | os.PathLike[str]) -> dict:
    """Build a read-only recovery assessment for journal and sidecar consistency.

    The result is diagnostic only. It never repairs evidence, resumes a module,
    or authorizes use of an unverified journal prefix.
    """
    journal_path = Path(path)
    report = inspect_execution_journal(journal_path)
    if not report["valid"]:
        return {
            "valid": False,
            "recovery_status": "JOURNAL_INVALID",
            "execution_id": report["execution_id"],
            "execution_status": "INVALID",
            "journal": report,
            "modules": [],
            "limitations": [
                "Journal verification failed; verified-prefix state is diagnostic only.",
                "Do not truncate, repair, resume, or continue this engagement.",
            ],
        }

    references = {item["module"]: item for item in report["artifact_refs"]}
    modules = []
    for module, state in report["module_states"].items():
        item = {
            "module": module,
            "journal_state": state,
            "artifact_status": "NOT_APPLICABLE",
            "artifact_file": None,
            "artifact_sha256": None,
            "error": None,
            "unreferenced_artifact": None,
        }
        if state == "STARTED":
            item["artifact_status"] = "INTERRUPTED"
        elif state == "NOT_STARTED":
            item["artifact_status"] = "NOT_STARTED"
        else:
            reference = references.get(module)
            if reference is None:
                item["artifact_status"] = "NO_ARTIFACT_RECORDED"
            else:
                item["artifact_file"] = reference["file"]
                item["artifact_sha256"] = reference["sha256"]
                try:
                    _read_module_artifact(
                        journal_path, reference, report["execution_id"], state
                    )
                    item["artifact_status"] = "VERIFIED"
                except ExecutionJournalError as exc:
                    item["artifact_status"] = "INVALID"
                    item["error"] = str(exc)
        if references.get(module) is None:
            item["unreferenced_artifact"] = _inspect_unreferenced_module_artifact(
                journal_path, module
            )
        modules.append(item)

    unresolved = any(
        item["artifact_status"] in {
            "INTERRUPTED", "NO_ARTIFACT_RECORDED", "INVALID", "NOT_STARTED"
        }
        for item in modules
    )
    return {
        "valid": True,
        "recovery_status": "REVIEW_REQUIRED" if unresolved else "EVIDENCE_VERIFIED",
        "execution_id": report["execution_id"],
        "execution_status": report["execution_status"],
        "journal": report,
        "modules": modules,
        "limitations": [
            "This is a read-only consistency assessment, not a recovery or resume operation.",
            "A missing sidecar is reported as unavailable evidence, not reconstructed or inferred.",
            "An expected sidecar without a journal reference is reported as unreferenced; its contents are never opened or adopted.",
            "Journal and artifact checksums establish byte consistency, not the truth or completeness of assessment observations.",
        ],
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
            if current["execution_status"] in {"FINALIZED", "FINALIZATION_FAILED"}:
                raise ExecutionJournalError("execution journal is already finalized")
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
        current = inspect_execution_journal(self.path)
        if (not current["valid"] or current["execution_id"] != self.execution_id
                or module not in current["module_states"]
                or current["module_states"][module] != "STARTED"
                or status not in TERMINAL_STATUSES):
            raise ExecutionJournalError("module cannot enter the requested terminal state")
        artifact_file = None
        artifact_sha256 = None
        if outcome is not None:
            if not isinstance(outcome, dict):
                raise ExecutionJournalError("module outcome artifact must be an object")
            outcome_status = outcome.get("status")
            if not isinstance(outcome_status, str) or outcome_status.strip().upper() != status:
                raise ExecutionJournalError("module outcome status must match the journal completion status")
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
            if len(payload) > MAX_MODULE_ARTIFACT_BYTES:
                raise ExecutionJournalError("module outcome exceeds the recovery artifact size limit")
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


def _print_recovery_report(path: str, report: dict) -> None:
    """Render a concise operator summary without exposing assessment outcomes."""
    print("ApexRecon execution recovery inspection")
    print("=" * 42)
    print(f"Journal: {path}")
    print(f"Recovery status: {report.get('recovery_status', 'UNKNOWN')}")
    print(f"Journal integrity: {'VALID' if report.get('valid') else 'INVALID'}")
    if report.get("execution_id"):
        print(f"Execution ID: {report['execution_id']}")
    print(f"Execution status: {report.get('execution_status', 'UNKNOWN')}")

    journal = report.get("journal", {})
    if not report.get("valid"):
        print(f"Failure code: {journal.get('failure_code') or 'unavailable'}")
        print(f"Failure sequence: {journal.get('failure_sequence') or 'unavailable'}")
        print(f"Verified prefix: {journal.get('verified_prefix_bytes', 0)} bytes")
        if journal.get("verified_prefix_sha256"):
            print(f"Verified prefix SHA-256: {journal['verified_prefix_sha256']}")
        if journal.get("error"):
            print(f"Journal error: {journal['error']}")
    else:
        print("\nModule recovery states:")
        for item in report.get("modules", []):
            print(f"  - {item['module']}: journal={item['journal_state']} | "
                  f"artifact={item['artifact_status']}")
            if item.get("artifact_file"):
                print(f"      Artifact: {item['artifact_file']}")
                print(f"      SHA-256: {item['artifact_sha256']}")
            if item.get("error"):
                print(f"      Verification error: {item['error']}")
            orphan = item.get("unreferenced_artifact")
            if orphan and orphan.get("status") != "ABSENT":
                detail = orphan.get("kind") or orphan.get("error") or "unknown"
                print(f"      Unreferenced artifact: {orphan['status']} ({detail})")

    limitations = report.get("limitations", [])
    if limitations:
        print("\nLimitations:")
        for limitation in limitations:
            print(f"  - {limitation}")


def main(argv=None) -> int:
    """Inspect an execution journal without resuming any assessment."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Read-only inspection of ApexRecon execution journals and evidence."
    )
    parser.add_argument("journal", help="path to an existing ApexRecon execution journal")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--recovery", action="store_true",
        help="inspect journal and outcome-sidecar consistency (read-only)",
    )
    mode.add_argument(
        "--verify-artifacts", action="store_true",
        help="verify and summarize completed module outcome sidecars as JSON",
    )
    args = parser.parse_args(argv)
    try:
        if args.recovery:
            report = inspect_execution_recovery(args.journal)
            _print_recovery_report(args.journal, report)
            if not report["valid"]:
                return 1
            return 0 if report["recovery_status"] == "EVIDENCE_VERIFIED" else 2

        report = inspect_execution_journal(args.journal)
        if args.verify_artifacts and report["valid"]:
            recovered = load_completed_module_artifacts(args.journal)
            report["verified_artifacts"] = [
                {"module": item["module"], "status": item["status"]}
                for item in recovered["artifacts"]
            ]
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["valid"] else 1
    except ExecutionJournalError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
