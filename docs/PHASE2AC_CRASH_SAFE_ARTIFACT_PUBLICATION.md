# Phase 2AC — Crash-safe assessment artifact publication

## Purpose

Prevent an interrupted report write from leaving a truncated JSON or PDF file at the final evidence filename. Phase 2AC hardens local artifact publication only; it does not change assessment execution, target scope, or network behavior.

## Publication behavior

The shared apex_storage.py helper now publishes HTTP/TLS evidence JSON, individual assessment PDFs, unified engagement JSON, and unified engagement PDFs using this sequence:

1. Create a uniquely named hidden staging file in the destination directory.
2. Apply owner-only permissions on POSIX systems.
3. Write the complete artifact, flush it, and call fsync on the file.
4. Publish the staged inode at the final path with a same-directory hard link. This is an atomic create-only operation and fails if the destination already exists.
5. Remove the temporary staging name and sync the containing directory where supported.

The final report path is not visible until the complete staged contents have been written and flushed. Existing artifacts are never replaced.

## Interruption and recovery behavior

- If the process stops while writing the staging file, the final report path is not created. A hidden .apexrecon-tmp-* staging file may remain.
- If the process stops after publication, the final path refers to the complete staged file. A hidden staging name may also remain if interruption occurred before cleanup.
- The helper removes staging files after ordinary success or failure.
- Do not treat hidden staging files as completed reports. Review and remove stale .apexrecon-tmp-* files manually after confirming no ApexRecon process is using them.
- Publication relies on same-directory hard-link support. If the filesystem does not support hard links, publication fails closed rather than falling back to a potentially partial final-file write.
- File data is fsynced before publication; directory fsync is attempted on POSIX systems. Actual power-loss guarantees still depend on the filesystem and storage hardware.

## Scope

- Updated HTTP/TLS JSON evidence and PDF export.
- Updated unified engagement JSON and PDF export.
- Preserved exclusive create behavior, owner-only file permissions, checksums, report schemas, and existing filenames.
- No change to audit JSONL append/recovery behavior, key-pair multi-file transactions, audit backup formats, scan commands, target validation, authorization prompts, request counts, methods, paths, ports, probes, redirects, or assessment scope.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents, or monitoring.
- No live targets contacted.

## Validation

Run the offline test suite:

```bash
python3 -m compileall -q apex_storage.py apex_evidence.py apex_engagement.py tests
python3 -m unittest discover -s tests -v
```

The new tests exercise successful publication, create-only collision handling, staged-write failure, publication failure, directory-sync failure, cleanup, and permission modes. They use temporary local directories and do not contact targets.

## Limitations

Atomic publication prevents readers from seeing a partially written final report. It does not provide immutable storage, a transaction across multiple separate artifacts, guaranteed cleanup after power loss, or proof that the assessment itself completed accurately. The SHA-256 evidence checksums and detached signatures retain their existing meanings and limitations.
