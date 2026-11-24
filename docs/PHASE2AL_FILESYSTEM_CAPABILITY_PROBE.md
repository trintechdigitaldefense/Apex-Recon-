# Phase 2AL — Local filesystem capability probe

## Purpose

Provide a repeatable, non-destructive check of the filesystem capabilities required by ApexRecon's atomic evidence publisher. The probe creates a few small synthetic files in a temporary directory beneath the selected existing parent, verifies hard-link creation, directory fsync, atomic publication and (on POSIX) mode 0600, then removes its temporary directory.

## Run

From the repository root:

```bash
python3 -m compileall -q apex_storage.py tools tests
python3 tools/apex_storage_probe.py
```

To test another existing directory or mounted filesystem, pass that directory as the parent:

```bash
python3 tools/apex_storage_probe.py --parent /path/to/existing/test-directory
```

The probe never creates the parent directory. It creates and removes only a uniquely named `.apexrecon-fs-probe-*` temporary child directory. Atomic-publication cleanup is evaluated after the published synthetic artifact is removed, so filesystem-managed sidecars tied to that live inode are not misclassified as abandoned staging files. Do not point it at a directory containing sensitive evidence if a disposable test directory is available. The script can be invoked directly by path from the repository root; it resolves the repository root for its local `apex_storage` import.

## Report fields

- `hard_links`: whether a same-directory hard link could be created and read, and whether helper entries disappear after both link names are removed.
- `directory_fsync`: whether the probe directory could be opened and synchronized.
- `private_file_mode_0600`: observed POSIX mode for a file published by ApexRecon's atomic helper. Non-POSIX platforms report this as not evaluated.
- `atomic_publication`: whether the actual `write_exclusive_atomic` helper published and verified exact bytes, and whether its directory is clean after the probe removes the published artifact. Some compatibility filesystems expose inode-associated helper sidecars while the published link exists; those are not treated as abandoned staging files if they disappear when the final link is removed.
- `free_bytes_before/after`: informational available-space observations where `statvfs` exists.
- `temporary_artifacts_removed`: whether the probe directory was removed. Cleanup uses bounded retries for compatibility filesystems that create helper sidecars during link/unlink; any remaining cleanup failure is reported in `temporary_cleanup_error` rather than masking the capability JSON.
- `overall_atomic_storage_compatible`: true only when hard links, directory fsync, atomic publication, content verification and post-removal cleanup all pass.

Exit code 0 means the required atomic-storage checks passed. Exit code 1 means one or more capabilities are unsupported or failed. Exit code 2 means the requested parent could not be used.

## Safety and limitations

- No network access, target interaction, package installation, permission changes to existing files, or storage exhaustion.
- Uses only small synthetic files in a temporary directory on the selected filesystem.
- A successful probe is a point-in-time capability check, not proof of crash consistency, power-loss durability, kernel behavior, or correct semantics under every concurrent workload.
- Available-space values are informational and can change concurrently.
- A filesystem may support hard links but still have device, mount, or synchronization behavior that requires separate controlled validation.
- Run separately on Termux native storage, Termux/proot storage, and Linux filesystems. Record the full JSON output and exact commit SHA for each environment.
- Do not perform real ENOSPC or power-loss drills on a primary phone or production system. Those remain limited to bounded disposable filesystems and disposable VM snapshots.

## Exit gate

The probe is complete when it passes tests in CI and is executed on each available intended filesystem. Unsupported capabilities must be recorded as unsupported; do not weaken atomic publication or silently fall back to direct writes.
