# Phase 2N — Cryptographic Evidence Signing and Verification

## Purpose

Phase 2N adds detached Ed25519 signatures for structurally verified ApexRecon engagement JSON records. This supplements the existing canonical SHA-256 checksum with a cryptographic signature made by an operator-controlled private key.

## Operator workflow

From the ApexRecon main menu, select **6 — Evidence Signing / Verification**.

1. Generate an Ed25519 key pair. The private key is encrypted as PKCS#8 PEM and written with owner-only permissions (0600). A passphrase of at least 12 characters is required.
2. Sign an exported engagement JSON. ApexRecon first verifies the engagement structure and checksum, then creates a detached `.sig.json` envelope.
3. Verify a detached signature using the engagement JSON, signature envelope and trusted public key.

The signature covers the complete canonical engagement JSON record, including its existing integrity metadata. Signature and key files are created exclusively; existing files are never overwritten.

## Trust and security boundaries

- Ed25519 verifies that the signature was produced by the private key corresponding to the supplied public key and that the signed record has not changed.
- A valid signature does **not** prove that the assessment was complete, accurate, authorized or performed by the person named in a report.
- The public key must be trusted independently. Verify its SHA-256 fingerprint with the intended signer through a separate trusted channel before accepting signatures.
- The `signed_at` field is informational metadata, not a trusted timestamp authority.
- Keep the encrypted private key and passphrase separate. Never commit either to Git, include them in reports, or share them with clients. Back up the private key securely.
- Key revocation, centralized identity, hardware-backed key storage, timestamp authority integration and PDF-byte signing are not included.
- PDF reports remain correlated to the JSON record through metadata; the detached signature signs the JSON record, not the PDF bytes.
- Cryptographic signing is optional. Existing unsigned JSON/PDF export behavior remains available.
- This phase performs no scans, network requests, background work or recurring monitoring.

## Optional dependency

Install the optional signing dependency with:

```bash
python3 -m pip install -r requirements-crypto.txt
```

## Offline validation

```bash
python3 -m compileall -q apex_recon_v2.py apex_signing.py apex_engagement.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```

Tests use synthetic engagement records and temporary keys only. No live targets are contacted.

## Readiness

Passing CI and local tests validates the implementation paths, not organizational key custody, identity assurance, real-world trust distribution or client readiness. Controlled operational review is still required.
