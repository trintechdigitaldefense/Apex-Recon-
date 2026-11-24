"""Adapters from legacy SMB and OSINT output to the shared finding schema.

These functions classify only observations already present in collected data.
They do not add probes, infer exploitability, or calculate risk.
"""
from __future__ import annotations

from typing import Any

from apex_findings import normalize_finding


SMB_MODULE = "SMB Network Auditor"
OSINT_MODULE = "External Footprinting (OSINT)"


def _record(
    module: str,
    check: str,
    severity: str,
    status: str,
    evidence: str,
    recommendation: str = "",
    *,
    confidence: str = "HIGH",
    evidence_type: str = "OBSERVATION",
) -> dict:
    return normalize_finding(
        {
            "check": check,
            "severity": severity,
            "status": status,
            "confidence": confidence,
            "evidence_type": evidence_type,
            "evidence": evidence,
            "recommendation": recommendation,
        },
        module,
    )


def smb_host_findings(host: dict[str, Any]) -> list[dict]:
    """Convert existing SMB parser fields to common finding records."""
    if not isinstance(host, dict):
        raise TypeError("SMB host must be an object")

    records = []
    signing = str(host.get("signing", "Unknown")).strip().upper()
    if signing == "DISABLED":
        records.append(_record(
            SMB_MODULE, "SMB_MESSAGE_SIGNING", "MEDIUM", "DISABLED",
            "Nmap SMB security-mode output reported message signing as disabled.",
            "Require SMB signing where supported and review relay mitigations.",
        ))
    elif signing == "REQUIRED":
        records.append(_record(
            SMB_MODULE, "SMB_MESSAGE_SIGNING", "INFO", "REQUIRED",
            "Nmap SMB security-mode output reported message signing as required.",
        ))

    shares = host.get("shares", [])
    if not isinstance(shares, list):
        raise TypeError("SMB shares must be a list")
    for share in shares:
        name = str(share).strip()
        if name and "$" not in name and name.upper() != "IPC":
            records.append(_record(
                SMB_MODULE, "SMB_NON_HIDDEN_SHARE", "MEDIUM", "OBSERVED",
                f"Non-hidden SMB share reported by enumeration: {name}",
                "Review share permissions and restrict access to authorized users.",
            ))

    vulnerability_checks = (
        ("ms17-010", "vuln_ms17010_status"),
        ("ms10-054", "vuln_ms10054_status"),
    )
    missing = []
    for check_name, status_key in vulnerability_checks:
        status = str(host.get(status_key, "NOT_REPORTED")).strip().upper()
        if status == "NOT_REPORTED":
            missing.append(check_name.upper())
            continue
        if status == "NOT_VULNERABLE":
            records.append(_record(
                SMB_MODULE, check_name.upper(), "INFO", "NOT_VULNERABLE",
                f"Nmap NSE reported {check_name.upper()} as NOT VULNERABLE; this is limited to that script result.",
                confidence="HIGH", evidence_type="OBSERVATION",
            ))
        elif status == "POTENTIAL":
            records.append(_record(
                SMB_MODULE, check_name.upper(), "MEDIUM", "POTENTIAL",
                f"Nmap NSE reported a potential {check_name.upper()} indicator; further validation is required.",
                "Independently validate the indicator before prioritizing remediation.",
                evidence_type="INDICATOR",
            ))
        elif status == "INDICATOR":
            records.append(_record(
                SMB_MODULE, check_name.upper(), "HIGH", "INDICATOR",
                f"Nmap NSE reported a {check_name.upper()} vulnerability indicator; this is not proof of exploitation.",
                "Independently verify the indicator and patch or mitigate if confirmed.",
                evidence_type="INDICATOR",
            ))
        else:
            missing.append(f"{check_name.upper()} (unrecognized status)")

    if signing in ("", "UNKNOWN"):
        missing.append("SMB_MESSAGE_SIGNING")
    if missing:
        records.append(_record(
            SMB_MODULE, "SMB_ASSESSMENT_COMPLETENESS", "UNKNOWN", "UNASSESSED",
            "No usable result was recorded for: " + ", ".join(missing) + ".",
            "Complete the missing SMB checks before treating the host as low risk.",
            confidence="UNKNOWN", evidence_type="UNKNOWN",
        ))
    return records


def osint_result_observations(results: dict[str, Any]) -> list[dict]:
    """Represent collected OSINT datasets as observations, never vulnerability claims."""
    if not isinstance(results, dict):
        raise TypeError("OSINT results must be an object")

    records = []
    for key in sorted(results):
        if key.startswith("DNS_"):
            values = results[key]
            if not isinstance(values, list):
                continue
            clean_values = [str(value).strip()[:500] for value in values if str(value).strip()]
            if clean_values:
                records.append(_record(
                    OSINT_MODULE, key, "INFO", "RECORDS_COLLECTED",
                    "DNS response values: " + "; ".join(clean_values[:20]),
                    confidence="HIGH", evidence_type="OBSERVATION",
                ))
        elif key == "WHOIS":
            lines = results[key]
            if isinstance(lines, list) and lines:
                fields = []
                for line in lines[:100]:
                    text = str(line).strip()
                    field = text.split(":", 1)[0].strip() if ":" in text else "WHOIS metadata"
                    if field and field not in fields:
                        fields.append(field[:100])
                records.append(_record(
                    OSINT_MODULE, "WHOIS_METADATA", "INFO", "METADATA_COLLECTED",
                    "WHOIS metadata fields returned: " + ", ".join(fields),
                    confidence="HIGH", evidence_type="OBSERVATION",
                ))
        elif key == "GEO":
            geo = results[key]
            if isinstance(geo, dict) and geo:
                fields = sorted(str(field)[:100] for field in geo.keys())[:30]
                records.append(_record(
                    OSINT_MODULE, "IP_GEOLOCATION_METADATA", "INFO", "METADATA_RETURNED",
                    "The configured geolocation provider returned fields: " + ", ".join(fields) + ". Target location values are not duplicated into this finding.",
                    confidence="HIGH", evidence_type="OBSERVATION",
                ))
        elif key == "PORTS":
            output = results[key]
            if isinstance(output, str):
                open_ports = [
                    line.strip()[:200]
                    for line in output.splitlines()
                    if "/tcp" in line and " open " in f" {line.lower()} "
                ][:40]
                if open_ports:
                    records.append(_record(
                        OSINT_MODULE, "TOP_20_TCP_PORTS", "INFO", "OPEN_PORTS_OBSERVED",
                        "Nmap top-20 TCP scan reported: " + "; ".join(open_ports),
                        "Confirm whether each exposed service is expected and appropriately restricted.",
                        confidence="HIGH", evidence_type="OBSERVATION",
                    ))
    return records
