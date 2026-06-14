#!/usr/bin/env python3
"""
ApexRecon v2.0 — TrinTech Digital Defense
Enterprise-Grade Local Network & OSINT Audit Framework
Optimized for Termux-Ubuntu proot (Android/Samsung A16)
"""

import os
import re
import sys
import json
import socket
import subprocess
import time
from datetime import datetime

# ─────────────────────────────────────────────
# ANSI Color Palette
# ─────────────────────────────────────────────
RED       = '\033[91m'
DARK_RED  = '\033[31m'
WHITE     = '\033[97m'
GREY      = '\033[90m'
CYAN      = '\033[96m'
YELLOW    = '\033[93m'
GREEN     = '\033[92m'
RESET     = '\033[0m'
BOLD      = '\033[1m'

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
LOG_FILE       = "apex_recon.log"
REPORT_FILE    = "apex_report_{}.html"
VERSION        = "2.0"
AUTHOR         = "TrinTech Digital Defense"

RISK_HIGH   = f"{RED}[HIGH]{RESET}"
RISK_MED    = f"{YELLOW}[MED] {RESET}"
RISK_LOW    = f"{GREEN}[LOW] {RESET}"
RISK_INFO   = f"{CYAN}[INFO]{RESET}"

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
def log(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {message}\n")

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{DARK_RED}
    █████╗ ██████╗ ███████╗██╗  ██╗
   ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
   ███████║██████╔╝█████╗   ╚███╔╝ 
   ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗ 
   ██║  ██║██║     ███████╗██╔╝ ██╗
   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
          {RED}{BOLD}R E C O N  v{VERSION}{RESET}
{GREY}  ══════════════════════════════════════{RESET}
     {WHITE}[ {RED}{AUTHOR}{WHITE} ]{RESET}
{GREY}  ══════════════════════════════════════{RESET}
    """)

# ─────────────────────────────────────────────
# Dependency Check
# ─────────────────────────────────────────────
def check_deps():
    deps = {"nmap": "apt-get install nmap", "whois": "apt-get install whois",
            "dig": "apt-get install dnsutils", "curl": "apt-get install curl"}
    missing = []
    for tool, install in deps.items():
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append((tool, install))
    if missing:
        print(f"\n{YELLOW}[!] Missing dependencies:{RESET}")
        for tool, cmd in missing:
            print(f"    {RED}{tool}{RESET} → run: {WHITE}{cmd}{RESET}")
        print()
    return len(missing) == 0

# ─────────────────────────────────────────────
# Utility: Run subprocess safely
# ─────────────────────────────────────────────
def run_cmd(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except FileNotFoundError:
        return "", f"NOT_FOUND:{cmd[0]}"

# ─────────────────────────────────────────────
# Utility: Auto-detect local subnet
# ─────────────────────────────────────────────
def get_local_subnet():
    try:
        # Try ip route first (works in proot)
        out, _ = run_cmd(["ip", "route"])
        for line in out.splitlines():
            if "src" in line and ("192.168" in line or "10." in line or "172." in line):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "src":
                        ip = parts[i+1]
                        # Build /24 subnet from src IP
                        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                        return subnet, ip
        # Fallback: hostname
        ip = socket.gethostbyname(socket.gethostname())
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        return subnet, ip
    except Exception:
        return None, None

# ─────────────────────────────────────────────
# SMB Parser: Extract structured data from nmap output
# ─────────────────────────────────────────────
def parse_smb_output(raw_output):
    hosts = []
    current_host = None

    for line in raw_output.splitlines():
        line = line.strip()

        # New host block
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            host_label = host_match.group(1)
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", host_label)
            ip = ip_match.group(1) if ip_match else host_label
            hostname = host_label.split(" ")[0] if "(" in host_label else ip
            current_host = {
                "ip": ip,
                "hostname": hostname,
                "os": "Unknown",
                "shares": [],
                "signing": "Unknown",
                "vuln_ms17010": False,
                "vuln_ms10054": False,
                "open_ports": [],
                "risk_level": "LOW",
                "findings": []
            }
            continue

        if not current_host:
            continue

        # Open ports
        port_match = re.match(r"(\d+/tcp)\s+open\s+(.+)", line)
        if port_match:
            current_host["open_ports"].append(f"{port_match.group(1)} {port_match.group(2)}")

        # OS Discovery
        if "OS:" in line:
            current_host["os"] = line.split("OS:")[-1].strip()

        # SMB Signing
        if "message_signing" in line:
            if "disabled" in line.lower():
                current_host["signing"] = "DISABLED"
                current_host["risk_level"] = "HIGH"
                current_host["findings"].append("SMB Signing DISABLED — relay attacks possible (MEDIUM risk)")
            elif "required" in line.lower():
                current_host["signing"] = "Required"
            else:
                current_host["signing"] = line.split(":")[-1].strip()

        # Shares
        if re.match(r"\s*\\\\", "  " + line) or ("$" in line and "Disk" in line) or \
           ("IPC" in line) or ("ADMIN" in line) or ("SYSVOL" in line) or ("NETLOGON" in line):
            share_match = re.search(r"(\\\\[^\s]+|[A-Z][A-Z0-9_\-$]+)\s+(Disk|IPC|Printer)?", line)
            if share_match and share_match.group(1) not in current_host["shares"]:
                share = share_match.group(1).strip()
                current_host["shares"].append(share)
                if "$" not in share and "IPC" not in share:
                    current_host["findings"].append(f"Non-hidden share detected: {share} — verify permissions")

        # EternalBlue
        if "ms17-010" in line.lower():
            if "vulnerable" in line.lower() or "VULNERABLE" in line:
                current_host["vuln_ms17010"] = True
                current_host["risk_level"] = "CRITICAL"
                current_host["findings"].append("CRITICAL: MS17-010 (EternalBlue) — VULNERABLE to remote code execution!")

        # MS10-054
        if "ms10-054" in line.lower():
            if "vulnerable" in line.lower():
                current_host["vuln_ms10054"] = True
                current_host["risk_level"] = "HIGH"
                current_host["findings"].append("HIGH: MS10-054 SMB memory corruption vulnerability detected")

    if current_host:
        hosts.append(current_host)

    return hosts

# ─────────────────────────────────────────────
# Risk Badge helper
# ─────────────────────────────────────────────
def risk_badge(level):
    badges = {
        "CRITICAL": RISK_HIGH,
        "HIGH":     RISK_HIGH,
        "MED":      RISK_MED,
        "MEDIUM":   RISK_MED,
        "LOW":      RISK_LOW,
        "INFO":     RISK_INFO,
    }
    return badges.get(level.upper(), RISK_INFO)

# ─────────────────────────────────────────────
# HTML Report Generator — v2.0 Enterprise UI
# ─────────────────────────────────────────────
def generate_html_report(hosts, target, scan_duration, module_name="SMB Audit"):
    filename = REPORT_FILE.format(datetime.now().strftime("%Y%m%d_%H%M%S"))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    total    = len(hosts)
    critical = sum(1 for h in hosts if h["risk_level"] == "CRITICAL")
    high     = sum(1 for h in hosts if h["risk_level"] == "HIGH")
    clean    = sum(1 for h in hosts if h["risk_level"] == "LOW")

    # ── Build host cards ──────────────────────
    host_cards_html = ""
    for i, h in enumerate(hosts):
        rl = h["risk_level"].upper()
        risk_class = rl.lower() if rl in ("CRITICAL","HIGH","MEDIUM","LOW") else "low"
        pill_class = risk_class

        # Vuln badges
        vuln_eb = '⚠ VULNERABLE' if h["vuln_ms17010"] else '✓ Clean'
        vuln_eb_cls = 'vulnerable' if h["vuln_ms17010"] else 'clean'
        vuln_ms = '⚠ VULNERABLE' if h["vuln_ms10054"] else '✓ Clean'
        vuln_ms_cls = 'vulnerable' if h["vuln_ms10054"] else 'clean'

        signing_val = h.get("signing", "Unknown")
        if signing_val == "DISABLED":
            sign_cls = "warn"
            sign_txt = "⚠ DISABLED"
        elif "required" in signing_val.lower():
            sign_cls = "clean"
            sign_txt = "✓ Required"
        else:
            sign_cls = "warn"
            sign_txt = signing_val

        # Ports
        ports_html = "".join(
            f'<div class="port-chip">{p}</div>' for p in h["open_ports"]
        ) or '<div class="port-chip" style="color:var(--muted)">None detected</div>'

        # Shares
        shares_html = ""
        for s in h["shares"]:
            is_system = "$" in s or "IPC" in s
            dot_cls  = "system" if is_system else "exposed"
            tag_txt  = "SYSTEM" if is_system else "EXPOSED"
            shares_html += f'''
            <div class="share-item">
              <div class="share-dot {dot_cls}"></div>
              <div class="share-name">{s}</div>
              <div class="share-tag">{tag_txt}</div>
            </div>'''
        if not shares_html:
            shares_html = '<div class="share-item"><div class="share-name" style="color:var(--muted)">None detected</div></div>'

        # Findings
        findings_html = ""
        for f in h["findings"]:
            fu = f.upper()
            if "CRITICAL" in fu:
                sev, sev_cls = "CRIT", "crit"
                rec = "→ Patch immediately and isolate host from network."
            elif "HIGH" in fu:
                sev, sev_cls = "HIGH", "high"
                rec = "→ Remediate within 24 hours. Review access controls."
            elif "SIGNING" in fu or "RELAY" in fu:
                sev, sev_cls = "HIGH", "high"
                rec = "→ Enable SMB signing via Group Policy immediately."
            elif "SHARE" in fu or "NON-HIDDEN" in fu:
                sev, sev_cls = "MED", "med"
                rec = "→ Audit share permissions. Apply least-privilege access."
            else:
                sev, sev_cls = "INFO", "info"
                rec = "→ Monitor and document."
            findings_html += f'''
            <div class="finding-item">
              <div class="finding-sev {sev_cls}">{sev}</div>
              <div>
                <div class="finding-text">{f}</div>
                <div class="finding-rec">{rec}</div>
              </div>
            </div>'''
        if not findings_html:
            findings_html = '''
            <div class="finding-item">
              <div class="finding-sev info">INFO</div>
              <div>
                <div class="finding-text">No critical findings detected on this host</div>
                <div class="finding-rec">→ Maintain current patch level. Continue monitoring.</div>
              </div>
            </div>'''

        anim_delay = f"{0.05 + i * 0.07:.2f}s"

        host_cards_html += f"""
  <div class="host-card risk-{risk_class}" style="animation-delay:{anim_delay}">
    <div class="host-card-header">
      <div class="host-ip">{h['ip']}</div>
      <div class="host-name">{h['hostname']}</div>
      <div class="host-os">{h['os']}</div>
      <div class="risk-pill {pill_class}">{rl}</div>
    </div>
    <div class="host-card-body">
      <div class="host-section">
        <div class="host-section-title">Vulnerability Status</div>
        <div class="vuln-row">
          <div><div class="vuln-name">EternalBlue</div><div class="vuln-cve">CVE MS17-010</div></div>
          <div class="vuln-status {vuln_eb_cls}">{vuln_eb}</div>
        </div>
        <div class="vuln-row">
          <div><div class="vuln-name">SMB Memory Corruption</div><div class="vuln-cve">CVE MS10-054</div></div>
          <div class="vuln-status {vuln_ms_cls}">{vuln_ms}</div>
        </div>
        <div class="vuln-row">
          <div><div class="vuln-name">SMB Signing</div><div class="vuln-cve">Relay attack vector</div></div>
          <div class="vuln-status {sign_cls}">{sign_txt}</div>
        </div>
      </div>
      <div class="host-section">
        <div class="host-section-title">Open Ports</div>
        <div class="port-grid">{ports_html}</div>
      </div>
      <div class="host-section">
        <div class="host-section-title">SMB Shares</div>
        {shares_html}
      </div>
      <div class="host-section">
        <div class="host-section-title">Findings &amp; Recommendations</div>
        {findings_html}
      </div>
    </div>
  </div>"""

    no_hosts_msg = '' if host_cards_html else \
        '<p style="color:var(--muted);font-family:var(--mono);padding:24px;">No live SMB hosts found on target range.</p>'

    # ── Full HTML ─────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ApexRecon v{VERSION} — Audit Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:       #07080d;
    --surface:  #0d0f1a;
    --card:     #10121f;
    --border:   #1a1d30;
    --red:      #e8001c;
    --red-dim:  #6b0010;
    --cyan:     #00c8f0;
    --cyan-dim: #004f60;
    --gold:     #f0a500;
    --green:    #00e676;
    --orange:   #ff6d00;
    --text:     #d0d4e8;
    --muted:    #4a5070;
    --mono:     'Share Tech Mono', monospace;
    --display:  'Orbitron', sans-serif;
    --ui:       'Rajdhani', sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--ui); font-size: 15px; line-height: 1.6; min-height: 100vh; }}
  body::before {{ content: ''; position: fixed; inset: 0; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.08) 2px, rgba(0,0,0,0.08) 4px); pointer-events: none; z-index: 999; }}
  .page {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }}
  .report-header {{ position: relative; border-bottom: 1px solid var(--border); padding-bottom: 28px; margin-bottom: 28px; overflow: hidden; }}
  .header-glow {{ position: absolute; top: -60px; left: -40px; width: 400px; height: 200px; background: radial-gradient(ellipse, rgba(232,0,28,0.12) 0%, transparent 70%); pointer-events: none; }}
  .header-top {{ display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }}
  .brand-eyebrow {{ font-family: var(--mono); font-size: 10px; color: var(--red); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 6px; }}
  .brand-name {{ font-family: var(--display); font-size: 2rem; font-weight: 900; color: #fff; letter-spacing: 2px; line-height: 1; }}
  .brand-name span {{ color: var(--red); }}
  .brand-sub {{ font-family: var(--mono); font-size: 11px; color: var(--cyan); letter-spacing: 3px; margin-top: 8px; }}
  .header-actions {{ display: flex; flex-direction: column; align-items: flex-end; gap: 10px; }}
  .print-btn {{ font-family: var(--display); font-size: 11px; font-weight: 700; letter-spacing: 2px; color: #000; background: var(--cyan); border: none; padding: 10px 20px; cursor: pointer; clip-path: polygon(8px 0%, 100% 0%, calc(100% - 8px) 100%, 0% 100%); transition: background 0.2s; }}
  .print-btn:hover {{ background: #fff; }}
  .timestamp {{ font-family: var(--mono); font-size: 10px; color: var(--muted); text-align: right; }}
  .meta-bar {{ display: flex; gap: 0; flex-wrap: wrap; border: 1px solid var(--border); overflow: hidden; margin-bottom: 0; }}
  .meta-item {{ flex: 1; min-width: 140px; padding: 10px 16px; border-right: 1px solid var(--border); }}
  .meta-item:last-child {{ border-right: none; }}
  .meta-label {{ font-family: var(--mono); font-size: 9px; color: var(--muted); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 3px; }}
  .meta-value {{ font-family: var(--mono); font-size: 13px; color: var(--cyan); }}
  .confidential-bar {{ background: var(--red-dim); border: 1px solid var(--red); padding: 8px 16px; margin-bottom: 28px; display: flex; align-items: center; gap: 12px; }}
  .confidential-bar span {{ font-family: var(--display); font-size: 10px; font-weight: 700; letter-spacing: 4px; color: var(--red); white-space: nowrap; }}
  .confidential-bar p {{ font-family: var(--mono); font-size: 10px; color: var(--muted); }}
  .threat-summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 36px; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); padding: 20px 16px; position: relative; overflow: hidden; }}
  .stat-card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }}
  .stat-card.s-total::before  {{ background: var(--cyan); }}
  .stat-card.s-crit::before   {{ background: var(--red); }}
  .stat-card.s-high::before   {{ background: var(--orange); }}
  .stat-card.s-clean::before  {{ background: var(--green); }}
  .stat-card.s-dur::before    {{ background: var(--gold); }}
  .stat-num {{ font-family: var(--display); font-size: 2.4rem; font-weight: 900; line-height: 1; margin-bottom: 6px; }}
  .stat-card.s-total .stat-num  {{ color: var(--cyan); }}
  .stat-card.s-crit  .stat-num  {{ color: var(--red); }}
  .stat-card.s-high  .stat-num  {{ color: var(--orange); }}
  .stat-card.s-clean .stat-num  {{ color: var(--green); }}
  .stat-card.s-dur   .stat-num  {{ color: var(--gold); font-size: 1.6rem; }}
  .stat-label {{ font-family: var(--mono); font-size: 9px; color: var(--muted); letter-spacing: 3px; text-transform: uppercase; }}
  .stat-icon {{ position: absolute; bottom: 12px; right: 14px; font-size: 1.6rem; opacity: 0.12; }}
  .section-heading {{ display: flex; align-items: center; gap: 14px; margin-bottom: 16px; margin-top: 8px; }}
  .section-heading h2 {{ font-family: var(--display); font-size: 0.75rem; font-weight: 700; letter-spacing: 4px; color: var(--muted); text-transform: uppercase; white-space: nowrap; }}
  .section-line {{ flex: 1; height: 1px; background: var(--border); }}
  .host-card {{ background: var(--card); border: 1px solid var(--border); margin-bottom: 20px; position: relative; overflow: hidden; animation: fadeUp 0.4s ease both; }}
  .host-card::after {{ content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%; }}
  .host-card.risk-critical::after {{ background: var(--red); }}
  .host-card.risk-high::after     {{ background: var(--orange); }}
  .host-card.risk-medium::after   {{ background: var(--gold); }}
  .host-card.risk-low::after      {{ background: var(--green); }}
  .host-card-header {{ display: flex; align-items: center; gap: 16px; padding: 16px 20px 14px 24px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }}
  .host-ip {{ font-family: var(--display); font-size: 1.1rem; font-weight: 700; color: var(--cyan); letter-spacing: 1px; }}
  .host-name {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
  .host-os {{ font-family: var(--mono); font-size: 11px; color: var(--text); background: var(--surface); padding: 3px 10px; border: 1px solid var(--border); }}
  .risk-pill {{ margin-left: auto; font-family: var(--display); font-size: 10px; font-weight: 700; letter-spacing: 2px; padding: 5px 14px; clip-path: polygon(6px 0%, 100% 0%, calc(100% - 6px) 100%, 0% 100%); }}
  .risk-pill.critical {{ background: var(--red);    color: #fff; }}
  .risk-pill.high     {{ background: var(--orange); color: #000; }}
  .risk-pill.medium   {{ background: var(--gold);   color: #000; }}
  .risk-pill.low      {{ background: var(--green);  color: #000; }}
  .host-card-body {{ display: grid; grid-template-columns: 1fr 1fr; }}
  .host-section {{ padding: 16px 20px 16px 24px; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); }}
  .host-section:nth-child(even) {{ border-right: none; }}
  .host-section:nth-last-child(-n+2) {{ border-bottom: none; }}
  .host-section-title {{ font-family: var(--mono); font-size: 9px; color: var(--red); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 10px; }}
  .vuln-row {{ display: flex; align-items: center; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 12px; }}
  .vuln-row:last-child {{ border-bottom: none; }}
  .vuln-name {{ color: var(--text); }}
  .vuln-cve  {{ color: var(--muted); font-size: 10px; }}
  .vuln-status {{ font-size: 11px; font-weight: 700; }}
  .vuln-status.vulnerable {{ color: var(--red); }}
  .vuln-status.clean      {{ color: var(--green); }}
  .vuln-status.warn       {{ color: var(--orange); }}
  .port-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .port-chip {{ font-family: var(--mono); font-size: 11px; padding: 4px 10px; border: 1px solid var(--cyan-dim); color: var(--cyan); background: rgba(0,200,240,0.04); }}
  .share-item {{ display: flex; align-items: center; gap: 10px; padding: 5px 0; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 12px; }}
  .share-item:last-child {{ border-bottom: none; }}
  .share-dot {{ width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }}
  .share-dot.exposed {{ background: var(--orange); }}
  .share-dot.system  {{ background: var(--muted); }}
  .share-name {{ color: var(--text); flex: 1; }}
  .share-tag  {{ font-size: 9px; color: var(--muted); border: 1px solid var(--border); padding: 1px 6px; }}
  .finding-item {{ display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 12px; line-height: 1.5; }}
  .finding-item:last-child {{ border-bottom: none; }}
  .finding-sev {{ flex-shrink: 0; font-size: 9px; font-weight: 700; letter-spacing: 1px; padding: 2px 6px; height: fit-content; margin-top: 2px; }}
  .finding-sev.crit {{ background: var(--red);      color: #fff; }}
  .finding-sev.high {{ background: var(--orange);   color: #000; }}
  .finding-sev.med  {{ background: var(--gold);     color: #000; }}
  .finding-sev.info {{ background: var(--cyan-dim); color: var(--cyan); }}
  .finding-text {{ color: var(--text); }}
  .finding-rec  {{ color: var(--muted); font-size: 11px; margin-top: 2px; }}
  .report-footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 16px; }}
  .footer-brand {{ font-family: var(--display); font-size: 11px; font-weight: 700; color: var(--muted); letter-spacing: 2px; }}
  .footer-brand span {{ color: var(--red); }}
  .footer-notice {{ font-family: var(--mono); font-size: 10px; color: var(--muted); text-align: right; max-width: 400px; line-height: 1.6; }}
  @keyframes fadeUp {{ from {{ opacity: 0; transform: translateY(12px); }} to {{ opacity: 1; transform: translateY(0); }} }}
  @media (max-width: 640px) {{ .host-card-body {{ grid-template-columns: 1fr; }} .host-section {{ border-right: none !important; }} }}
  @media print {{ body::before {{ display: none; }} .print-btn {{ display: none; }} .host-card {{ break-inside: avoid; animation: none; }} }}
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div class="header-glow"></div>
    <div class="header-top">
      <div class="brand-block">
        <div class="brand-eyebrow">// confidential security assessment</div>
        <div class="brand-name">APEX<span>RECON</span></div>
        <div class="brand-sub">v{VERSION} &nbsp;·&nbsp; {AUTHOR} &nbsp;·&nbsp; NETWORK AUDIT REPORT</div>
      </div>
      <div class="header-actions">
        <button class="print-btn" onclick="window.print()">&#11015; EXPORT PDF</button>
        <div class="timestamp">Generated: {now}</div>
      </div>
    </div>
    <div class="meta-bar">
      <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{target}</div></div>
      <div class="meta-item"><div class="meta-label">Module</div><div class="meta-value">{module_name}</div></div>
      <div class="meta-item"><div class="meta-label">Scan Duration</div><div class="meta-value">{scan_duration}s</div></div>
      <div class="meta-item"><div class="meta-label">Auditor</div><div class="meta-value">TrinTech DD</div></div>
      <div class="meta-item"><div class="meta-label">Classification</div><div class="meta-value" style="color:var(--red)">CONFIDENTIAL</div></div>
    </div>
  </div>

  <div class="confidential-bar">
    <span>&#9888; CONFIDENTIAL</span>
    <p>This report contains sensitive security findings. Distribute only to authorized personnel. Unauthorized disclosure is prohibited.</p>
  </div>

  <div class="threat-summary">
    <div class="stat-card s-total"><div class="stat-num">{total}</div><div class="stat-label">Hosts Found</div><div class="stat-icon">&#9672;</div></div>
    <div class="stat-card s-crit"><div class="stat-num">{critical}</div><div class="stat-label">Critical Risk</div><div class="stat-icon">&#9888;</div></div>
    <div class="stat-card s-high"><div class="stat-num">{high}</div><div class="stat-label">High Risk</div><div class="stat-icon">&#9650;</div></div>
    <div class="stat-card s-clean"><div class="stat-num">{clean}</div><div class="stat-label">Clean Hosts</div><div class="stat-icon">&#10003;</div></div>
    <div class="stat-card s-dur"><div class="stat-num">{scan_duration}s</div><div class="stat-label">Scan Time</div><div class="stat-icon">&#9711;</div></div>
  </div>

  <div class="section-heading">
    <h2>Host Findings</h2>
    <div class="section-line"></div>
  </div>

  {host_cards_html}
  {no_hosts_msg}

  <div class="report-footer">
    <div class="footer-brand">APEX<span>RECON</span> v{VERSION}</div>
    <div class="footer-notice">
      This report is confidential and intended solely for authorized audit use.<br>
      &copy; 2026 {AUTHOR} &mdash; Trinidad and Tobago<br>
      trintechdigitaldefense.github.io
    </div>
  </div>

</div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    return filename

# ─────────────────────────────────────────────
# MODULE 1: OSINT — External Footprinting
# ─────────────────────────────────────────────
def osint_module():
    print_banner()
    print(f"{RED}[*] External Footprinting (OSINT Module){RESET}\n")
    domain = input(f"{WHITE}Enter target domain (e.g., example.com): {RESET}").strip()

    if not domain:
        print(f"{RED}[!] Domain cannot be blank.{RESET}")
        time.sleep(1.5)
        return

    log(f"OSINT scan started on domain: {domain}")
    results = {}

    # ── DNS Records ──────────────────────────────
    print(f"\n{CYAN}[+] Resolving DNS records...{RESET}")
    for rtype in ["A", "MX", "NS", "TXT", "CNAME"]:
        out, err = run_cmd(["dig", "+short", rtype, domain])
        if out:
            results[f"DNS_{rtype}"] = out.splitlines()
            print(f"  {GREY}{rtype:6}{RESET} → {WHITE}{out.replace(chr(10), ', ')}{RESET}")
        else:
            print(f"  {GREY}{rtype:6}{RESET} → {RED}No record{RESET}")

    # ── WHOIS ────────────────────────────────────
    print(f"\n{CYAN}[+] Running WHOIS lookup...{RESET}")
    out, _ = run_cmd(["whois", domain], timeout=30)
    if out:
        important = []
        for line in out.splitlines():
            for kw in ["Registrar:", "Creation Date:", "Expiry Date:", "Updated Date:",
                       "Name Server:", "Registrant", "Admin", "Tech"]:
                if kw.lower() in line.lower():
                    important.append(line.strip())
                    break
        results["WHOIS"] = important
        for line in important[:12]:
            print(f"  {GREY}{line}{RESET}")

    # ── IP Geolocation ───────────────────────────
    print(f"\n{CYAN}[+] Geolocating IP...{RESET}")
    try:
        ip = socket.gethostbyname(domain)
        out, _ = run_cmd(["curl", "-s", f"https://ipinfo.io/{ip}/json"], timeout=15)
        if out:
            try:
                geo = json.loads(out)
                results["GEO"] = geo
                for k in ["ip", "city", "region", "country", "org", "timezone"]:
                    if k in geo:
                        print(f"  {GREY}{k:12}{RESET} → {WHITE}{geo[k]}{RESET}")
            except Exception:
                print(f"  {GREY}Raw: {out[:200]}{RESET}")
    except Exception as e:
        print(f"  {RED}Could not resolve IP: {e}{RESET}")

    # ── Open Ports (Quick Top 20) ────────────────
    print(f"\n{CYAN}[+] Scanning common external ports (top 20)...{RESET}")
    log(f"OSINT port scan on {domain}")
    out, err = run_cmd([
        "nmap", "-Pn", "--open", "-F",
        "--script", "banner",
        domain
    ], timeout=90)

    if "NOT_FOUND" in err:
        print(f"  {RED}nmap not installed — apt-get install nmap{RESET}")
    elif out:
        results["PORTS"] = out
        # Print only port lines
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                print(f"  {GREEN}✓{RESET} {WHITE}{line.strip()}{RESET}")

    # ── Summary ──────────────────────────────────
    print(f"\n{GREY}[+] OSINT collection complete. Data logged.{RESET}")
    log(f"OSINT complete for {domain}: {json.dumps(results, indent=2)}")

    input(f"\n{GREY}Press Enter to return to main menu...{RESET}")

# ─────────────────────────────────────────────
# MODULE 2: SMB Network Auditor
# ─────────────────────────────────────────────
def smb_auditor_module():
    print_banner()
    print(f"{RED}[*] Local Network SMB Auditor — Enterprise Build{RESET}\n")

    # Auto-detect subnet
    subnet, local_ip = get_local_subnet()
    if subnet:
        print(f"{GREY}[auto-detected]{RESET} Local IP: {CYAN}{local_ip}{RESET}  Subnet: {CYAN}{subnet}{RESET}")
        use_auto = input(f"{WHITE}Use detected subnet? (Y/n): {RESET}").strip().lower()
        if use_auto in ("", "y"):
            target_ip = subnet
        else:
            target_ip = input(f"{WHITE}Enter Target IP/Subnet: {RESET}").strip()
    else:
        target_ip = input(f"{WHITE}Enter Target IP/Subnet (e.g., 192.168.1.0/24): {RESET}").strip()

    if not target_ip:
        print(f"{RED}[!] Error: Target cannot be blank.{RESET}")
        time.sleep(1.5)
        return

    print(f"\n{GREY}[+] Launching enterprise SMB enumeration...{RESET}")
    print(f"{GREY}    → Discovery + Share enum + Vuln checks (MS17-010, MS10-054){RESET}")
    print(f"{GREY}    Target: {RESET}{CYAN}{target_ip}{RESET}\n")
    log(f"SMB Audit v2 started on {target_ip}")

    nmap_cmd = [
        "nmap", "-Pn", "--open",
        "-p", "139,445",
        "--script",
        "smb-os-discovery,smb-enum-shares,smb-security-mode,"
        "smb-vuln-ms17-010,smb-vuln-ms10-054",
        "-T4",
        target_ip
    ]

    start = time.time()
    out, err = run_cmd(nmap_cmd, timeout=300)
    duration = round(time.time() - start, 2)

    if "NOT_FOUND" in err:
        print(f"{RED}[!] nmap not installed — run: apt-get install nmap{RESET}")
        log("ERROR: nmap not found")
        input(f"\n{GREY}Press Enter to return...{RESET}")
        return

    if not out:
        print(f"{YELLOW}[!] No output returned. Check target or network connectivity.{RESET}")
        input(f"\n{GREY}Press Enter to return...{RESET}")
        return

    print(f"{GREY}--- Raw Output ---{RESET}\n{out}\n{GREY}------------------{RESET}\n")

    # Parse into structured objects
    hosts = parse_smb_output(out)

    if not hosts:
        print(f"{YELLOW}[!] No SMB hosts detected on {target_ip}{RESET}")
    else:
        print(f"\n{RED}[!] Parsed Findings:{RESET}\n")
        for h in hosts:
            badge = risk_badge(h["risk_level"])
            print(f"  {badge} {CYAN}{h['ip']}{RESET}  ({h['hostname']})  OS: {WHITE}{h['os']}{RESET}")
            if h["signing"] != "Unknown":
                print(f"         SMB Signing: {WHITE}{h['signing']}{RESET}")
            if h["vuln_ms17010"]:
                print(f"         {RED}⚠ EternalBlue (MS17-010) — VULNERABLE{RESET}")
            if h["shares"]:
                print(f"         Shares: {WHITE}{', '.join(h['shares'])}{RESET}")
            for finding in h["findings"]:
                print(f"         {YELLOW}→ {finding}{RESET}")
            print()

        # Generate HTML report
        report_path = generate_html_report(hosts, target_ip, duration)
        print(f"{GREEN}[+] HTML Audit Report saved: {BOLD}{report_path}{RESET}")
        log(f"Report saved: {report_path}")

    log(f"SMB Audit complete in {duration}s. Hosts found: {len(hosts)}")
    log(f"Raw output:\n{out}\n")

    input(f"\n{GREY}Press Enter to return to main menu...{RESET}")

# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────
def main_menu():
    print_banner()
    print(f"{WHITE}Target Engagement Modules:{RESET}\n")
    print(f"  {RED}[1]{RESET} {WHITE}External Footprinting (OSINT){RESET}")
    print(f"       {GREY}DNS · WHOIS · GeoIP · Open Ports · Banner grab{RESET}")
    print(f"  {RED}[2]{RESET} {WHITE}Local Network SMB Auditor{RESET}")
    print(f"       {GREY}Host discovery · Share enum · EternalBlue check · HTML report{RESET}")
    print(f"  {RED}[9]{RESET} {WHITE}Exit Framework{RESET}\n")
    return input(f"{RED}Apex{WHITE}@{RED}TrinTech{WHITE}:~#{RESET} ")

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print(f"{GREY}Checking dependencies...{RESET}")
    check_deps()
    time.sleep(0.5)
    log(f"ApexRecon v{VERSION} started.")

    while True:
        choice = main_menu()
        if choice == '1':
            osint_module()
        elif choice == '2':
            smb_auditor_module()
        elif choice == '9':
            print(f"{GREY}Terminating session...{RESET}")
            log("ApexRecon exited cleanly.")
            sys.exit(0)
        else:
            print(f"{RED}[!] Invalid selection.{RESET}")
            time.sleep(1)
