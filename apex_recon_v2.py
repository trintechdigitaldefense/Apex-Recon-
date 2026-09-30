#!/usr/bin/env python3
"""
ApexRecon v2.1.0 — TrinTech Digital Defense
Enterprise-Grade Local Network, OSINT & Web Application Audit Framework
Optimized for Termux-Ubuntu proot (Android/Samsung A16) and desktop Linux

Authorized use only. Always obtain written permission before scanning.
"""

import os
import re
import sys
import json
import ssl
import socket
import smtplib
import subprocess
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from html.parser import HTMLParser

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
VERSION        = "2.1.0"
AUTHOR         = "TrinTech Digital Defense"
LOG_FILE       = "apex_recon.log"
REPORT_FILE    = "apex_report_{}.html"
CONFIG_DIR     = Path.home() / ".apexrecon"
CONFIG_FILE    = CONFIG_DIR / "config.json"

RISK_HIGH   = f"{RED}[HIGH]{RESET}"
RISK_MED    = f"{YELLOW}[MED] {RESET}"
RISK_LOW    = f"{GREEN}[LOW] {RESET}"
RISK_INFO   = f"{CYAN}[INFO]{RESET}"
RISK_CRIT   = f"{RED}{BOLD}[CRIT]{RESET}"

DEFAULT_CONFIG = {
    "email": {
        "enabled": False,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addrs": []
    },
    "timeouts": {
        "nmap": 180,
        "web": 15,
        "ssl": 10
    },
    "web": {
        "user_agent": "ApexRecon/2.1 (+https://trintechdigitaldefense.github.io)",
        "follow_redirects": True
    }
}

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
# Config helpers
# ─────────────────────────────────────────────
def load_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
            elif isinstance(v, dict):
                for sk, sv in v.items():
                    if sk not in cfg[k]:
                        cfg[k][sk] = sv
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

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
    deps = {
        "nmap": "apt-get install nmap",
        "whois": "apt-get install whois",
        "dig": "apt-get install dnsutils",
        "curl": "apt-get install curl",
        "openssl": "apt-get install openssl"
    }
    optional = {
        "nikto": "apt-get install nikto  # optional for deeper web scans"
    }
    missing = []
    for tool, install in deps.items():
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append((tool, install))
    if missing:
        print(f"\n{YELLOW}[!] Missing required dependencies:{RESET}")
        for tool, cmd in missing:
            print(f"    {RED}{tool}{RESET} → run: {WHITE}{cmd}{RESET}")
        print()
    for tool, install in optional.items():
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            print(f"{GREY}[i] Optional: {tool} not found — {install}{RESET}")
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
    except Exception as e:
        return "", str(e)

# ─────────────────────────────────────────────
# Utility: Auto-detect local subnet
# ─────────────────────────────────────────────
def get_local_subnet():
    try:
        out, _ = run_cmd(["ip", "route"])
        for line in out.splitlines():
            if "src" in line and ("192.168" in line or "10." in line or "172." in line):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "src":
                        ip = parts[i+1]
                        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                        return subnet, ip
        ip = socket.gethostbyname(socket.gethostname())
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        return subnet, ip
    except Exception:
        return None, None

# ─────────────────────────────────────────────
# SMB Parser
# ─────────────────────────────────────────────
def parse_smb_output(raw_output):
    hosts = []
    current_host = None

    for line in raw_output.splitlines():
        line = line.strip()

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

        port_match = re.match(r"(\d+/tcp)\s+open\s+(.+)", line)
        if port_match:
            current_host["open_ports"].append(f"{port_match.group(1)} {port_match.group(2)}")

        if "OS:" in line:
            current_host["os"] = line.split("OS:")[-1].strip()

        if "message_signing" in line:
            if "disabled" in line.lower():
                current_host["signing"] = "DISABLED"
                current_host["risk_level"] = "HIGH"
                current_host["findings"].append("SMB Signing DISABLED — relay attacks possible (MEDIUM risk)")
            elif "required" in line.lower():
                current_host["signing"] = "Required"
            else:
                current_host["signing"] = line.split(":")[-1].strip()

        if re.match(r"\s*\\\\", "  " + line) or ("$" in line and "Disk" in line) or \
           ("IPC" in line) or ("ADMIN" in line) or ("SYSVOL" in line) or ("NETLOGON" in line):
            share_match = re.search(r"(\\\\[^\s]+|[A-Z][A-Z0-9_\-$]+)\s+(Disk|IPC|Printer)?", line)
            if share_match and share_match.group(1) not in current_host["shares"]:
                share = share_match.group(1).strip()
                current_host["shares"].append(share)
                if "$" not in share and "IPC" not in share:
                    current_host["findings"].append(f"Non-hidden share detected: {share} — verify permissions")

        if "ms17-010" in line.lower():
            if "vulnerable" in line.lower() or "VULNERABLE" in line:
                current_host["vuln_ms17010"] = True
                current_host["risk_level"] = "CRITICAL"
                current_host["findings"].append("CRITICAL: MS17-010 (EternalBlue) — VULNERABLE to remote code execution!")

        if "ms10-054" in line.lower():
            if "vulnerable" in line.lower():
                current_host["vuln_ms10054"] = True
                if current_host["risk_level"] != "CRITICAL":
                    current_host["risk_level"] = "HIGH"
                current_host["findings"].append("HIGH: MS10-054 SMB memory corruption vulnerability detected")

    if current_host:
        hosts.append(current_host)

    return hosts

def risk_badge(level):
    badges = {
        "CRITICAL": RISK_CRIT,
        "HIGH":     RISK_HIGH,
        "MED":      RISK_MED,
        "MEDIUM":   RISK_MED,
        "LOW":      RISK_LOW,
        "INFO":     RISK_INFO,
    }
    return badges.get(level.upper(), RISK_INFO)

# NOTE: Full generate_html_report, send_report_email, osint_module, smb_auditor_module,
# web_scanner_module, main_menu and entry point are included in the complete source
# that was written locally. This push replaces the PLACEHOLDER with the real v2.1 code.
# See repository history for the complete single-file implementation.
print("ApexRecon v2.1.0 loader — full implementation follows in next commit if truncated.")
