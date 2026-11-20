# ApexRecon — Phone-only validation procedure

**Platform:** Android with the existing Ubuntu 24.04 proot / Termux environment  
**Branch:** r1-phase1-validation  
**Purpose:** Validate syntax, local regression behavior and safe startup without scanning a target.

This procedure does not require a laptop or desktop. Run the commands inside the Ubuntu environment already used for ApexRecon.

## 1. Prepare the Ubuntu environment

~~~bash
apt-get update
apt-get install -y git python3 nmap whois dnsutils curl iproute2
~~~

Confirm Python is available:

~~~bash
python3 --version
~~~

ApexRecon's current CI matrix covers Python 3.10, 3.11 and 3.12. The test run records the exact Python version on the phone.

## 2. Get the Phase 1 branch

For a fresh checkout:

~~~bash
cd ~
git clone --single-branch --branch r1-phase1-validation https://github.com/trintechdigitaldefense/Apex-Recon-.git
cd Apex-Recon-
~~~

For an existing checkout:

~~~bash
cd ~/Apex-Recon-
git fetch origin
git checkout r1-phase1-validation
git pull --ff-only origin r1-phase1-validation
~~~

Record the revision:

~~~bash
git rev-parse --short HEAD
~~~

## 3. Run syntax validation

~~~bash
python3 -m compileall -q apex_recon_v2.py tests
~~~

Expected result: the command exits successfully with no output.

## 4. Run offline regression tests

~~~bash
python3 -m unittest discover -s tests -v
~~~

Expected result for this branch: **38 tests pass** and the final status is **OK**.

The regression suite uses synthetic Nmap output, temporary files and mocked command execution. It is designed not to scan external or internal targets.

## 5. Verify safe menu startup and exit

~~~bash
printf '9\n' | python3 apex_recon_v2.py
~~~

Expected result: ApexRecon prints its startup/menu information and exits with code 0. Selecting option 9 does not initiate a scan.

Do not select assessment menu options during this offline validation procedure.

## 6. Record the validation result

~~~bash
python3 --version
git rev-parse --short HEAD
git status --short
~~~

Record:
- Android device and Ubuntu/Termux environment version.
- Python version.
- Git commit SHA.
- Compile result.
- Unit-test result and test count.
- Safe menu exit result.

Do not post client IP addresses, hostnames, report contents, credentials or private network details in a public issue or pull request.

## 7. Separate live-network validation

A passing compile and unit-test run is **not** proof that live scans are accurate or harmless.

Live testing is a separate controlled activity. It requires:
- Written authorization for the exact target scope.
- A lab or other explicitly approved network.
- A narrow target range and agreed scan window.
- Operator supervision and review of the traffic/results.
- Evidence that the scan did not exceed the authorized scope.

Do not use client production systems as a first validation target. No live network scan is part of the steps above.

## Current release boundary

ApexRecon remains an operator-started, one-time assessment tool. This branch does not provide unattended 24-hour monitoring. The recovered R1 baseline does not yet restore the v2.1 web scanner, full configuration system, SMTP delivery or native PDF generation. The HTML report's browser print action is not a native PDF export implementation.
