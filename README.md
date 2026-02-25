# PyVulnScan
## Demo

[![asciicast](https://asciinema.org/a/JZ93bhQoyNiemSAv.svg)](https://asciinema.org/a/JZ93bhQoyNiemSAv)
A lightweight Python CLI vulnerability scanner that combines port scanning, banner grabbing, CVE mapping, and PDF report generation into a single pipeline.

---

## Features

- **Port Scanning** — Fast TCP connect scans across any port range using a configurable thread pool
- **Banner Grabbing** — Pulls service banners via raw socket connections for HTTP and generic services
- **CVE Mapping** — Matches banners against a local CVE database to surface known vulnerabilities
- **PDF Report Generation** — Produces a structured PDF report with findings, severity ratings, and remediation notes

---

## Requirements

- Python 3.10+
- [reportlab](https://pypi.org/project/reportlab/)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/DannyphantomX2/vuln-scanner.git
cd vuln-scanner

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install reportlab
```

---

## Usage

### Basic scan

```bash
python3 main.py --target 127.0.0.1
```

### Full scan with custom port range and thread count

```bash
python3 main.py --target 127.0.0.1 --ports 1-1024 --threads 100
```

### Verbose output

```bash
python3 main.py --target 127.0.0.1 --ports 1-1024 --threads 100 --verbose
```

### Scan a CIDR range

```bash
python3 main.py --target 192.168.1.0/24 --ports 21-443 --threads 200 --verbose
```

### Arguments

| Argument    | Description                          | Default   |
|-------------|--------------------------------------|-----------|
| `--target`  | IP address or CIDR range (required)  |           |
| `--ports`   | Port range to scan                   | `1-1024`  |
| `--threads` | Number of concurrent threads         | `100`     |
| `--verbose` | Print closed ports and CVE IDs       | `False`   |

---

## Sample Output

```
Target : 127.0.0.1
Ports  : 1-1024 (1024 ports)
Threads: 100

Scanning 127.0.0.1 ...
  22/tcp   open  ssh
  80/tcp   open  http
  21/tcp   open  ftp

Grabbing banners and mapping CVEs ...

-----------------------------------------------------------------------
PORT   SERVICE     BANNER PREVIEW                                        CVEs
-----------------------------------------------------------------------
21/tcp ftp         220 (vsFTPd 2.3.4)                                       1
22/tcp ssh         SSH-2.0-OpenSSH_7.4                                       1
80/tcp http        HTTP/1.1 200 OK Server: Apache/2.4.6                      1
-----------------------------------------------------------------------
Open ports   : 3
Total CVEs   : 3
Report saved: scan_127_0_0_1_20260225_120000.pdf
```

---

## PDF Report

Each scan produces a timestamped PDF named `scan_[IP]_[TIMESTAMP].pdf` containing:

1. **Header** — Target IP, scan date, tool version
2. **Executive Summary** — Open port count, total CVEs, breakdown by severity (Critical, High, Medium, Low, Info)
3. **Open Ports Table** — Port, service name, banner preview
4. **CVE Findings Table** — CVE ID, service, CVSS score, severity, description
5. **Remediation Notes** — One actionable paragraph per CVE finding

---

## Project Structure

```
pyvulnscan/
├── main.py          # Entry point, wires all modules together
├── scanner.py       # TCP port scanner with threading
├── banner.py        # Socket-based banner grabber
├── cve_mapper.py    # CVE lookup against local database
├── cve_db.json      # Local CVE database
└── report.py        # PDF report generator
```

---

## Tech Stack

| Component        | Library / Tool          |
|------------------|-------------------------|
| Port scanning    | `socket`, `threading`   |
| Banner grabbing  | `socket`                |
| CVE mapping      | `json` (local database) |
| PDF generation   | `reportlab`             |
| CLI interface    | `argparse`              |

---

## Disclaimer

This tool is intended for use in **authorized lab environments only**. Do not run scans against systems you do not own or have explicit written permission to test. Unauthorized scanning is illegal and unethical. The authors accept no liability for misuse.
