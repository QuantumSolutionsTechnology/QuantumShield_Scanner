# QuantumShield Cryptography Scanner — Quickstart & Usage

**What it does:** Scans endpoints you own/control to inventory network crypto posture and optional file-system artifacts.

**Protocols:** TLS, SSH, RDP, IKE (plus optional QUIC reachability)  
**Optional FS scan:** SFTP-only sweep (no remote shell) for certs/keys/keystores/configs and crypto signals  
**Outputs:** `cbom.json` (structured) and `cbom.csv` (spreadsheet-friendly)

---

## Repo layout (key files)

- `run_scan.py` – runner that loads config (`.env`, `targets.yaml`) and invokes the scanner
- `qs_scanner.py` – the scanner module (TLS/SSH/RDP/IKE/FS logic)
- `targets.yaml` – your target hosts and ports (you create/edit this)
- `.env` – feature toggles & optional Azure credentials (you create/edit this)

---

## Choose your path

- **A) Native Linux (recommended if you have Ubuntu/Debian/RHEL, etc.)**
- **B) Docker (recommended for Windows & macOS; also works on Linux)**

---

## A) Native Linux (venv)

### 1) Install system prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip nmap ike-scan openssl
```

**RHEL/CentOS/Fedora (sudo dnf or yum):**
```bash
sudo dnf install -y python3 python3-venv python3-pip nmap ike-scan openssl
# or: sudo yum install -y ...
```

> `ike-scan` may live in EPEL or a separate repo on some distros.

### 2) Create a virtual environment & install Python deps
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools
```

### 3) Create `.env` (feature toggles and optional Azure)
Create a file named **`.env`** in the repo root:
```ini
# ========== Feature toggles ==========
ENABLE_NMAP_TLS_ENUM=true
ENABLE_SSLYZE_ENUM=true
ENABLE_PQC_HYBRID_SCAN=false
ENABLE_QUIC_PROBE=false

# Use YAML targets via the runner
TARGETS_FILE=targets.yaml

# ========== (Optional) Azure discovery ==========
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_SUBSCRIPTION_ID=
```
*Leave Azure blank to skip cloud discovery. The scan still runs on your YAML targets.*

### 4) Create `targets.yaml`
Minimal example (replace with your real host/IP):
```yaml
- host: your.domain.com
  name: web1
  ports:
    tls: 443
    ssh: 22
    rdp: 3389
```
Add more entries to scan additional hosts.

### 5) Run the scan
```bash
python run_scan.py
```

**Results:** `cbom.json` and `cbom.csv` appear in the repo folder. Open the CSV to review `status` and `risk_flags` per protocol.

---

## B) Docker route (Windows / macOS / Linux)

### Prerequisite
- **Docker Desktop** (Windows/macOS) or **Docker Engine** (Linux). Use **Linux containers** mode on Desktop.

You’ll run inside a clean Linux container so you don’t need to install tools on your host.

### Option 1 — One-liner (ephemeral image)
From **PowerShell** (Windows) or **Terminal** (macOS/Linux) in the repo root:
```bash
docker run --rm -it \
  -v "$PWD:/app" -w /app \
  --env-file .env \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  python:3.12-bookworm bash -lc "
    apt-get update -y &&
    apt-get install -y nmap ike-scan openssl &&
    python -m pip install --no-cache-dir python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools &&
    python run_scan.py
  "
```

**PowerShell alternative mount (if `$PWD` doesn’t expand):**
```powershell
docker run --rm -it `
  -v "$((Get-Location).Path):/app" -w /app `
  --env-file .env `
  --cap-add=NET_RAW --cap-add=NET_ADMIN `
  python:3.12-bookworm bash -lc "
    apt-get update -y &&
    apt-get install -y nmap ike-scan openssl &&
    python -m pip install --no-cache-dir python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools &&
    python run_scan.py
  "
```

**What this does**
- Mounts your repo into `/app` (outputs land back in your host folder)
- Installs `nmap`, `ike-scan`, `openssl` and required Python libs
- Runs `run_scan.py` using your `.env` and `targets.yaml`

> `sudo: not found` messages are harmless in containers—you're already root.

### Option 2 — Reusable image with a `Dockerfile`
Create **`Dockerfile`** in the repo root:
```dockerfile
FROM python:3.12-bookworm
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends \
      nmap ike-scan openssl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --upgrade pip && \
    python -m pip install \
      cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools \
      python-dotenv pyyaml \
      azure-identity azure-mgmt-compute azure-mgmt-network
WORKDIR /app
CMD ["python", "run_scan.py"]
```
Build & run:
```bash
docker build -t qs-scan .
docker run --rm -it -v "$PWD:/app" -w /app --env-file .env --cap-add=NET_RAW --cap-add=NET_ADMIN qs-scan
```

> Some desktop NATs limit UDP/500 (IKE). TLS/SSH/RDP will still work.

---

## Outputs

- **`cbom.json`** — JSON CBOM with normalized evidence (protocol details, flags, artifacts)
- **`cbom.csv`** — compact table: host, protocol, port, version/algorithm, `risk_flags`

Open the CSV in Excel/Numbers to sort by risk or filter to a protocol.

---

## Sanity check (TLS reachability)

If TLS rows show `status=closed`, confirm 443 is reachable:

**From Linux/macOS or inside the Docker shell:**
```bash
openssl s_client -connect your.domain.com:443 -servername your.domain.com -brief </dev/null
```
If this fails, the scanner can’t reach the target (firewall, DNS, routing).

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Azure … invalid tenant` or similar | Azure is optional. Leave fields blank to skip cloud discovery; the scan still runs on your YAML targets. |
| `TLS status: closed` | 443 blocked/unreachable from the **runner** (container/host). Test with `openssl s_client` as above. |
| `ike-scan` shows no handshake | UDP/500 blocked by NAT/firewall (common on Desktop Docker). Try from a Linux host/VM with direct egress, or ignore IKE for now. |
| `sudo: not found` at start | Harmless inside containers; tools are installed with `apt-get` as root. |
| FS scan errors or empty | Ensure `ssh_auth.enabled: true` and valid SSH creds/paths in config if you enable FS scanning. |
| `sslyze`/`nmap` not found on host | Install using your OS package manager (Linux) or use the Docker route. |

---

## Security & hygiene

- Keep secrets in `.env`. **Do not commit** `.env` to source control.
- Limit scans to assets you own or have written permission to test.
- Results include hints like `risk_flags` (`legacy_tls`, `rsa_lt_3072`, `ssh_sha1_macs_enabled`, etc.) to prioritize remediation.

---

## FAQ

**Do I need both YAML and JSON targets?**  
No. Use **`targets.yaml`** with `run_scan.py`. The scanner prefers targets injected by the runner; legacy `targets.json` support exists only for backward compatibility.

**Can I run natively on macOS?**  
Yes, but Docker is usually simpler. If you prefer native: install Homebrew, then `brew install nmap ike-scan openssl@3`, ensure `python3` and `pip` are present, create a venv, and follow the Linux steps.

**Windows without Docker?**  
WSL2 Ubuntu works, but Docker Desktop (Linux containers) is usually easier and avoids toolchain drift.

---

Happy scanning! ✨
