# QuantumShield Cryptography Scanner — README

This guide shows how to configure and test the scanner using simple
**environment variables** (for Azure auth and feature toggles) and **target files**
(for hosts and optional SSH file-system scan settings). You can still hardcode config
in `qs_scanner.py`, but file-based config makes testing and re-runs easier.

---

## 0) What you have
- `qs_scanner.py` — the scanner script (network TLS/SSH/RDP/IKE + optional SFTP FS scan).
  It writes `cbom.json`, `cbom.csv`, and prints a summary DataFrame.

This README adds a tiny launcher, `run_scan.py`, which:
- Loads `.env` (Azure auth + toggles)
- Loads `targets.yaml` (or `targets.json`) for host/port and SSH scan settings
- Sets the corresponding globals the scanner expects (`TARGETS`, `SSH_AUTH`, `ENABLE_*`)
- Executes the scanner

> You **don’t** need to edit `qs_scanner.py` to use files.

---

## 1) Prereqs

### System packages (Debian/Ubuntu)
```bash
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip nmap ike-scan openssl
```

### Python virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### Python deps (scanner + launcher)
```bash
# scanner deps (same as qs_scanner installs, but installing here is cleaner)
python -m pip install cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools

# launcher deps
python -m pip install python-dotenv pyyaml
```

> If you plan to test **PQC hybrid** detection, your machine needs **OpenSSL 3**
with the **oqsprovider** available on the PATH, which is an advanced setup.
The scanner will fallback gracefully if it’s not present.

---

## 2) Create configuration files

### 2.1 `.env` — Azure + toggles
Create a file named `.env` in the project folder:

```ini
# Azure service principal (used for the optional Azure public-IP discovery step)
AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=YOUR_SUPER_SECRET
AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000

# Feature toggles (true/false). Leave unset to use defaults in qs_scanner.py
ENABLE_QUIC_PROBE=false
ENABLE_NMAP_TLS_ENUM=true
ENABLE_SSLYZE_ENUM=true
ENABLE_PQC_HYBRID_SCAN=true
```

> **Tip:** If you’re not using Azure discovery, you can leave those four vars blank.

### 2.2 `targets.yaml` — who to scan + optional SSH/SFTP FS scan
Create a file named `targets.yaml`:

```yaml
# Hosts to test. Supply either hostnames or IPs.
targets:
  - host: example.com
    name: web-prod
    ports:
      tls: 443
      ssh: 22
      rdp: 3389

# Optional SSH/SFTP FS scan settings (applies if enabled:true)
ssh_auth:
  enabled: false        # set true to enable FS scan
  hostname: example.com
  port: 22
  username: ubuntu
  password: null        # or set a password string if not using key auth
  pkey: null            # paste PEM private key string here if you prefer in-memory key
  key_filename: null    # or path to a private key file on the scanner box
  paths_to_scan:        # folders to crawl (if enabled)
    - /opt/your_app
```

> You can use `targets.json` instead if you prefer JSON; the launcher supports both.

---

## 3) Add the launcher file

Create `run_scan.py` in the same folder as `qs_scanner.py`:

```python
#!/usr/bin/env python3
import json, os, runpy, sys
from pathlib import Path

# Optional deps for env + yaml/json config
from dotenv import load_dotenv
try:
    import yaml
except Exception:
    yaml = None

ROOT = Path(__file__).parent.resolve()
SCANNER = ROOT / "qs_scanner.py"

def load_targets(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")
    if path.suffix.lower() == ".yaml" or path.suffix.lower() == ".yml":
        if not yaml:
            raise RuntimeError("PyYAML not installed. Run: python -m pip install pyyaml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    # Normalize
    targets = data.get("targets") or data.get("TARGETS") or []
    ssh_auth = data.get("ssh_auth") or data.get("SSH_AUTH") or {
        "enabled": False
    }
    return targets, ssh_auth

def env_bool(name: str, default: bool):
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1","true","yes","on")

def main():
    # 1) .env (optional)
    load_dotenv(dotenv_path=ROOT / ".env")

    # 2) feature toggles (fallback to qs_scanner defaults when not set)
    enable_quic      = env_bool("ENABLE_QUIC_PROBE",      False)
    enable_nmap_tls  = env_bool("ENABLE_NMAP_TLS_ENUM",   True)
    enable_sslyze    = env_bool("ENABLE_SSLYZE_ENUM",     True)
    enable_pqc_hyb   = env_bool("ENABLE_PQC_HYBRID_SCAN", True)

    # 3) targets.yaml or targets.json
    tfile = os.getenv("TARGETS_FILE", "targets.yaml")
    targets, ssh_auth = load_targets(ROOT / tfile)

    # 4) Inject config into the scanner's global namespace and run it
    globs = {
        "__name__": "__main__",
        "ENABLE_QUIC_PROBE": enable_quic,
        "ENABLE_NMAP_TLS_ENUM": enable_nmap_tls,
        "ENABLE_SSLYZE_ENUM": enable_sslyze,
        "ENABLE_PQC_HYBRID_SCAN": enable_pqc_hyb,
        "TARGETS": targets,
        "SSH_AUTH": ssh_auth,
    }

    # Optional: Azure discovery step (if you want to pre-populate targets from Azure)
    # Keep it off by default to avoid adding Azure SDK deps here.
    # If you want to use it, consider writing a small pre-step that appends discovered
    # public IPs to `targets` before calling runpy.run_path.

    runpy.run_path(str(SCANNER), init_globals=globs)

if __name__ == "__main__":
    main()
```

Make it executable on Unix-like systems:
```bash
chmod +x run_scan.py
```

---

## 4) Quick test (no credentials needed)

1) Edit `targets.yaml` and set a public HTTPS host you control (e.g., `example.com`).
2) Run:
```bash
source .venv/bin/activate
python run_scan.py
```
3) Expected outputs:
   - Terminal summary DataFrame
   - `cbom.json`
   - `cbom.csv`

Open the CSV quickly:
```bash
python - <<'PY'
import pandas as pd
df = pd.read_csv('cbom.csv')
print(df.head(10).to_string(index=False))
PY
```

---

## 5) Enabling the SSH FS scan (optional)

1) Set `ssh_auth.enabled: true` in `targets.yaml` and fill in:
   - `hostname`, `port`, `username`
   - Either `password`, or `key_filename`, or paste a PEM string into `pkey`
   - Add one or more `paths_to_scan` (e.g., `/opt/app`)

2) Re-run:
```bash
python run_scan.py
```

> The scanner will SFTP-crawl those folders (no remote shell), parse certs/keys/keystores,
grep crypto-related config directives, examine ELF linked libs, and add results to the CBOM.

---

## 6) Azure-based public IP discovery (optional)

If you want to **augment** your `targets` list from Azure:
- Put your service-principal creds in `.env` (`AZURE_*` as shown above).
- Write a tiny pre-step (or a separate helper) that queries Azure for VMs and public IPs
  and appends them to `targets` before launching `qs_scanner.py`. (This keeps the core
  scanner dependency-light.)

A minimal example (run before `runpy.run_path` in `run_scan.py` if you prefer):
```python
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

if all([tenant_id, client_id, client_secret, subscription_id]):
    cred = ClientSecretCredential(tenant_id, client_id, client_secret)
    compute = ComputeManagementClient(cred, subscription_id)
    network = NetworkManagementClient(cred, subscription_id)
    discovered = []
    for vm in compute.virtual_machines.list_all():
        rg = vm.id.split("/")[4]
        nic_id = vm.network_profile.network_interfaces[0].id
        nic_name = nic_id.split("/")[-1]
        nic = network.network_interfaces.get(rg, nic_name)
        for ip_cfg in nic.ip_configurations:
            if ip_cfg.public_ip_address:
                pip = network.public_ip_addresses.get(rg, ip_cfg.public_ip_address.id.split("/")[-1])
                discovered.append(pip.ip_address)
    # extend targets
    for ip in discovered:
        targets.append({"host": ip, "name": "azure-auto", "ports": {"tls": 443, "ssh": 22, "rdp": 3389}})
```

> If you want, I can fold this discovery block directly into `run_scan.py` for a one-command experience.

---

## 7) Interpreting results

- **`cbom.csv`**: flat summary per component (protocol/FS artifacts), with `risk_flags`.
- **`cbom.json`**: structured graph with raw details (TLS enum via nmap/sslyze, FS findings, PQC attempts).
- Look for flags like `legacy_tls`, `rsa_lt_3072`, `ssh_sha1_macs_enabled`, `ike_sha1_integrity`,
  or `pqc_hybrid_detected`.

---

## 8) Troubleshooting

- **Permission denied** on SSH FS scan → verify `username` and one of `password`/`pkey`/`key_filename`.
- **nmap/ike-scan not found** → confirm they’re installed and on PATH (see Prereqs).
- **PQC scan shows error** → oqsprovider not present; set `ENABLE_PQC_HYBRID_SCAN=false` or install it.
- **Empty outputs** → host/ports closed, firewall filtering, or wrong target.

---

## 9) Clean up
```bash
deactivate
```

---

## File layout recap

```
project/
├─ qs_scanner.py        # provided scanner
├─ run_scan.py          # launcher (reads .env + targets.*)
├─ .env                 # optional Azure + toggles
├─ targets.yaml         # targets + ssh_auth
├─ cbom.json            # output
└─ cbom.csv             # output
```
