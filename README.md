# QuantumShield Cryptography Scanner — Quickstart & Usage

Scans endpoints to inventory network cryptographic posture and (optionally) **file‑system artifacts over SFTP**.

**Protocols:** TLS, SSH, RDP, IKE (+ optional QUIC reachability)  
**Optional FS scan:** SFTP-only sweep (no remote shell) for certs/keys/keystores/configs & crypto signals  
**Outputs:** `cbom.json` (structured) and `cbom.csv` (spreadsheet-friendly)

---

## Repo layout (key files)

- `run_scan.py` — runner that loads config (`.env`, `targets.yaml`) and invokes the scanner, also runs API server on port 5555
- `qs_scanner.py` — the scanner module (TLS/SSH/RDP/IKE/FS logic)
- `qs_utils.py` - utilities code
- `targets.yaml` — your target hosts and ports (**you create/edit this**)
- `.env` — feature toggles & optional Azure credentials (**you create/edit this**)
- `Dockerfile` — optional reusable image for Docker path

There are other development files, such as .gitignore and so on.  

---

## Choose your path

**A) Native Linux** (recommended if you have Ubuntu/Debian/RHEL, etc.)  
**B) Docker** (recommended for **Windows & macOS**; also works on Linux)

> If you’re on Windows/macOS, use **Docker**. If you’re on Linux, you can use either native or Docker.

---

## A) Native Linux (venv)

### 1) Install system prerequisites

**Ubuntu/Debian:**

```bash
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip nmap ike-scan openssl
```

**RHEL/CentOS/Fedora:**

```bash
sudo dnf install -y python3 python3-venv python3-pip nmap ike-scan openssl
# or: sudo yum install -y ...
# Note: ike-scan may be in EPEL on some distros
```

### 2) Create a virtual environment & install Python deps
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools ssh-audit ... (see latest Docker for additional requirments)
```

### 3) Create `.env` (feature toggles + optional Azure + FS/SFTP)

Create a file named `.env` in the repo root. **Example** (edit values for your environment):

```dotenv
# ===== (Optional) Azure discovery; leave blank to skip =====
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_SUBSCRIPTION_ID=

# ===== Inputs =====
TARGETS_FILE=targets.yaml

# ===== Feature toggles =====
ENABLE_NMAP_TLS_ENUM=true
ENABLE_SSLYZE_ENUM=true
ENABLE_PQC_HYBRID_SCAN=false
ENABLE_QUIC_PROBE=false

# ===== FS / SFTP scan =====
QS_FS_ENABLED=true
QS_SSH_ENABLED=true
QS_SSH_HOST=00.00.00.00   # Host to SFTP into (for FS scan)
QS_SSH_PORT=22
QS_SSH_USER=qsro
QS_SSH_KEYFILE=/home/you/.ssh/qsro_pem     # path to your **private** key on the scanner machine
QS_SCAN_PATH=/opt/quantumshield_demo        # directory to crawl on the remote host
QS_SSH_DEBUG=true                           # verbose logs (optional)
```

### 4) Create `targets.yaml`

Minimal example (replace with your real host/IP):

```yaml
- host: 00.00.00.00
  name: host-name
  ports:
    tls: 443
    ssh: 22
    rdp: 3389
```

Add more entries to scan additional hosts.

### 5) Prepare the **remote** host for FS/SFTP scan (one-time)

On each target VM you want to FS-scan **(Ubuntu example)**:

```bash
# 5.1 Create the scanning user (if not present)
sudo id qsro || sudo useradd -m -s /bin/bash qsro

# 5.2 Add your public key to that user
sudo -u qsro mkdir -p /home/qsro/.ssh
sudo -u qsro chmod 700 /home/qsro/.ssh
# Paste your public key (ssh-ed25519/ssh-rsa) below between quotes:
sudo bash -c 'echo "ssh-ed25519 AAAA... your-comment" >> /home/qsro/.ssh/authorized_keys'
sudo chmod 600 /home/qsro/.ssh/authorized_keys
sudo chown -R qsro:qsro /home/qsro/.ssh

# 5.3 Ensure OpenSSH SFTP subsystem is enabled
sudo grep -n '^Subsystem' /etc/ssh/sshd_config
# It should show either of these:
#   Subsystem sftp /usr/lib/openssh/sftp-server
# or
#   Subsystem sftp internal-sftp
# If you changed it, then:
sudo systemctl restart ssh

# 5.4 Ensure the directory you want to scan is world-readable (or at least readable to 'qsro')
sudo test -r /opt/quantumshield_demo || sudo chmod -R a+rX /opt/quantumshield_demo
```

**Optional sanity test** from your scanner box:
```bash
# list remote path via sftp
sftp -i /path/to/qsro_pem -P 22 qsro@00.00.00.00 <<'EOF'
ls -l /opt/quantumshield_demo
bye
EOF
```

### 6) Run the scan
```bash
python run_scan.py
```
Results: A timestamp folder should be created containing json files per target and aspect of security scan, also a cummulative `cbom_scan.json` is compiled.

**Re-run later:** just re-run `python run_scan.py` (you can keep the same venv).

---

## B) Windows/macOS (and Linux) via **Docker**

> Within Visual Studio Code

In the terminal window, build the code
``` docker build --no-cache -t qs-scan . ```
In the terminal window, to run the code
``` docker run -p 5555:5555 -v .:/app qs-scan ```

In order to run in the debug mode, uncomment relevent code in `run_scan.py`

```
'''
# remove comment to enable debugpy, set breakpoints in VSCode
import debugpy
# Allow remote debugging and wait for a client to connect
debugpy.listen(("0.0.0.0", 5678)) # Listen on all interfaces
debugpy.wait_for_client()
'''
```

Rebuild and run as above.  

> This path runs the scanner inside a clean Linux container. No local installs needed besides Docker.

### 0) Prerequisite
- **Docker Desktop** (Windows/macOS) or **Docker Engine** (Linux). Use **Linux containers** mode on Desktop.

### 1) Generate or choose your SSH keypair (on your laptop)
If you don’t already have one for scanning:
```powershell
# PowerShell (Windows) — creates C:\Users\<you>\.ssh\qsro_pem(.pem) and public key .pub
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\qsro_pem" -C "qsro-scan"
```
Remember the two files (adjust names if you used different ones):
- **Private**: `C:\Users\<you>\.ssh\qsro_pem.pem` (or no `.pem` on older OpenSSH)
- **Public**:  `C:\Users\<you>\.ssh\qsro_pem.pub`

### 2) Put the **public** key on the VM (Ubuntu example)
Either paste the key directly (SSH’d in as an admin user) **or** copy it up with `scp`.

**A. Paste method (on the VM):**
```bash
sudo id qsro || sudo useradd -m -s /bin/bash qsro
sudo -u qsro mkdir -p /home/qsro/.ssh
sudo -u qsro chmod 700 /home/qsro/.ssh
# paste the single-line public key content into the echo below:
sudo bash -c 'echo "ssh-ed25519 AAAA... qsro-scan" >> /home/qsro/.ssh/authorized_keys'
sudo chmod 600 /home/qsro/.ssh/authorized_keys
sudo chown -R qsro:qsro /home/qsro/.ssh
```

**B. Copy method from Windows (PowerShell):**
```powershell
# Use your existing admin login/key for the VM to copy the public key up
scp -i "C:\path\to\your\admin_login_key.pem" `
    "C:\Users\<you>\.ssh\qsro_pem.pub" `
    azureuser@00.00.00.00:/tmp/qsro_pub.pub

# Then on the VM:
sudo id qsro || sudo useradd -m -s /bin/bash qsro
sudo -u qsro mkdir -p /home/qsro/.ssh
sudo -u qsro chmod 700 /home/qsro/.ssh
sudo bash -c 'cat /tmp/qsro_pub.pub >> /home/qsro/.ssh/authorized_keys'
sudo chmod 600 /home/qsro/.ssh/authorized_keys
sudo chown -R qsro:qsro /home/qsro/.ssh
```

**Ensure SFTP is enabled and the scan path is readable:**
```bash
# On the VM
sudo grep -n '^Subsystem' /etc/ssh/sshd_config
# Expect: "Subsystem sftp /usr/lib/openssh/sftp-server" OR "Subsystem sftp internal-sftp"
sudo systemctl restart ssh

sudo test -r /opt/quantumshield_demo || sudo chmod -R a+rX /opt/quantumshield_demo
```

### 3) Create `.env` and `targets.yaml` in your repo (on your laptop)

**`.env` example (Windows/macOS via Docker):**
```dotenv
# Azure (optional — leave blank to skip)
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_SUBSCRIPTION_ID=

TARGETS_FILE=targets.yaml

ENABLE_NMAP_TLS_ENUM=true
ENABLE_SSLYZE_ENUM=true
ENABLE_PQC_HYBRID_SCAN=false
ENABLE_QUIC_PROBE=false

# FS/SFTP
QS_FS_ENABLED=true
QS_SSH_ENABLED=true
QS_SSH_HOST=00.00.00.00
QS_SSH_PORT=22
QS_SSH_USER=qsro

# IMPORTANT: inside the container we will copy your key to /tmp/qsro_pem with chmod 600
QS_SSH_KEYFILE=/tmp/qsro_pem

# Directory on the VM to crawl:
QS_SCAN_PATH=/opt/quantumshield_demo

# Optional debug
QS_SSH_DEBUG=true
```

**`targets.yaml` example:**
```yaml
- host: 00.00.00.00
  name: host-name
  ports:
    tls: 443
    ssh: 22
    rdp: 3389
```

### 4) Run (ephemeral one-liner) — **PowerShell**

> This mounts your repo and your private key, fixes key perms inside the container (required by SSH), then runs the scan.

```powershell
docker run --rm -it `
  -v "$((Get-Location).Path):/app" -w /app `
  -v "C:\Users\<you>\.ssh\qsro_pem.pem:/app/keys/qsro_pem.pem:ro" `
  --env-file .env `
  --env QS_SSH_KEYFILE=/tmp/qsro_pem `
  --cap-add=NET_RAW --cap-add=NET_ADMIN `
  python:3.12-bookworm bash -lc "
    apt-get update -y &&
    apt-get install -y nmap ike-scan openssl &&
    python -m pip install --no-cache-dir python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools &&
    install -m 600 /app/keys/qsro_pem.pem /tmp/qsro_pem &&
    echo '--- test ssh as qsro ---' &&
    ssh -i /tmp/qsro_pem -o StrictHostKeyChecking=no ${QS_SSH_USER}@${QS_SSH_HOST} 'echo FS-OK' &&
    python run_scan.py
  "
```

**macOS/Linux shell version:**
```bash
docker run --rm -it \
  -v "$PWD:/app" -w /app \
  -v "$HOME/.ssh/qsro_pem.pem:/app/keys/qsro_pem.pem:ro" \
  --env-file .env \
  --env QS_SSH_KEYFILE=/tmp/qsro_pem \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  python:3.12-bookworm bash -lc "
    apt-get update -y &&
    apt-get install -y nmap ike-scan openssl &&
    python -m pip install --no-cache-dir python-dotenv pyyaml cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools &&
    install -m 600 /app/keys/qsro_pem.pem /tmp/qsro_pem &&
    echo '--- test ssh as qsro ---' &&
    ssh -i /tmp/qsro_pem -o StrictHostKeyChecking=no ${QS_SSH_USER}@${QS_SSH_HOST} 'echo FS-OK' &&
    python run_scan.py
  "
```

### 5) (Optional) Reusable image with Dockerfile

Build once:
```powershell
docker build -t qs-scan .
```

Run:
```powershell
docker run --rm -it `
  -v "$((Get-Location).Path):/app" -w /app `
  -v "C:\Users\<you>\.ssh\qsro_pem.pem:/app/keys/qsro_pem.pem:ro" `
  --env-file .env `
  --env QS_SSH_KEYFILE=/tmp/qsro_pem `
  --cap-add=NET_RAW --cap-add=NET_ADMIN `
  qs-scan bash -lc "
    install -m 600 /app/keys/qsro_pem.pem /tmp/qsro_pem &&
    ssh -i /tmp/qsro_pem -o StrictHostKeyChecking=no ${QS_SSH_USER}@${QS_SSH_HOST} 'echo FS-OK' &&
    python run_scan.py
  "
```

### Re-running the scan (fast path)

- **Docker one-liner:** just re-run the same `docker run …` command.
- **Dockerfile path:** re-run the `docker run … qs-scan bash -lc "install … && python run_scan.py"` command.
- **Native Linux:** re-run `python run_scan.py` from your venv.

Outputs land in your repo (`cbom.json`, `cbom.csv`).

---

## Sanity checks

**TLS reachability**
```bash
openssl s_client -connect your.domain.com:443 -servername your.domain.com -brief </dev/null
```

**SFTP reachability**
```bash
sftp -i /path/to/private_key -P 22 qsro@00.00.00.00 <<'EOF'
ls -l /opt/quantumshield_demo
bye
EOF
```

---

## Troubleshooting

**“EOF during negotiation” on FS scan**  
- Ensure SFTP subsystem is enabled:
  ```bash
  sudo grep -n '^Subsystem' /etc/ssh/sshd_config
  # Expect:
  #   Subsystem sftp /usr/lib/openssh/sftp-server
  #   or: Subsystem sftp internal-sftp
  sudo systemctl restart ssh
  ```
- Ensure your scan path is readable:
  ```bash
  sudo test -r /opt/quantumshield_demo || sudo chmod -R a+rX /opt/quantumshield_demo
  ```
- Confirm the key really works:
  ```bash
  ssh -i /path/to/private_key -o StrictHostKeyChecking=no qsro@00.00.00.00 "echo ok"
  sftp -i /path/to/private_key -P 22 qsro@00.00.00.00 <<'EOF'
  ls -l /opt/quantumshield_demo
  bye
  EOF
  ```

**“Permissions … too open” for your key inside Docker**  
Always copy the key to a private path with mode `600` before use:
```bash
install -m 600 /app/keys/qsro_pem.pem /tmp/qsro_pem
```

**TLS status: closed**  
Port 443 blocked/unreachable from the scanner (container/host). Test with `openssl s_client` above.

**`ike-scan` no handshake**  
UDP/500 often blocked by NAT/firewalls (esp. Desktop Docker). TLS/SSH/RDP still work.

**Azure credential errors**  
Azure is optional. Leave the fields blank to skip cloud discovery; scan runs on your YAML targets.

---

## Security & hygiene

- Keep secrets in `.env`. **Do not commit** `.env` to source control.
- Limit scans to assets you own or have written permission to test.
- Results include `risk_flags` (e.g., `legacy_tls`, `rsa_lt_3072`, `ssh_sha1_macs_enabled`, etc.) to help prioritize remediation.

---

## Supported API

Currenlty only few APIs are exposed.  

``` http://127.0.0.1:5555/cbom ```
``` http://127.0.0.1:5555/scan?type=ssh_audit&host=20.55.32.72 ```
``` http://127.0.0.1:5555/runscan ```

## FAQ

**Do I need both YAML and JSON targets?**  
No. Use `targets.yaml` with `run_scan.py`. JSON support is legacy/back-compat.

**Can I run natively on macOS?**  
Yes, with Homebrew (`brew install nmap ike-scan openssl@3`) and Python3 + venv, but **Docker is easier**.

**Windows without Docker?**  
WSL2 Ubuntu works, but Docker Desktop (Linux containers) is simpler and avoids toolchain drift.

---

**Happy scanning! ✨**
