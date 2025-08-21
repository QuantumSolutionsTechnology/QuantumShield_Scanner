# QuantumShield Cryptography Scanner (Azure + Network/FS)

A one-stop script that:
- Authenticates to **Azure** and discovers public IPs for all VMs in a subscription.
- Performs **network cryptography scans** against discovered (or provided) hosts: **TLS**, **SSH**, **RDP**, **IKE** (+ optional QUIC reachability).
- Optionally performs an **agentless filesystem/binary scan over SFTP** to find certs/keys/keystores/configs and crypto-linked binaries.
- Produces a **Cryptographic Bill of Materials (CBOM)** as `cbom.json` and `cbom.csv`, plus an on-screen DataFrame.

> ⚠️ **Security note**: The script prints configuration and writes results to files. Do **not** commit secrets, private keys, or unredacted CBOM files to version control. Treat outputs as internal security artifacts.

---

## Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Azure Authentication](#azure-authentication)
  - [Targets](#targets)
  - [Filesystem/Binary Scan (SFTP)](#filesystembinary-scan-sftp)
  - [Feature Toggles](#feature-toggles)
- [What Gets Collected](#what-gets-collected)
- [Outputs](#outputs)
- [Operational Guidance](#operational-guidance)
- [Troubleshooting](#troubleshooting)
- [Hardening & Safety](#hardening--safety)
- [Notes on PQC](#notes-on-pqc)
- [License](#license)

---

## Features

- **Azure Asset Discovery**
  - Enumerates VM NICs and collects **public IPs** for scan targeting using ARM SDKs.
- **Network Crypto Scans**
  - **TLS (TCP/443)**: live handshake probe (cert subject/issuer, key alg/size, TLS version/cipher, cert sig hash), `nmap ssl-enum-ciphers`, and optional `sslyze` deep enumeration.
  - **SSH (TCP/22)**: `nmap ssh2-enum-algos` for KEX/hostkeys/ciphers/MACs.
  - **RDP (TCP/3389)**: `nmap rdp-enum-encryption` to detect security layer and TLS version.
  - **IKEv2 (UDP/500)**: `ike-scan` with multiple DH groups; parses negotiated SA details if available.
  - **QUIC (UDP/443)**: optional best-effort reachability probe.
- **Agentless FS/Binary Scan (SFTP)** *(optional)*
  - Finds certs/keys/keystores/configs, parses metadata, and scans binaries for TLS/crypto indicators.
- **PQC Hybrid Detection** *(optional)*
  - Tries **OpenSSL 3 + oqsprovider** TLS 1.3 hybrid groups (e.g., ML-KEM) to detect post-quantum trials.
- **CBOM Generation**
  - Normalizes findings into a simple **CBOM** (`qs-cbom:v0.3`) with helpful `risk_flags` (e.g., `legacy_tls`, `weak_cert_signature_hash`, `pqc_hybrid_detected`).

---

## Architecture Overview

```text
Azure ARM (Compute + Network)
        │
        ├─► Discover VM NICs → Public IPs
        │
Scanner Host (Ubuntu/Colab/VM with nmap, ike-scan, OpenSSL)
        │
        ├─► TLS/SSH/RDP/IKE/QUIC network probes
        ├─► Optional SFTP-only FS scan (no shell)
        └─► CBOM normalization → cbom.json + cbom.csv + DataFrame
```

---

## Prerequisites

- **Python 3.9+**
- **System tools** on the scanner host:
  - `nmap`, `ike-scan`, `openssl`
- **Python packages**:
  - Azure SDKs: `azure-identity`, `azure-mgmt-network`, `azure-mgmt-compute`
  - Crypto/scan libs: `cryptography`, `paramiko`, `pandas`, `pynacl`, `ecdsa`, `sslyze`, `pyjks`, `pyelftools`
- **(Optional) PQC hybrid**:
  - **OpenSSL 3** with **oqsprovider** available on the scanner host.
- **(Optional) SFTP FS scan**:
  - SSH access (key or password) to the target(s) and read permission on paths to scan.

> The script auto-installs system tools and Python deps when possible:
> ```bash
> sudo apt-get update -y && sudo apt-get install -y nmap ike-scan openssl
> python -m pip install -U cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools
> ```

---

## Quick Start

1. **Set Azure credentials** (service principal):
   - Create an App Registration with a secret and grant subscription-level `Reader` for discovery.
2. **Export credentials as environment variables** (recommended):
   ```bash
   export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   export AZURE_CLIENT_SECRET="********************************"
   export AZURE_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   ```
3. **Run the script** on your scanner host (Ubuntu VM or Colab):
   - The Azure section will list public IPs from your subscription.
   - Set up `TARGETS` (see below) to include discovered IPs or your own hosts.
4. **Review outputs**:
   - `cbom.json`, `cbom.csv`, and an on-screen Pandas DataFrame.

---

## Configuration

### Azure Authentication

The script uses the Azure SDKs with a **client secret** credential:

```python
from azure.identity import ClientSecretCredential
credential = ClientSecretCredential(
    tenant_id=os.getenv("AZURE_TENANT_ID"),
    client_id=os.getenv("AZURE_CLIENT_ID"),
    client_secret=os.getenv("AZURE_CLIENT_SECRET"),
)
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
```

> You can keep the inline placeholders if you prefer, but **environment variables** avoid committing secrets.

### Targets

Provide one or more scan targets. You can paste discovered public IPs or hardcode hostnames:

```python
TARGETS = [
    {"host": "203.0.113.10", "name": "azure-vm-01", "ports": {"tls": 443, "ssh": 22, "rdp": 3389}},
    {"host": "example.com", "name": "web-prod", "ports": {"tls": 443}},
]
```

### Filesystem/Binary Scan (SFTP)

Enable and point to an SSH-accessible host and paths to scan:

```python
SSH_AUTH = {
    "enabled": True,
    "hostname": "203.0.113.10",
    "port": 22,
    "username": "qsro",
    "password": None,             # prefer None + key auth
    "pkey": None,                 # in-memory PEM (avoid committing)
    "key_filename": "/path/to/id_ed25519",
    "paths_to_scan": ["/opt/quantumshield_demo"],
}
```

> The FS module only uses **SFTP** (no remote shell) and reads at most **5 MB** per file. It parses certs/keys/keystores/configs and inspects binaries for crypto signals, secrets indicators, and linked TLS libs.

### Feature Toggles

```python
ENABLE_QUIC_PROBE      = False  # UDP/443 reachability only
ENABLE_NMAP_TLS_ENUM   = True   # nmap ssl-enum-ciphers
ENABLE_SSLYZE_ENUM     = True   # richer TLS detail
ENABLE_PQC_HYBRID_SCAN = True   # needs OpenSSL 3 + oqsprovider
```

---

## What Gets Collected

**TLS (live handshake):**
- Version, cipher, secret bits
- Certificate subject/issuer, validity, **public key alg & bits**, **signature hash & OID**

**TLS (enum):**
- `nmap ssl-enum-ciphers`: version → ciphers, KEX/group, signature hints
- `sslyze`: JSON with versions, suites, TLS 1.3 sig schemes, cert analysis

**SSH:**
- KEX, host key algs, ciphers, MACs

**RDP:**
- Security layer, encryption level, TLS version

**IKEv2:**
- DH group/name, encryption/integrity/PRF, group attempts

**QUIC (optional):**
- UDP/443 basic reachability status

**FS/Binary (optional):**
- Certs/keys/keystores/configs (parsing metadata)
- Binaries: linked TLS libs, crypto-related strings, entropy, secret indicators

**Derived Summary (`META`):**
- `hndl_exposed_streams`: classical public-key channels susceptible to HNDL
- `quantum_vulnerable_algs`: e.g., RSA, ECDSA, DH
- `pqc_ready_hints`: e.g., `openssl_oqsprovider_configured`, `SSH_hybrid_kex_supported`
- `pqc_blockers`: e.g., `non_openssl_stack`

---

## Outputs

- **`cbom.json`** — Full normalized record:
  ```json
  {
    "schema": "qs-cbom:v0.3",
    "generated_at": "2025-08-21T17:00:00Z",
    "targets": [...],
    "components": [
      {
        "timestamp": "...",
        "host": "203.0.113.10",
        "protocol": "TLS",
        "port": 443,
        "status": "ok",
        "algorithm": "RSA",
        "key_bits": 2048,
        "version": "TLSv1.3",
        "risk_flags": ["rsa_lt_3072"],
        "details": { "...": "..." }
      },
      { "protocol": "META", "details": { "hndl_exposed_streams": [...], "...": "..." } }
    ],
    "policy_refs": ["CNSA 2.0", "FIPS 203-205"]
  }
  ```

- **`cbom.csv`** — Flattened tabular view with columns:
  - `host, protocol, port, status, algorithm, key_bits, version, risk_flags, artifact, error`

- **On-screen DataFrame** — Same as CSV columns for quick inspection.

---

## Operational Guidance

- **Scan scope**: Point `TARGETS` to internet-reachable IPs or hosts you own/have permission to test. Use maintenance windows for production.
- **Rate limiting**: The script paces PQC trials and uses `--host-timeout` on nmap/ike-scan. Adjust if needed.
- **Privileged access**: Network scans do not require elevated privileges. FS scans need SSH/SFTP access with read permissions.
- **Data handling**: Treat `cbom.*` as sensitive. Add to `.gitignore`. Share summary-only views externally.

---

## Troubleshooting

- **Azure discovery empty**: Check SP permissions (Reader) and that VMs have **public** IPs. Private-only NICs won’t appear.
- **SSH FS scan fails**: Ensure the key/password is correct, the user has SFTP enabled, and the `paths_to_scan` exist.
- **`sslyze` errors**: Some environments restrict socket operations; the script records tool stderr in `details.error`.
- **PQC hybrid probe fails**: Confirm `openssl list -groups -provider oqsprovider -provider default` works on the scanner host.
- **IKE scan silent**: Many gateways drop or rate-limit IKE probes. The result `status: no-handshake` is expected in that case.

---

## Hardening & Safety

- **Never** commit real values for `tenant_id`, `client_id`, `client_secret`, `subscription_id`, SSH passwords, or private keys.
- Prefer **env vars** and ephemeral secrets stores.
- The FS scan currently includes small text **contexts** for matches. When running in sensitive environments, set it to record **metadata only** (no content snippets).
- Mask hostnames/IPs in demo screenshots.
- Limit file read sizes and recursion depth as provided (`FS_MAX_BYTES`, `max_depth`).

---

## Notes on PQC

- The optional PQC module uses **OpenSSL 3 + oqsprovider** to *attempt* TLS 1.3 hybrid groups (e.g., ML-KEM) during the client hello. Not all servers or CDNs will negotiate these groups even if listed locally.
- Findings contribute `pqc_hybrid_detected` to `risk_flags` and add a **`META`** summary for migration readiness.

---

## License

© 2025 Quantum Solutions Technology Inc. All rights reserved. For internal evaluation only.
