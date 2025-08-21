# ============================
# Auto-config: .env + targets.json + Azure discovery
# ============================
import os, json, pathlib
from typing import List, Dict

# Optional: load .env if present
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()
except Exception:
    pass  # it's optional—script can still run with inline values or environment

# --- Azure auth from env (recommended) ---
AZURE_TENANT_ID      = os.getenv("AZURE_TENANT_ID", "-------------------------")
AZURE_CLIENT_ID      = os.getenv("AZURE_CLIENT_ID", "-------------------------")
AZURE_CLIENT_SECRET  = os.getenv("AZURE_CLIENT_SECRET", "-------------------------")
AZURE_SUBSCRIPTION_ID= os.getenv("AZURE_SUBSCRIPTION_ID", "-------------------------")

# --- SSH FS scan from env ---
QS_SSH_HOST     = os.getenv("QS_SSH_HOST", "---------")
QS_SSH_PORT     = int(os.getenv("QS_SSH_PORT", "22"))
QS_SSH_USER     = os.getenv("QS_SSH_USER", "qsro")
QS_SSH_KEYFILE  = os.getenv("QS_SSH_KEYFILE", "") or None
QS_SSH_PASSWORD = os.getenv("QS_SSH_PASSWORD")  # optional
QS_SCAN_PATH    = os.getenv("QS_SCAN_PATH", "/opt/quantumshield_demo")

# --- Load targets.json if present ---
def load_targets_json(path: str = "targets.json") -> List[Dict]:
    p = pathlib.Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            print(f"[warn] Could not parse {path}; falling back to inline TARGETS")
    return []

# --- Optionally discover Azure public IPs and append to targets ---
def discover_azure_public_ips() -> List[str]:
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except Exception as e:
        print("[info] Azure SDKs not available; skipping Azure discovery")
        return []
    # Bail if envs are placeholders
    if "----" in AZURE_TENANT_ID or "----" in AZURE_CLIENT_ID or "----" in AZURE_CLIENT_SECRET or "----" in AZURE_SUBSCRIPTION_ID:
        print("[info] Azure creds not set; skipping discovery")
        return []
    try:
        cred = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
        compute_client = ComputeManagementClient(cred, AZURE_SUBSCRIPTION_ID)
        network_client = NetworkManagementClient(cred, AZURE_SUBSCRIPTION_ID)
        public_ips = []
        for vm in compute_client.virtual_machines.list_all():
            rg_name = vm.id.split("/")[4]
            nic_id = vm.network_profile.network_interfaces[0].id
            nic_name = nic_id.split("/")[-1]
            nic = network_client.network_interfaces.get(rg_name, nic_name)
            for ip_config in nic.ip_configurations:
                if ip_config.public_ip_address:
                    pip_id = ip_config.public_ip_address.id
                    pip_name = pip_id.split("/")[-1]
                    pip = network_client.public_ip_addresses.get(rg_name, pip_name)
                    if pip.ip_address:
                        public_ips.append(pip.ip_address)
        if public_ips:
            print("Discovered Host Public IPs:", public_ips)
        else:
            print("[info] No public IPs discovered in subscription")
        return list(sorted(set(public_ips)))
    except Exception as e:
        print(f"[warn] Azure discovery error: {e}")
        return []

# Feature toggles
ENABLE_QUIC_PROBE      = os.getenv("QS_ENABLE_QUIC", "false").lower() == "true"
ENABLE_NMAP_TLS_ENUM   = os.getenv("QS_ENABLE_NMAP", "true").lower() != "false"
ENABLE_SSLYZE_ENUM     = os.getenv("QS_ENABLE_SSLYZE", "true").lower() != "false"
ENABLE_PQC_HYBRID_SCAN = os.getenv("QS_ENABLE_PQC", "true").lower() != "false"

# SSH Auth (for FS scan)
SSH_AUTH = globals().get("SSH_AUTH") or {
    "enabled": os.getenv("QS_FS_ENABLED", "true").lower() != "false",
    "hostname": os.getenv("QS_SSH_HOST", "localhost"),
    "port": int(os.getenv("QS_SSH_PORT", "22")),
    "username": os.getenv("QS_SSH_USER", "qsro"),
    "password": os.getenv("QS_SSH_PASSWORD"),
    "pkey": None,
    "key_filename": os.getenv("QS_SSH_KEYFILE") or None,
    "paths_to_scan": [os.getenv("QS_SCAN_PATH", "/opt")],
}

# Prefer injected globals (from run_scan.py), else fall back to local/defaults
TARGETS = globals().get("TARGETS") or load_targets_json() or [
    {"host": "example.com", "name": "example", "ports": {"tls": 443, "ssh": 22, "rdp": 3389}},
]

# Extend with Azure discovered IPs (deduplicated) using default ports
azure_ips = discover_azure_public_ips()
for ip in azure_ips:
    if not any(t.get("host") == ip for t in TARGETS):
        TARGETS.append({"host": ip, "name": f"azure-{ip}", "ports": {"tls": 443, "ssh": 22}})

print(f"[config] Loaded {len(TARGETS)} target(s). FS scan enabled={SSH_AUTH['enabled']}.")

# ----------------------------
# Setup & imports
# ----------------------------
import sys, subprocess, json, re, os, socket, ssl, time, io
from datetime import datetime, timezone
import pandas as pd

def sh(cmd, check=True):
    print(f"$ {cmd}")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if res.stdout: print(res.stdout)
    if res.stderr: print(res.stderr)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}")
    return res

# System tools
sh("sudo apt-get update -y && sudo apt-get install -y nmap ike-scan openssl >/dev/null 2>&1 || true", check=False)

# Python deps
sh(f"{sys.executable} -m pip install --quiet cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools", check=False)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import paramiko
import stat
import shlex

# ----------------------------
# Helpers
# ----------------------------
def is_port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def tls_probe(host, port=443, timeout=6):
    """Return dict with TLS version, cipher, cert subject/issuer, key algo/size, notBefore/notAfter."""
    out = {"protocol": "TLS", "host": host, "port": port}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # tuple: (cipher_name, protocol, secret_bits)
                cipher_name, tls_version, secret_bits = ssock.cipher()
                out["cipher_name"] = cipher_name
                out["tls_version"] = tls_version
                out["secret_bits"] = secret_bits
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                out["cert_subject"] = cert.subject.rfc4514_string()
                out["cert_issuer"]  = cert.issuer.rfc4514_string()
                out["not_before"] = getattr(cert, "not_valid_before_utc", cert.not_valid_before).isoformat()
                out["not_after"]  = getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat()
                # cert public key
                pk = cert.public_key()
                if isinstance(pk, rsa.RSAPublicKey):
                    out["public_key_alg"] = "RSA"
                    out["public_key_bits"] = pk.key_size
                elif isinstance(pk, ec.EllipticCurvePublicKey):
                    out["public_key_alg"] = f"EC({pk.curve.name})"
                    out["public_key_bits"] = pk.key_size
                elif isinstance(pk, dsa.DSAPublicKey):
                    out["public_key_alg"] = "DSA"
                    out["public_key_bits"] = pk.key_size
                else:
                    out["public_key_alg"] = type(pk).__name__
                    out["public_key_bits"] = None

                # cert signature algorithm (hash + oid)
                out["cert_sig_oid"] = cert.signature_algorithm_oid.dotted_string
                try:
                    out["cert_sig_hash"] = cert.signature_hash_algorithm.name
                except Exception:
                    out["cert_sig_hash"] = None

        out["status"] = "ok"
    except Exception as e:
        out["status"] = "error"
        out["error"] = str(e)
    return out

def nmap_ssh_algos(host, port=22, timeout=30):
    """Enumerate SSH algos via nmap script; robust parsing for 7.x output."""
    cmd = f"nmap -p {port} --script ssh2-enum-algos -Pn --host-timeout {timeout}s {host}"
    res = sh(cmd, check=False)
    text = (res.stdout or "") + (res.stderr or "")
    out = {"protocol": "SSH", "host": host, "port": port, "status": "error", "raw": text}
    if "ssh2-enum-algos" not in (res.stdout or ""):
        return out

    out["status"] = "ok"
    sections = {
        "kex_algorithms": [],
        "server_host_key_algorithms": [],
        "encryption_algorithms": [],
        "mac_algorithms": [],
        "compression_algorithms": [],
    }

    current = None
    hdr_re = re.compile(r'^(kex_algorithms|server_host_key_algorithms|encryption_algorithms|mac_algorithms|compression_algorithms)\s*:', re.I)
    for line in (res.stdout or "").splitlines():
        L = line.strip()
        if L.startswith("|"):
            L = L[1:].strip()
        m = hdr_re.match(L)
        if m:
            current = m.group(1).lower()
            continue
        if current:
            if re.fullmatch(r"\(\d+\)", L):
                continue
            val = L[1:].strip() if L.startswith("-") else L.strip()
            if val:
                sections[current].append(val)
    out.update(sections)
    return out

def rdpscan(host, port=3389, timeout=30):
    """Use nmap script rdp-enum-encryption to get RDP security layer/version."""
    cmd = f"nmap -p {port} --script rdp-enum-encryption -Pn --host-timeout {timeout}s {host}"
    res = sh(cmd, check=False)
    out = {"protocol": "RDP", "host": host, "port": port, "status": "error", "raw": res.stdout}
    if res.returncode == 0 and "rdp-enum-encryption" in res.stdout:
        out["status"] = "ok"
        m = re.search(r"Security layer:\s*(.+)", res.stdout)
        if m: out["security_layer"] = m.group(1).strip()
        m = re.search(r"RDP Encryption level:\s*(.+)", res.stdout)
        if m: out["encryption_level"] = m.group(1).strip()
        m = re.search(r"SSL/TLS version:\s*(.+)", res.stdout)
        if m: out["tls_version"] = m.group(1).strip()
    return out

def ike_scan(host, timeout=25, groups=(14, 15, 16, 19, 20, 21)):
    """Probe IKEv2, try several DH groups, parse SA line on success."""
    tried = []
    for g in groups:
        cmd = f"ike-scan --ikev2 -M --timeout={timeout} --dhgroup={g} -- {host}"
        res = sh(cmd, check=False)
        txt = (res.stdout or "") + (res.stderr or "")
        tried.append({"group": g, "snippet": (txt.strip()[:400] or "")})

        if "returned handshake" in txt:
            m = re.search(
                r"SA=\\(Encr=([A-Z0-9_]+)(?:,KeyLength=(\\d+))?\\s+Integ=([A-Z0-9_]+)\\s+Prf=([A-Z0-9_]+)\\s+DH_Group=(\\d+):([A-Za-z0-9_+-]+)\\)",
                txt
            )
            details = {"dhgroup": g, "raw": txt}
            if m:
                encr, keylen, integ, prf, dh_num, dh_name = m.groups()
                encr_disp = f"{encr}-{keylen}" if keylen else encr
                details.update({
                    "dhgroup": int(dh_num),
                    "dh_name": dh_name,
                    "encryption": encr,
                    "key_length": int(keylen) if keylen else None,
                    "integrity": integ,
                    "prf": prf,
                })
                summary = f"DH{dh_num}/{encr_disp}/{integ}"
            else:
                summary = f"DH{g}"

            return {
                "protocol": "IKE",
                "host": host,
                "port": 500,
                "status": "ok",
                "summary": summary,
                **details
            }

        if "INVALID_KE_PAYLOAD" in txt:
            continue

    return {
        "protocol": "IKE",
        "host": host,
        "port": 500,
        "status": "no-handshake",
        "tried_groups": [t["group"] for t in tried],
        "raw": tried[-1]["snippet"] if tried else None,
    }

def quic_probe_udp(host, port=443):
    """Best-effort UDP/443 reachability (not a full QUIC handshake)."""
    out = {"protocol": "QUIC", "host": host, "port": port, "status": "no-attempt"}
    if not ENABLE_QUIC_PROBE:
        return out
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"\x00\x00\x00", (host, port))
        try:
            data, _ = s.recvfrom(2048)
            out["status"] = "response"
            out["bytes"] = len(data)
        except socket.timeout:
            out["status"] = "silent"
    except Exception as e:
        out["status"] = "error"
        out["error"] = str(e)
    return out

# ----------------------------
# TLS enumeration
# ----------------------------
def nmap_ssl_enum(host, port=443, timeout=60):
    """
    Uses nmap's ssl-enum-ciphers to enumerate TLS versions and ciphers.
    Returns dict: {"enumeration": { "TLSv1.2": [{cipher,...}], "TLSv1.3": [...] } }
    """
    cmd = f"nmap -p {port} --script ssl-enum-ciphers -Pn --host-timeout {timeout}s {host}"
    res = sh(cmd, check=False)
    out = {"protocol": "TLS", "tool": "nmap ssl-enum-ciphers", "host": host, "port": port, "status": "error", "raw": res.stdout}
    if res.returncode != 0 or "ssl-enum-ciphers" not in (res.stdout or ""):
        return out

    out["status"] = "ok"
    tls = {}
    current_ver = None
    for line in (res.stdout or "").splitlines():
        L = line.strip("| ").rstrip()
        if L.startswith("TLSv"):
            current_ver = L.split()[0]
            tls.setdefault(current_ver, [])
        elif current_ver and L.startswith("cipher:"):
            name = L.split("cipher:", 1)[1].strip()
            tls[current_ver].append({"cipher": name})
        elif current_ver and ("key-exchange" in L.lower() or "group:" in L.lower()):
            if tls[current_ver]:
                tls[current_ver][-1]["kex"] = L.split(":", 1)[1].strip()
        elif current_ver and "signature" in L.lower():
            if tls[current_ver]:
                tls[current_ver][-1]["sig"] = L.split(":", 1)[1].strip()
    out["enumeration"] = tls
    return out

def sslyze_enum(host, port=443, timeout=120):
    """
    Run sslyze for rich JSON: versions, ciphersuites, TLS1.3 signature schemes, certificate signature alg, etc.
    """
    cmd = [
        sys.executable, "-m", "sslyze",
        f"{host}:{port}",
        "--regular",
        "--tls13",
        "--json_out=-"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0:
            return {"protocol":"TLS","tool":"sslyze","host":host,"port":port,"status":"error","error":(res.stderr or res.stdout)[:4000]}
        data = json.loads(res.stdout)
        return {"protocol":"TLS","tool":"sslyze","host":host,"port":port,"status":"ok","results": data}
    except Exception as e:
        return {"protocol":"TLS","tool":"sslyze","host":host,"port":port,"status":"error","error":str(e)}

def openssl_list_groups():
    """List TLS groups with oqsprovider loaded (for PQC hybrids)."""
    cmd = "openssl list -groups -provider oqsprovider -provider default"
    res = sh(cmd, check=False)
    if res.returncode != 0:
        return {"status":"error","error":res.stderr or res.stdout}
    return {"status":"ok","raw":res.stdout}

def openssl_tls13_probe(host, port=443, groups=None, ciphersuites=None, sigalgs=None, timeout=20):
    """
    Attempt TLS1.3 handshake advertising specific groups/ciphers/sigalgs with oqsprovider.
    """
    grp_arg = f"-groups {','.join(groups)}" if groups else ""
    cs_arg  = f"-ciphersuites {','.join(ciphersuites)}" if ciphersuites else ""
    sa_arg  = f"-sigalgs {','.join(sigalgs)}" if sigalgs else ""
    cmd = f"openssl s_client -connect {host}:{port} -tls1_3 -servername {host} -brief -provider oqsprovider -provider default {grp_arg} {cs_arg} {sa_arg} -quiet"
    res = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
    out = {"host":host,"port":port,"status":"error","cmd":cmd,"stdout":res.stdout,"stderr":res.stderr}
    if res.returncode == 0:
        out["status"]="ok"
        text = (res.stdout or "") + "\n" + (res.stderr or "")
        mcs = re.search(r"TLSv1\.3, Cipher is ([A-Z0-9_\-]+)", text)
        if mcs: out["cipher"]=mcs.group(1)
        mg = re.search(r"(?:Shared group|Server Temp Key|Key Exchange):\s*([A-Za-z0-9_\-+]+)", text)
        if mg: out["group"]=mg.group(1)
    return out

def pqc_hybrid_scan(host, port=443):
    """
    Enumerate PQC-capable hybrid groups via openssl list -groups (oqsprovider) and
    try to negotiate them. Returns any successful hybrid handshakes.
    """
    groups_raw = openssl_list_groups()
    if groups_raw.get("status") != "ok":
        return {"protocol":"TLS","tool":"openssl+oqsprovider","host":host,"port":port,"status":"error","error":"oqsprovider not loaded or OpenSSL not PQC-enabled"}

    hybrids = []
    for line in (groups_raw["raw"] or "").splitlines():
        line=line.strip()
        if "mlkem" in line.lower() or "kyber" in line.lower():
            for tok in re.split(r"[,\\s]+", line):
                if "mlkem" in tok.lower() or "kyber" in tok.lower():
                    hybrids.append(tok)
    hybrids = sorted(set([h for h in hybrids if len(h) > 3]))

    results = {"protocol":"TLS","tool":"openssl+oqsprovider","host":host,"port":port,"status":"ok","pqc_groups_tried":hybrids,"pqc_handshakes":[]}
    for g in hybrids:
        try:
            pr = openssl_tls13_probe(host, port, groups=[g])
        except Exception as e:
            pr = {"status":"error","error":str(e)}
        if pr.get("status") == "ok" and pr.get("group","" ).lower().find(g.lower()) != -1:
            results["pqc_handshakes"].append({"group": g, "cipher": pr.get("cipher")})
        time.sleep(0.2)  # gentle pacing
    return results

def sftp_walk(sftp, root, max_depth=3, max_items=2000):
    todo = [(root.rstrip("/"), 0)]
    seen = 0
    while todo:
        path, depth = todo.pop(0)
        try:
            for entry in sftp.listdir_attr(path):
                child = f"{path}/{entry.filename}"
                is_dir = stat.S_ISDIR(entry.st_mode)
                yield child, is_dir
                seen += 1
                if seen >= max_items:
                    return
                if is_dir and depth < max_depth:
                    todo.append((child, depth+1))
        except Exception:
            continue

def remote_find_crypto_artifacts_sftp(ssh, paths, max_depth=3, max_items=2000, max_read_bytes=512*1024):
    sftp = ssh.open_sftp()
    name_pats = [
        re.compile(r'.*\\.pem$', re.I), re.compile(r'.*\\.crt$', re.I),
        re.compile(r'.*\\.der$', re.I), re.compile(r'.*\\.p12$', re.I),
        re.compile(r'.*key.*', re.I),  re.compile(r'.*cert.*', re.I),
    ]
    needles = [b'aes-256', b'chacha20', b'poly1305', b'ecdsa', b'x25519',
               b'RSA PUBLIC KEY', b'BEGIN CERTIFICATE']
    results = []
    for base in paths:
        try:
            sftp.listdir(base)
        except Exception as e:
            print(f"[FS preflight SFTP] cannot list {base}: {e}")
            continue

        for p, is_dir in sftp_walk(sftp, base, max_depth=max_depth, max_items=max_items):
            if is_dir:
                continue
            if any(pat.search(p) for pat in name_pats):
                results.append({"type": "fs-artifact", "path": p})
            try:
                with sftp.open(p, 'rb') as fh:
                    buf = fh.read(max_read_bytes)
                for needle in needles:
                    if needle in buf:
                        try:
                            snippet = buf[:2000].decode('utf-8', 'ignore')
                        except Exception:
                            snippet = None
                        results.append({
                            "type": "fs-grep",
                            "path": p,
                            "match": (needle.decode() if isinstance(needle, bytes) else str(needle)),
                            "context": snippet
                        })
                        break
            except Exception:
                continue
    try:
        sftp.close()
    except Exception:
        pass
    return results

# ============================
# FS/Binary deep scan module
# ============================
import base64, math, zipfile
from io import BytesIO
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from elftools.elf.elffile import ELFFile
import jks

# ---- Config knobs for FS scan
FS_SCAN_EXTS = {  # prioritized by parser
    ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c",
    ".key", ".pub", ".p12", ".pfx", ".jks", ".csr",
    ".conf", ".cnf",
    ".so", "", ".bin", ".exe", ".dll", ".jar", ".war", ".ear"
}
FS_MAX_BYTES = 5 * 1024 * 1024         # read up to 5MB per file
FS_STR_MINLEN = 6                      # minimal ASCII string length for scanning
DEFAULT_PASSWORD_GUESSES = ["", "password"]  # cautious; disable/add as needed
CONFIG_SNIFF = {
    "nginx": re.compile(r"\b(ssl_ciphers|ssl_protocols|ssl_ecdh_curve|ssl_prefer_server_ciphers)\b", re.I),
    "apache": re.compile(r"\b(SSLCipherSuite|SSLProtocol|SSLOpenSSLConfCmd)\b", re.I),
    "sshd": re.compile(r"\b(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms)\b", re.I),
    "openssl": re.compile(r"\b(openssl_conf|providers|alg_section|system_default)\b", re.I),
}
CRYPTO_NAME_PAT = re.compile(
    r"\b(AES-(?:128|192|256)-(?:CBC|GCM|CCM)|CHACHA20-POLY1305|3DES|DES|RC4|BLOWFISH|"
    r"RSA|DSA|ECDSA|ED25519|ED448|X25519|X448|P-256|SECP256R1|SECP384R1|SECP521R1|"
    r"KYBER|ML-?KEM|DILITHIUM|FALCON|SPHINCS)\b", re.I
)
SECRET_PATTERNS = [
    (re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "pem_private_key"),
    (re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----"), "openssh_private_key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
    (re.compile(rb"(?i)aws_secret_access_key\s*=\s*[0-9A-Za-z/+=]{30,}"), "aws_secret"),
    (re.compile(rb"(?i)(api[-_ ]?key|secret|token)\s*[:=]\s*[0-9A-Za-z_\-]{20,}"), "api_secret_like"),
]

def shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    freq = [0]*256
    for b in buf:
        freq[b] += 1
    ent = 0.0
    n = len(buf)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def guess_ext(path: str) -> str:
    base = path.lower()
    if "." in base:
        return "." + base.split(".")[-1]
    return ""

def sftp_read_bytes(sftp, path, max_bytes=FS_MAX_BYTES):
    try:
        with sftp.open(path, 'rb') as fh:
            return fh.read(max_bytes)
    except Exception as e:
        return None

def parse_cert_from_pem_or_der(buf: bytes):
    # try PEM first
    try:
        if b"-----BEGIN CERTIFICATE-----" in buf:
            cert = x509.load_pem_x509_certificate(buf, default_backend())
        else:
            cert = x509.load_der_x509_certificate(buf, default_backend())
        pk = cert.public_key()
        alg = None; bits = None; curve=None
        if isinstance(pk, rsa.RSAPublicKey):
            alg, bits = "RSA", pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            alg, bits, curve = f"EC({pk.curve.name})", pk.key_size, pk.curve.name
        elif isinstance(pk, dsa.DSAPublicKey):
            alg, bits = "DSA", pk.key_size
        sig_oid = cert.signature_algorithm_oid.dotted_string
        try:
            sig_hash = cert.signature_hash_algorithm.name
        except Exception:
            sig_hash = None
        return {
            "type": "CERT",
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": getattr(cert, "not_valid_before_utc", cert.not_valid_before).isoformat(),
            "not_after": getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
            "pubkey_alg": alg,
            "pubkey_bits": bits,
            "ec_curve": curve,
            "cert_sig_oid": sig_oid,
            "cert_sig_hash": sig_hash,
        }
    except Exception:
        return None

def parse_private_key_pem(buf: bytes, password_guesses=DEFAULT_PASSWORD_GUESSES):
    # Detect encryption by header
    is_enc = b"ENCRYPTED" in buf or b"Proc-Type: 4,ENCRYPTED" in buf
    if is_enc:
        return {"type":"KEY","encrypted": True}
    # Try load
    try:
        key = serialization.load_pem_private_key(buf, password=None, backend=default_backend())
    except Exception:
        return {"type":"KEY","encrypted": None}
    # If loaded, characterize
    if isinstance(key, rsa.RSAPrivateKey):
        return {"type":"KEY","encrypted": False,"key_alg":"RSA","key_bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"type":"KEY","encrypted": False,"key_alg": f"EC({key.curve.name})","key_bits": key.key_size, "ec_curve": key.curve.name}
    return {"type":"KEY","encrypted": False,"key_alg": type(key).__name__}

def parse_pkcs12(buf: bytes, passwords=DEFAULT_PASSWORD_GUESSES):
    for pw in passwords:
        try:
            pkey, cert, add_certs = pkcs12.load_key_and_certificates(buf, pw.encode() if pw else None, default_backend())
            info = {"type":"KEYSTORE","format":"PKCS12","encrypted": bool(pw), "entries": []}
            if cert:
                cinfo = parse_cert_from_pem_or_der(cert.public_bytes(serialization.Encoding.DER))
                if cinfo: info["entries"].append(cinfo)
            if pkey:
                if isinstance(pkey, rsa.RSAPrivateKey):
                    info["entries"].append({"type":"KEY","key_alg":"RSA","key_bits": pkey.key_size})
                elif isinstance(pkey, ec.EllipticCurvePublicKey):
                    info["entries"].append({"type":"KEY","key_alg": f"EC({pkey.curve.name})","key_bits": pkey.key_size,"ec_curve": pkey.curve.name})
                else:
                    info["entries"].append({"type":"KEY","key_alg": type(pkey).__name__})
            for ac in (add_certs or []):
                cinfo = parse_cert_from_pem_or_der(ac.public_bytes(serialization.Encoding.DER))
                if cinfo: info["entries"].append(cinfo)
            return info
        except Exception:
            continue
    return {"type":"KEYSTORE","format":"PKCS12","encrypted": True}

def parse_jks_file(buf: bytes, passwords=DEFAULT_PASSWORD_GUESSES):
    for pw in passwords:
        try:
            ks = jks.KeyStore.loads(buf, pw)
            info = {"type":"KEYSTORE","format":"JKS","encrypted": bool(pw), "entries": []}
            for alias, e in ks.private_keys.items():
                alg = None; bits=None
                if e.algorithm and "RSA" in e.algorithm.upper():
                    alg="RSA"
                if e.algorithm and "EC" in e.algorithm.upper():
                    alg="EC"
                info["entries"].append({"type":"KEY","alias":alias,"key_alg":alg})
                for cert in e.cert_chain:
                    cinfo = parse_cert_from_pem_or_der(cert.cert)
                    if cinfo: info["entries"].append(cinfo)
            for alias, t in ks.certs.items():
                cinfo = parse_cert_from_pem_or_der(t.cert)
                if cinfo:
                    cinfo["alias"]=alias
                    info["entries"].append(cinfo)
            return info
        except Exception:
            continue
    return {"type":"KEYSTORE","format":"JKS","encrypted": True}

def parse_config_text(path: str, text: str):
    out = {"type":"CONFIG","path": path, "hints":[]}
    for name, rx in CONFIG_SNIFF.items():
        if rx.search(text):
            out["hints"].append(name)
    # extract common directives
    cfg = {}
    for line in text.splitlines():
        L = line.strip()
        if L.startswith("#") or not L:
            continue
        for k in ["ssl_ciphers","ssl_protocols","ssl_ecdh_curve","ssl_prefer_server_ciphers",
                  "SSLCipherSuite","SSLProtocol","SSLOpenSSLConfCmd",
                  "KexAlgorithms","Ciphers","MACs","HostKeyAlgorithms"]:
            if L.lower().startswith(k.lower()):
                cfg.setdefault(k, []).append(L)
    if cfg:
        out["directives"] = cfg
    # detect oqsprovider reference
    if "oqs" in text.lower():
        out.setdefault("signals",[]).append("pqc_provider_ref")
    return out

def extract_ascii_strings(buf: bytes, minlen=FS_STR_MINLEN):
    s = []
    cur = []
    for b in buf:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                s.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        s.append("".join(cur))
    return s

CRYPTO_LIB_HINTS = [
    "OpenSSL", "libcrypto", "libssl", "BoringSSL", "mbedTLS", "wolfSSL",
    "Libgcrypt", "libsodium", "TweetNaCl", "Botan"
]

def parse_elf_libs(buf: bytes):
    try:
        ef = ELFFile(BytesIO(buf))
        libs = []
        if ef.has_dwarf_info(): pass
        for seg in ef.iter_segments():
            if seg.header.p_type == "PT_DYNAMIC":
                dyn = seg
                for t in dyn.iter_tags():
                    if t.entry.d_tag == "DT_NEEDED":
                        libs.append(t.needed)
        return {"type":"LIBS","libs": libs}
    except Exception:
        return None

def analyze_binary_bytes(path: str, buf: bytes):
    res = {"type":"BINARY","path":path,"signals":[]}
    # linked libs if ELF
    libinfo = parse_elf_libs(buf)
    if libinfo:
        res["linked_libs"] = libinfo["libs"]
        if any(any(h.lower() in l.lower() for h in ["ssl","crypto"]) for l in libinfo["libs"]):
            res["signals"].append("uses_tls_libs")
    # strings scan
    strs = extract_ascii_strings(buf)
    hits = list(sorted({m.group(0) for m in (CRYPTO_NAME_PAT.search(s) for s in strs) if m}))
    if hits:
        res["crypto_strings"] = hits[:50]
    # secret scan
    secrets = []
    for rx, tag in SECRET_PATTERNS:
        if rx.search(buf):
            secrets.append(tag)
    if secrets:
        res["secret_indicators"] = secrets
    # entropy
    ent = shannon_entropy(buf[:1024*64])
    res["entropy_64k"] = round(ent, 3)
    return res

def fs_deep_scan_v2(ssh, paths, max_depth=4, max_items=4000):
    """
    Enhanced FS scan using SFTP only (no shell):
      - certs/keys/keystores parsing
      - config directive grepping
      - ELF/binary crypto strings & linked libs
    """
    sftp = ssh.open_sftp()
    results = []
    count = 0
    for base in paths:
        try:
            sftp.listdir(base)
        except Exception as e:
            results.append({"protocol":"FS","status":"error","path":base,"error":str(e)})
            continue

        for p, is_dir in sftp_walk(sftp, base, max_depth=max_depth, max_items=max_items):
            if is_dir:
                continue
            ext = guess_ext(p)
            if ext not in FS_SCAN_EXTS:
                continue
            buf = sftp_read_bytes(sftp, p, FS_MAX_BYTES)
            if buf is None:
                continue

            # Try structured parsers first
            rec = None
            if ext in {".pem",".crt",".cer",".der",".p7b",".p7c"}:
                rec = parse_cert_from_pem_or_der(buf)
                if rec: rec.update({"path": p})
            elif ext in {".key",".pub"} and b"-----BEGIN" in buf:
                rec = parse_private_key_pem(buf); rec.update({"path": p})
            elif ext in {".p12",".pfx"}:
                rec = parse_pkcs12(buf); rec.update({"path": p})
            elif ext == ".jks":
                rec = parse_jks_file(buf); rec.update({"path": p})
            elif ext in {".conf",".cnf"}:
                try:
                    text = buf.decode("utf-8", "ignore")
                except Exception:
                    text = ""
                rec = parse_config_text(p, text)

            # Fallback: binary/ELF/strings scan
            if not rec:
                rec = analyze_binary_bytes(p, buf)

            # shape into CBOM-style
            rec.update({"protocol":"FS","host": SSH_AUTH["hostname"]})
            results.append(rec)
            count += 1
            if count >= max_items:
                break
    try:
        sftp.close()
    except Exception:
        pass
    return results

# ---- Derive quantum-relevant signals from FS + network evidence
def derive_quantum_risk(evidence):
    """
    Adds high-level quantum/HNDL/migration signals by inspecting CBOM evidence so far.
    """
    summary = {
        "hndl_exposed_streams": [],   # network protocols that are classical and in-use
        "quantum_vulnerable_algs": set(),
        "pqc_ready_hints": set(),
        "pqc_blockers": set(),
    }
    # network components
    for e in evidence:
        if e.get("protocol") in {"TLS","SSH","IKE","RDP"}:
            # HNDL exposure: classical public-key use means recordable today, decryptable later
            if e.get("protocol") == "TLS" and e.get("tool") is None and e.get("status") == "ok":
                # Any RSA/ECDSA auth or classical key exchange implies HNDL risk
                pka = (e.get("public_key_alg") or "").upper()
                if "RSA" in pka or "EC(" in pka:
                    summary["hndl_exposed_streams"].append({"proto":"TLS","port":e.get("port"),"host":e.get("host"),"auth":pka,"cipher":e.get("cipher_name")})
                    summary["quantum_vulnerable_algs"].update(["RSA","ECDSA"])
            if e.get("protocol") == "SSH" and e.get("status") == "ok":
                # classical KEX in offers
                kex = " ".join(e.get("kex_algorithms") or [])
                if "sntrup" in kex.lower():
                    summary["pqc_ready_hints"].add("SSH_hybrid_kex_supported")
                else:
                    summary["hndl_exposed_streams"].append({"proto":"SSH","port":e.get("port"),"host":e.get("host")})
                    summary["quantum_vulnerable_algs"].update(["ECDH","DH","RSA"])
            if e.get("protocol") == "IKE" and e.get("status") in {"ok","no-handshake"}:
                # IKEv2 classical DH/ECDH --> HNDL risk for VPN
                summary["hndl_exposed_streams"].append({"proto":"IKEv2","port":e.get("port",500),"host":e.get("host")})
                summary["quantum_vulnerable_algs"].update(["DH","ECDH","RSA"])
        # FS components for PQC readiness/blockers
        if e.get("protocol") == "FS":
            det = json.dumps(e, default=str).lower()
            if e.get("type") == "CONFIG" and "oqs" in det:
                summary["pqc_ready_hints"].add("openssl_oqsprovider_configured")
            if "boringssl" in det or "libressl" in det:
                summary["pqc_blockers"].add("non_openssl_stack")
    # de-dup
    summary["hndl_exposed_streams"] = list({(d["proto"],d.get("host"),d.get("port"),d.get("auth","")): d for d in summary["hndl_exposed_streams"]}.values())
    summary["quantum_vulnerable_algs"] = sorted(summary["quantum_vulnerable_algs"])
    summary["pqc_ready_hints"] = sorted(summary["pqc_ready_hints"])
    summary["pqc_blockers"] = sorted(summary["pqc_blockers"])
    return summary

# ----------------------------
# Risk helpers / normalization
# ----------------------------
LEGACY_TLS = {"TLSv1", "TLSv1.1", "SSLv3"}
WEAK_RSA_BITS = 2048  # <2048 flagged
GOOD_EC_CURVES = {"secp256r1", "prime256v1", "x25519", "x448"}
PQC_ALG_HINTS = {"ML-KEM", "Kyber", "Dilithium", "Falcon", "SPHINCS"}

def assess_tls(find):
    flags = []
    ver = find.get("tls_version") or find.get("tls")
    if ver and ver in LEGACY_TLS:
        flags.append("legacy_tls")
    if find.get("public_key_alg") == "RSA" and isinstance(find.get("public_key_bits"), int) and find["public_key_bits"] < WEAK_RSA_BITS:
        flags.append("weak_rsa_key")
    if find.get("public_key_alg") == "RSA" and find.get("public_key_bits", 0) < 3072:
        flags.append("rsa_lt_3072")
    if find.get("cert_subject") == find.get("cert_issuer"):
        flags.append("self_signed_cert")
    # heuristic PQC hints
    if any(isinstance(v, str) and any(h in v for h in PQC_ALG_HINTS) for v in find.values()):
        flags.append("pqc_hint")
    # cert sig hash risks
    if (find.get("cert_sig_hash") or "").lower() in {"md5", "sha1"}:
        flags.append("weak_cert_signature_hash")
    return flags

def assess_ssh(find):
    flags = []
    macs = find.get("mac_algorithms") or []
    kex  = find.get("kex_algorithms") or []
    hks  = find.get("server_host_key_algorithms") or []
    if any(m == "hmac-sha1" or "hmac-sha1-" in m for m in macs):
        flags.append("ssh_sha1_macs_enabled")
    if any(alg == "ssh-rsa" for alg in hks):
        flags.append("legacy_ssh_hostkey")
    if any("sntrup761x25519" in x for x in kex):
        flags.append("pqc_hybrid_kex")
    return flags

def assess_rdp(find):
    flags = []
    if find.get("security_layer", "").lower().startswith("rdp"):
        flags.append("legacy_rdp_security")
    return flags

def assess_ike(find):
    flags = []
    g = find.get("dhgroup")
    if isinstance(g, int):
        if g < 14:
            flags.append("ike_weak_dh")
        elif g == 14:
            flags.append("ike_modp2048_ok")
        elif g in (19, 20, 21):
            flags.append("ike_ecdh_good")
    if (find.get("integrity") or "").startswith("HMAC_SHA1"):
        flags.append("ike_sha1_integrity")
    if (find.get("encryption") or "") == "AES_CBC":
        flags.append("ike_aes_cbc_used")
    return flags

# ----------------------------
# Orchestration
# ----------------------------
evidence = []

for t in TARGETS:
    host = t["host"]
    tls_port = t["ports"].get("tls", 443)
    ssh_port = t["ports"].get("ssh", 22)
    print(f"\n=== Scanning {host} ({t.get('name','')}) ===")

    # TLS (simple live handshake)
    if is_port_open(host, tls_port):
        tls = tls_probe(host, tls_port)
        tls["risk_flags"] = assess_tls(tls)
        evidence.append(tls)
    else:
        evidence.append({"protocol": "TLS", "host": host, "port": tls_port, "status": "closed"})

    # TLS capability enumeration via nmap
    if ENABLE_NMAP_TLS_ENUM and is_port_open(host, tls_port):
        tls_enum = nmap_ssl_enum(host, tls_port)
        if tls_enum.get("status") == "ok":
            evidence.append(tls_enum)

    # TLS capability enumeration via sslyze (richer JSON)
    if ENABLE_SSLYZE_ENUM and is_port_open(host, tls_port):
        tls_sslyze = sslyze_enum(host, tls_port)
        if tls_sslyze.get("status") == "ok":
            evidence.append(tls_sslyze)

    # Optional PQC hybrid probe (scanner must have oqsprovider)
    if ENABLE_PQC_HYBRID_SCAN and is_port_open(host, tls_port):
        pqc = pqc_hybrid_scan(host, tls_port)
        # Don't fail scan if oqsprovider missing; just record status
        if pqc.get("status") == "ok" and pqc.get("pqc_handshakes"):
            pqc["risk_flags"] = ["pqc_hybrid_detected"]
        evidence.append(pqc)

    # SSH
    if is_port_open(host, ssh_port):
        sshr = nmap_ssh_algos(host, ssh_port)
        sshr["risk_flags"] = assess_ssh(sshr)
        evidence.append(sshr)
    else:
        evidence.append({"protocol": "SSH", "host": host, "port": ssh_port, "status": "closed"})

    # RDP (optional)
    if t["ports"].get("rdp") and is_port_open(host, t["ports"]["rdp"]):
        rdp = rdpscan(host, t["ports"]["rdp"])
        rdp["risk_flags"] = assess_rdp(rdp)
        evidence.append(rdp)

    # IKE/IPsec (best-effort; may be silent)
    ike = ike_scan(host)
    if ike.get("status") == "ok":
        ike["risk_flags"] = assess_ike(ike)
    evidence.append(ike)

    # QUIC (optional)
    quic = quic_probe_udp(host, 443)
    evidence.append(quic)

    # ---------------- Optional: FS/Binary scan (enhanced, SFTP-only) ----------------
def ssh_connect(cfg):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Try explicit in-memory key first (cfg["pkey"]), then key file, then password.
    pkey_obj = None
    passphrase = cfg.get("password")  # reused as key passphrase if needed

    # 1) In-memory private key blob (PEM) if provided
    if cfg.get("pkey"):
        for KeyCls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                pkey_obj = KeyCls.from_private_key(io.StringIO(cfg["pkey"]), password=passphrase)
                break
            except Exception:
                continue

    # 2) Key from file path
    if not pkey_obj and cfg.get("key_filename") and os.path.exists(cfg["key_filename"]):
        for KeyCls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                pkey_obj = KeyCls.from_private_key_file(cfg["key_filename"], password=passphrase)
                break
            except Exception:
                continue

    try:
        client.connect(
            cfg["hostname"],
            port=cfg.get("port", 22),
            username=cfg["username"],
            password=(None if pkey_obj else cfg.get("password")),  # only send password if no key
            pkey=pkey_obj,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        # Sanity-check SFTP availability early
        sftp = client.open_sftp()
        sftp.listdir(".")
        sftp.close()
        return client
    except Exception as e:
        # Surface the exact reason in stdout and in the CBOM evidence (later)
        print(f"[SSH] connect/open_sftp failed: {e}")
        raise


# ----------------------------
# Build CBOM
# ----------------------------
def to_component(find):
    """Map raw finding to a CBOM-ish component record."""
    comp = {
        "timestamp": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
        "host": find.get("host"),
        "protocol": find.get("protocol"),
        "port": find.get("port"),
        "status": find.get("status", "ok"),
        "algorithm": None,
        "key_bits": None,
        "version": None,
        "artifact": None,
        "details": {},
        "risk_flags": find.get("risk_flags", []),
    }
    if find.get("protocol") == "TLS" and find.get("tool") is None:
        # handshake result
        comp["version"] = find.get("tls_version") or find.get("cipher_name")
        comp["algorithm"] = find.get("public_key_alg")
        comp["key_bits"] = find.get("public_key_bits")
        comp["details"] = {
            "cipher": find.get("cipher_name"),
            "secret_bits": find.get("secret_bits"),
            "cert_subject": find.get("cert_subject"),
            "cert_issuer": find.get("cert_issuer"),
            "not_before": find.get("not_before"),
            "not_after": find.get("not_after"),
            "cert_sig_oid": find.get("cert_sig_oid"),
            "cert_sig_hash": find.get("cert_sig_hash"),
        }
    elif find.get("protocol") == "TLS" and find.get("tool") == "nmap ssl-enum-ciphers":
        comp["details"] = {"tls_enum": find.get("enumeration")}
    elif find.get("protocol") == "TLS" and find.get("tool") == "sslyze":
        comp["details"] = find.get("results")
    elif find.get("protocol") == "TLS" and find.get("tool") == "openssl+oqsprovider":
        comp["details"] = {
            "pqc_groups_tried": find.get("pqc_groups_tried"),
            "pqc_handshakes": find.get("pqc_handshakes"),
        }
        if find.get("pqc_handshakes"):
            comp["algorithm"] = "TLS1.3-PQC-HYBRID"
    elif find.get("protocol") == "SSH":
        comp["details"] = {
            "kex": find.get("kex_algorithms"),
            "hostkeys": find.get("server_host_key_algorithms"),
            "ciphers": find.get("encryption_algorithms"),
            "macs": find.get("mac_algorithms"),
        }
        hk = find.get("server_host_key_algorithms") or []
        comp["algorithm"] = ", ".join(hk[:3]) if hk else None
    elif find.get("protocol") == "RDP":
        comp["details"] = {
            "security_layer": find.get("security_layer"),
            "encryption_level": find.get("encryption_level"),
            "tls_version": find.get("tls_version"),
        }
    elif find.get("protocol") == "IKE":
        comp["port"] = find.get("port", 500)
        comp["version"] = "IKEv2"
        comp["algorithm"] = find.get("summary")
        comp["details"] = {
            "dhgroup": find.get("dhgroup"),
            "dh_name": find.get("dh_name"),
            "encryption": find.get("encryption"),
            "key_length": find.get("key_length"),
            "integrity": find.get("integrity"),
            "prf": find.get("prf"),
            "tried_groups": find.get("tried_groups"),
            "raw": (find.get("raw") or "")[:4000],
        }
    elif find.get("protocol") == "QUIC":
        comp["status"] = find.get("status")
        comp["details"] = {"note": "best-effort UDP/443 probe"}
    elif find.get("protocol") == "FS":
        # map diverse FS record shapes
        t = find.get("type")
        comp["details"] = {k: v for k, v in find.items() if k not in {"protocol"}}
        if t == "CERT":
            comp["algorithm"] = find.get("pubkey_alg")
            comp["key_bits"] = find.get("pubkey_bits")
            comp["artifact"] = find.get("path")
        elif t == "KEY":
            comp["algorithm"] = find.get("key_alg")
            comp["key_bits"] = find.get("key_bits")
            comp["artifact"] = find.get("path")
        elif t in {"KEYSTORE","CONFIG","BINARY","LIBS","SYSTEM"}:
            comp["artifact"] = find.get("path")
        else:
            comp["artifact"] = find.get("path")
    elif find.get("protocol") == "META" and find.get("type") == "QUANTUM_SUMMARY":
        comp["details"] = find.get("summary")
    else:
        comp["details"] = {k: v for k, v in find.items() if k not in comp.keys()}
    return comp

quantum_summary = derive_quantum_risk(evidence)
evidence.append({
    "protocol":"META",
    "host": None,
    "port": None,
    "status":"ok",
    "type":"QUANTUM_SUMMARY",
    "summary": quantum_summary,
    "risk_flags":[]
})

components = [to_component(f) for f in evidence]

cbom = {
    "schema": "qs-cbom:v0.3",
    "generated_at": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
    "targets": TARGETS,
    "components": components,
    "policy_refs": ["CNSA 2.0", "FIPS 203-205"],
}

# Save outputs
with open("cbom.json", "w") as f:
    json.dump(cbom, f, indent=2)

rows = []
for c in components:
    details = c.get("details") or {}
    err = details.get("error") if isinstance(details, dict) else None
    rows.append({
        "host": c["host"],
        "protocol": c["protocol"],
        "port": c["port"],
        "status": c["status"],
        "algorithm": c["algorithm"],
        "key_bits": c["key_bits"],
        "version": c["version"],
        "risk_flags": ";".join(c.get("risk_flags", [])),
        "artifact": c.get("artifact"),
        "error": err,
    })
df = pd.DataFrame(rows)
df.to_csv("cbom.csv", index=False)
print("Wrote cbom.json and cbom.csv")
df
