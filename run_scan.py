
#!/usr/bin/env python3
import json, os, runpy, sys
from pathlib import Path

'''
# remove comment to enable debugpy, set breakpoints in VSCode
import debugpy
# Allow remote debugging and wait for a client to connect
debugpy.listen(("0.0.0.0", 5678)) # Listen on all interfaces
debugpy.wait_for_client()
'''

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
    if path.suffix.lower() in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML not installed. Run: python -m pip install pyyaml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    targets = data.get("targets") or data.get("TARGETS") or []
    ssh_auth = data.get("ssh_auth") or data.get("SSH_AUTH") or {"enabled": False}
    return targets, ssh_auth

def env_bool(name: str, default: bool):
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1","true","yes","on")

def main():
    load_dotenv(dotenv_path=ROOT / ".env")

    enable_quic      = env_bool("ENABLE_QUIC_PROBE",      False)
    enable_nmap_tls  = env_bool("ENABLE_NMAP_TLS_ENUM",   True)
    enable_sslyze    = env_bool("ENABLE_SSLYZE_ENUM",     True)
    enable_pqc_hyb   = env_bool("ENABLE_PQC_HYBRID_SCAN", True)

    tfile = os.getenv("TARGETS_FILE", "targets.yaml")
    targets, ssh_auth = load_targets(ROOT / tfile)

    globs = {
        "__name__": "__main__",
        "ENABLE_QUIC_PROBE": enable_quic,
        "ENABLE_NMAP_TLS_ENUM": enable_nmap_tls,
        "ENABLE_SSLYZE_ENUM": enable_sslyze,
        "ENABLE_PQC_HYBRID_SCAN": enable_pqc_hyb,
        "TARGETS": targets,
        "SSH_AUTH": ssh_auth,
    }

    runpy.run_path(str(SCANNER), init_globals=globs)

if __name__ == "__main__":
    main()
