
#!/usr/bin/env python3
import json, os, runpy, sys
import qs_utils
from pathlib import Path
from flask import Flask, request

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

app = Flask(__name__)

ROOT = Path(__file__).parent.resolve()
SCANNER = ROOT / "qs_scanner.py"
OUTPUT_DIR = ROOT / qs_utils.get_current_timestamp()

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

# -------
# runs the scanner tool with config from .env and targets.yaml
# -------
def run_scanner():
    load_dotenv(dotenv_path=ROOT / ".env")

    # update output directory for output files
    global OUTPUT_DIR 
    OUTPUT_DIR = ROOT / qs_utils.get_current_timestamp()

    # create output directory
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

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
        "OUTPUT_DIR": OUTPUT_DIR
    }

    runpy.run_path(str(SCANNER), run_name='__main__', init_globals=globs)

# -------
# main entry point
# -------
def main():
    run_scanner()    

# -------
# simple Flask API to get results
# TODO: create API module
# -------

@app.route('/')
def hello_world():
    return 'QS Ready!'

@app.route('/runscan', methods=['GET'])
def runscan():
    try:
        run_scanner()
        return {"status": "scan completed"}, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/status', methods=['GET'])
def status():
    return {"status": "running"}, 200

@app.route('/results', methods=['GET'])
def results():
    results = []
    for file in os.listdir(OUTPUT_DIR):
        if file.endswith(".json"):
            with open(os.path.join(OUTPUT_DIR, file), 'r') as f:
                data = json.load(f)
                results.append(data)
    return {"results": results}, 200

@app.route('/cbom', methods=['GET'])
def cbom():
    for file in os.listdir(OUTPUT_DIR):
        if file.endswith("cbom_scan.json"):
            with open(os.path.join(OUTPUT_DIR, file), 'r') as f:
                data = json.load(f)
                return data, 200
    return {"cbom": 'not found'}, 200

@app.route('/scan', methods=['GET'])
def scan():
    type = request.args.get('type', None)
    host = request.args.get('host', None)
    if type is None or host is None:
        return {"error": "type and host parameters are required"}, 400
    
    for file in os.listdir(OUTPUT_DIR):
        if file.startswith(type) and file.endswith(f"{host}.json"):
            with open(os.path.join(OUTPUT_DIR, file), 'r') as f:
                data = json.load(f)
                return data, 200
            
    return {"scan": 'not found'}, 200
    # create output directory
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    main()
    app.run(host='0.0.0.0', port=5555)

