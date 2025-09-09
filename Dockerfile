# Python + Debian (bookworm) for wide wheel support
FROM python:3.12-bookworm

# System deps for scanning
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends \
      nmap ike-scan openssl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

# Python deps (include Azure SDKs; harmless if unused)
RUN python -m pip install --upgrade pip && \
    python -m pip install \
      cryptography paramiko pandas pynacl ecdsa sslyze pyjks pyelftools \
      python-dotenv pyyaml \
      azure-identity azure-mgmt-compute azure-mgmt-network \
      ssh-audit psutil

# not for production
RUN pip install debugpy
EXPOSE 5678

# App workspace
WORKDIR /app

COPY . .

# Default command can be overridden at runtime
CMD ["python", "run_scan.py"]
