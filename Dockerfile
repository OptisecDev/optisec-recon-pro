# ============================================================
# OPTISEC Recon Pro v4.0 SINGULARITY — Production Dockerfile
# ============================================================
FROM python:3.12-slim AS base

# System dependencies (nmap for scanning, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    whois \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# ---- Build stage ----
FROM base AS builder

WORKDIR /build

COPY requirements.txt .

# git is required to install theHarvester from GitHub (git+https dependency)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages into /install prefix
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Runtime stage ----
FROM base AS runtime

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Persistent data lives in a volume; pre-create directories
RUN mkdir -p data/quantum_keys data/wireguard data/wordlists logs reports

# Non-root user for security
RUN groupadd -r optisec && useradd -r -g optisec optisec && \
    chown -R optisec:optisec /app
USER optisec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fs http://localhost:8000/ || exit 1

# --forwarded-allow-ips=* would make uvicorn rewrite request.client.host to
# whatever X-Forwarded-For an attacker sends, for ANY connecting peer -- that
# both defeats web/auth.py's get_client_ip() peer check (it re-checks
# request.client.host, which would already be spoofed by the time it runs)
# and leaves other request.client.host call sites (e.g. web/routers/osint.py)
# spoofable outright. PaaS edge-proxy IPs (Render/Railway/etc.) aren't a
# fixed, publicly documented CIDR we can bake in here, so instead this reuses
# TRUSTED_PROXY_IPS -- the same operator-supplied allowlist get_client_ip
# already trusts (see web/auth.py) -- as an explicit, narrow uvicorn-level
# allowlist. Unset, it defaults to 127.0.0.1 (uvicorn's own safe default):
# no forwarded header is trusted from anywhere until an operator opts in.
CMD ["sh", "-c", "python -m uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --proxy-headers --forwarded-allow-ips=${TRUSTED_PROXY_IPS:-127.0.0.1}"]
