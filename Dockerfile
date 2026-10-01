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

# git is required to install theHarvester from GitHub (git+https dependency);
# cmake/ninja-build/build-essential build liboqs (PQC) as a native C library below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git cmake ninja-build build-essential && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages into /install prefix
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- liboqs (Open Quantum Safe) — native C library backing liboqs-python ----
# Pinned to the release matching the liboqs-python version in requirements.txt
# (liboqs-python 0.16.0.1 -> liboqs 0.16.0) so the ABI liboqs-python's ctypes
# bindings expect is guaranteed to match what's actually loaded.
#
# OQS_MINIMAL_BUILD restricts the build to only the algorithms this app uses
# (modules/quantum/encryption.py's PQC_ALGORITHMS) instead of liboqs' full ~40
# algorithm suite — this cuts build time from ~15min to ~30s and the resulting
# .so from a full build down to ~1-2MB.
# OQS_USE_OPENSSL=OFF statically embeds liboqs' own crypto primitives instead
# of dynamically linking system OpenSSL, so the runtime image needs no libssl
# package and there's no builder/runtime OpenSSL-version mismatch risk.
# OQS_DIST_BUILD=ON bakes in runtime CPU-feature detection (AVX2/AVX512/etc.)
# so one build works correctly regardless of which specific x86_64 the builder
# ran on vs. the host Render eventually schedules the container onto.
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /build/liboqs-src && \
    cmake -GNinja -S /build/liboqs-src -B /build/liboqs-src/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DOQS_USE_OPENSSL=OFF \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_65;SIG_falcon_512;SIG_slh_dsa_pure_sha2_128s" \
        -DCMAKE_INSTALL_PREFIX=/install-liboqs && \
    cmake --build /build/liboqs-src/build && \
    cmake --install /build/liboqs-src/build && \
    rm -rf /build/liboqs-src

# ---- Runtime stage ----
FROM base AS runtime

WORKDIR /app

# Copy installed Python packages
COPY --from=builder /install /usr/local

# Copy the liboqs native shared library and register it with the dynamic
# linker (ldconfig) so ctypes.util.find_library("oqs"), which liboqs-python
# uses to locate it, succeeds at import time. Without this, liboqs-python
# silently falls back to git-cloning and compiling the FULL liboqs suite from
# scratch inside the running container on first use -- slow, network-
# dependent, and not something that belongs in a request path.
COPY --from=builder /install-liboqs/lib /usr/local/lib
RUN ldconfig

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
CMD ["sh", "-c", "python -m uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips=${TRUSTED_PROXY_IPS:-127.0.0.1}"]
