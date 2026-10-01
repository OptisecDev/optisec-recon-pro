# syntax=docker/dockerfile:1.7
# ============================================================
# OPTISEC Recon Pro v4.0 SINGULARITY — Production Dockerfile
# ============================================================
# Pinned by digest, not just the "3.12-slim" tag: Docker Hub repoints that
# tag whenever Debian/Python ship a point release, and an unpinned FROM
# invalidates every downstream layer (apt, pip, the liboqs build) on
# whichever deploy happens to race that repoint -- indistinguishable from a
# cold build even though nothing in this repo changed. Bump deliberately:
# `docker pull python:3.12-slim && docker inspect python:3.12-slim --format
# '{{index .RepoDigests 0}}'`.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS base

# System dependencies (nmap for scanning, curl for health checks)
#
# --mount=type=cache persists apt's downloaded .deb files and package index
# across builds, on any builder that retains its BuildKit cache between
# invocations (confirmed: local `docker buildx` with a docker-container
# builder, and most CI runners). docker-clean is the stock Debian image's
# post-install hook that deletes /var/cache/apt/archives/*.deb right after
# each install -- without disabling it first, the cache mount would stay
# permanently empty. If a given builder does NOT retain the mount between
# invocations, this is a safe no-op: apt just re-downloads, identical to
# today.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    whois \
    wireguard-tools

# ---- Build stage ----
FROM base AS builder

WORKDIR /build

COPY requirements.txt .

# git is required to install theHarvester from GitHub (git+https dependency);
# cmake/ninja-build/build-essential build liboqs (PQC) as a native C library below.
# Same cache-mount reasoning as the base stage's apt RUN above (shares that
# RUN's cache bucket, since both mounts target the same paths).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends git cmake ninja-build build-essential

# Install Python packages into /install prefix.
# --mount=type=cache on pip's cache dir (not --no-cache-dir, which would
# disable that cache outright) lets pip skip re-downloading/rebuilding
# wheels for an unchanged requirements.txt across builds, on a builder that
# retains the mount. The final image still only gets /install (COPY
# --from=builder below, runtime stage) -- the pip cache itself never leaves
# the mount, so this doesn't add anything to image size either way.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt

# ---- liboqs (Open Quantum Safe) — native C library backing liboqs-python ----
# Pinned to the release matching the liboqs-python version in requirements.txt
# (liboqs-python 0.16.0.1 -> liboqs 0.16.0) so the ABI liboqs-python's ctypes
# bindings expect is guaranteed to match what's actually loaded.
#
# OQS_MINIMAL_BUILD restricts the build to only the algorithms this app uses
# (modules/quantum/encryption.py's PQC_ALGORITHMS) instead of liboqs' full ~40
# algorithm suite — liboqs applies this filter identically regardless of
# OQS_DIST_BUILD (see upstream .CMake/alg_support.cmake), so these 5
# algorithms are ALL that ever get compiled here, on Render or anywhere else.
# Measured locally (liboqs 0.16.0, this exact flag set): ~38s wall time,
# ~292 object files — this is "minutes", not the hours a full ~40-algorithm
# build would take. If a Render build is still taking far longer than that,
# the liboqs step above is very unlikely to be the cause; look at Docker
# layer-cache reuse between deploys and apt-get/pip mirror speed instead.
# OQS_USE_OPENSSL=OFF statically embeds liboqs' own crypto primitives instead
# of dynamically linking system OpenSSL, so the runtime image needs no libssl
# package and there's no builder/runtime OpenSSL-version mismatch risk.
# OQS_DIST_BUILD=ON bakes in runtime CPU-feature detection (AVX2/AVX512/etc.)
# so one build works correctly regardless of which specific x86_64 the builder
# ran on vs. the host Render eventually schedules the container onto. Turning
# it OFF was evaluated as a further speedup (measured ~46% less liboqs build
# time: ~236 objects / ~20s instead of ~292 / ~38s) but was rejected: per
# liboqs' own CONFIGURE.md, OQS_DIST_BUILD=OFF auto-detects and bakes in
# whatever CPU features the BUILD machine has, with no runtime check — if
# Render's builder and the host it schedules the container onto ever differ
# in CPU generation, that produces a SIGILL crash in production. The ~18s
# saved isn't worth that risk.
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
