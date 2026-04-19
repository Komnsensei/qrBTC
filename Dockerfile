# ═══════════════════════════════════════════════════════════════
# qBTC Full Node — Multi-Stage Docker Build
# ═══════════════════════════════════════════════════════════════
# Stage 1: Build liboqs (post-quantum crypto C library)
# Stage 2: Install Python dependencies + qBTC
# Stage 3: Minimal runtime image
#
# Build:  docker build -t qbtc-node .
# Run:    docker run -p 19333:19333 -p 19332:19332 -v qbtc_data:/data qbtc-node
# Mine:   docker run -p 19333:19333 qbtc-node --mine
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Build liboqs ────────────────────────────────────
FROM python:3.12-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake gcc g++ make libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git \
    && cmake -S liboqs -B liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DOQS_BUILD_ONLY_LIB=ON \
    && cmake --build liboqs/build --parallel $(nproc) \
    && cmake --build liboqs/build --target install

# ── Stage 2: Python Environment ─────────────────────────────
FROM python:3.12-slim AS python-builder

COPY --from=liboqs-builder /opt/liboqs /opt/liboqs

ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV OQS_INSTALL_PATH=/opt/liboqs

WORKDIR /app

# Install liboqs-python + project deps
RUN pip install --no-cache-dir \
    liboqs-python>=0.11.0 \
    pycryptodome>=3.20.0 \
    aiohttp>=3.9.0 \
    msgpack>=1.0.7 \
    rich>=13.7.0 \
    click>=8.1.7 \
    structlog>=24.1.0 \
    cryptography>=42.0.0

COPY . /app
RUN pip install --no-cache-dir .

# ── Stage 3: Minimal Runtime ────────────────────────────────
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -m qbtc

COPY --from=liboqs-builder /opt/liboqs/lib /opt/liboqs/lib
COPY --from=python-builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=python-builder /usr/local/bin /usr/local/bin
COPY --from=python-builder /app /app

ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV PYTHONUNBUFFERED=1

# Data volume
VOLUME /data
ENV QBTC_DATA_DIR=/data

# P2P + RPC ports
EXPOSE 19333 19332

USER qbtc
WORKDIR /app

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD echo '{"jsonrpc":"2.0","method":"getinfo","id":1}' | \
        python -c "import socket,sys; s=socket.socket(); s.connect(('127.0.0.1',19332)); s.send(sys.stdin.buffer.read()); print(s.recv(4096))" \
        || exit 1

ENTRYPOINT ["qbtc-node"]
CMD ["--data-dir", "/data", "--host", "0.0.0.0", "--port", "19333", "--rpc-port", "19332"]