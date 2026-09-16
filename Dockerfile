# ATL Edge + SmartTokenProd — multi-stage reproducible image
# Build:  docker build -t atl-edge:hardened .
# Run:    docker compose up --build
# Test:   docker compose run --rm testbench

FROM python:3.12-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ gcc make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .
RUN bash build.sh

# ── runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

RUN useradd -m -u 10001 atl \
    && mkdir -p /app /data \
    && chown -R atl:atl /app /data

WORKDIR /app
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /src /app

# Ensure native libs are present and discoverable
RUN test -f /app/vendor/smart_token_prod/libfriction.so \
    && test -f /app/build/libmorph8.so \
    && chown -R atl:atl /app

USER atl
ENV PYTHONPATH=/app/vendor:/app
ENV ATL_DATA_DIR=/data

EXPOSE 8787 8790 8795
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "from src.long_lived_protection import is_available; assert is_available()"

# Default: SmartToken sidecar. Edge API: docker compose service edge-api
CMD ["python", "-m", "src.sidecar_server", "--host", "0.0.0.0", "--port", "8787"]
