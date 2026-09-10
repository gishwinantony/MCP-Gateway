FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config ./config
COPY tests/fixtures ./tests/fixtures

# The gateway spawns upstream servers as subprocesses, so it must not run as
# root. Upstreams inherit only PATH unless inherit_env is set per upstream.
RUN useradd --create-home --uid 10001 gateway \
    && mkdir -p /app/data \
    && chown -R gateway:gateway /app
USER gateway

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

ENTRYPOINT ["mcpgateway", "-c", "config/gateway.yaml"]
CMD ["--mode", "http", "--host", "0.0.0.0"]
