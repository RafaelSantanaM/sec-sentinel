# ==============================================================================
# Stage 1: Builder — Compila e instala apenas dependências de produção em /opt/venv
# ==============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip && \
    pip install --no-cache-dir .

# ==============================================================================
# Stage 2: Runtime — Imagem mínima sem compiladores e rodando como UID 10001
# ==============================================================================
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --gid 10001 secsentinel && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin secsentinel

WORKDIR /app

COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv
COPY --chown=10001:10001 alembic.ini ./alembic.ini
COPY --chown=10001:10001 alembic ./alembic
COPY --chown=10001:10001 src ./src

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["uvicorn", "secsentinel.main:app", "--host", "0.0.0.0", "--port", "8000"]
