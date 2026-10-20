# ==============================================================================
# Stage 1: Builder — Compila e instala dependências de produção em /opt/venv
# Otimizado para Cache de Camadas (Layer Caching) do Docker BuildKit
# ==============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 1. Copia apenas manifestos de dependência primeiro para maximizar o cache de camadas
COPY pyproject.toml README.md ./
RUN mkdir -p src/secsentinel && touch src/secsentinel/__init__.py && \
    pip install --upgrade pip && \
    pip install --no-cache-dir .

# 2. Copia o código-fonte real e instala o pacote local sem baixar dependências novamente
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

# ==============================================================================
# Stage 2: Runtime — Imagem mínima hardened rodando como usuário não-root (UID 10001)
# ==============================================================================
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="SecSentinel" \
      org.opencontainers.image.description="DevSecOps Automated PR & API Security Auditing Platform" \
      org.opencontainers.image.vendor="SecSentinel Engineering" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH"

# Cria grupo e usuário de sistema sem shell interativo (UID/GID > 10000 evita colisão com host)
RUN groupadd --gid 10001 secsentinel && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin secsentinel

WORKDIR /app

COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv
COPY --chown=10001:10001 alembic.ini ./alembic.ini
COPY --chown=10001:10001 alembic ./alembic
COPY --chown=10001:10001 src ./src

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

CMD ["uvicorn", "secsentinel.main:app", "--host", "0.0.0.0", "--port", "8000"]
