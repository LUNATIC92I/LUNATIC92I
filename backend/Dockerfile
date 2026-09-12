# syntax=docker/dockerfile:1
# Pinned by exact version+variant, never `latest` (THREAT_MODEL.md / spec §32).
FROM python:3.12.7-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- dependency layer (cached separately from source for faster rebuilds) ---
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# --- application source ---
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

RUN groupadd --system lunatic && useradd --system --gid lunatic --no-create-home lunatic \
    && chown -R lunatic:lunatic /app
USER lunatic

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
