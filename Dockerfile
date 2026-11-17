FROM docker.io/library/ubuntu:26.04
ARG NAVIS_VERSION=0.1.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Navis" \
    org.opencontainers.image.version="${NAVIS_VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.source="https://github.com/Zen1988/navis"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    NAVIS_VERSION="${NAVIS_VERSION}" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY pyproject.toml ./
COPY src ./src
COPY web ./web
COPY migrations ./migrations
RUN pip install --no-cache-dir . \
    && python -c "import os; from importlib.metadata import version; assert version('navis-common') == os.environ['NAVIS_VERSION'], 'Image and package versions must match'" \
    && useradd --create-home --uid 10001 navis
USER 10001
EXPOSE 8000
CMD ["uvicorn", "navis_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
