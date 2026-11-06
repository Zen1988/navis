FROM docker.io/library/ubuntu:26.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY pyproject.toml ./
COPY src ./src
COPY web ./web
COPY migrations ./migrations
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 navis
USER 10001
EXPOSE 8000
CMD ["uvicorn", "navis_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
