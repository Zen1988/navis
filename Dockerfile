FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app/src
COPY pyproject.toml ./
COPY src ./src
COPY web ./web
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 navis
USER 10001
EXPOSE 8000
CMD ["uvicorn", "navis_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
