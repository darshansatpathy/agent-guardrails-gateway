# syntax=docker/dockerfile:1
FROM python:3.15-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies
COPY evals ./evals
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.15-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGGW_DATA_DIR=/data
RUN useradd --system --uid 10001 --home /app aggw \
    && mkdir -p /data /app \
    && chown aggw /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER aggw
WORKDIR /app
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/healthz'); sys.exit(0)"
CMD ["aggw", "serve", "--host", "0.0.0.0", "--port", "8080"]
