# NOT executed in the environment this project was built in (no Docker daemon). Treat as a starting point and test it.
FROM node:22-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt && playwright install --with-deps chromium
COPY backend/ backend/
COPY demo/ demo/
COPY --from=web /web/dist frontend/dist
RUN useradd --system --create-home --uid 10001 cyberrecon && mkdir /data && chown cyberrecon /data /ms-playwright
USER cyberrecon
ENV CYBERRECON_DATA_DIR=/data CYBERRECON_ENVIRONMENT=production
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]
