# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HEALTH_PORT=8000

# Create non-root user and working directories
RUN useradd -ms /bin/bash agent && mkdir -p /app /data && chown -R agent:agent /app /data
WORKDIR /app

# Install system deps (if any minimal build tools needed later, keep slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Python deps
COPY runner/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# App code
COPY runner/app /app/app
RUN chown -R agent:agent /app

USER agent
EXPOSE 8000

CMD ["python", "-m", "app.main"]
