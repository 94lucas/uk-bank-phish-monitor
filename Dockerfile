FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UKPHISH_CONFIG_DIR=/app/config \
    UKPHISH_DB_PATH=/app/data/detections.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[dnstwist]"

COPY config ./config

# Run as an unprivileged user (uid 1000). The ./data folder on the host
# must be writable by this uid (see docs/homelab-zimablade.md).
RUN useradd --uid 1000 --create-home ukphish && mkdir -p /app/data && chown ukphish /app/data
USER ukphish

ENTRYPOINT ["ukphish"]
CMD ["stream"]
