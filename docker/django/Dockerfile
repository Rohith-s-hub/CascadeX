FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ═══════════════════════════════════════════════════════════
# System dependencies for ALL CascadeX features
# ═══════════════════════════════════════════════════════════
#
# netcat-openbsd  → entrypoint.sh: wait for PostgreSQL
# libpq-dev + gcc → compile psycopg2 (PostgreSQL driver)
# nmap            → Active Network Scanner (active_scanner.py)
# curl            → debug API connectivity (NVD, CISA, Slack, Jira)
# iputils-ping    → validate scan targets before nmap
# dnsutils        → DNS resolution for hostname scanning
# procps          → monitor background threads (realtime_monitor.py)
#
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    libpq-dev \
    gcc \
    nmap \
    curl \
    iputils-ping \
    dnsutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project (respects .dockerignore)
COPY . .

# Create runtime directories
#   logs/        → application logging
#   staticfiles/ → Django collectstatic output
#   media/       → uploaded files / exports
RUN mkdir -p /app/logs /app/staticfiles /app/media

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]