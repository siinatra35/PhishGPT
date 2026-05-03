# =============================================================================
# phishGPT – Multi-stage Dockerfile
#
# Shared Python base keeps images small and dependency installs consistent.
# Each service is a separate target so docker compose can build them
# independently from the same Dockerfile.
#
# Build a single service:   docker build --target flask_app -t phishgpt-app .
# Build everything:         docker compose build
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 0: shared Python base (Alpine + Python 3)
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS python_base

RUN apk add --no-cache python3 py3-pip && \
    ln -sf python3 /usr/bin/python

WORKDIR /opt

# Common to every service – install once, cache forever
COPY requirements/base.txt /tmp/base.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/base.txt


# ---------------------------------------------------------------------------
# Flask API
# ---------------------------------------------------------------------------
FROM python_base AS flask_app
LABEL service="flask_app"

COPY requirements/flask_app.txt /tmp/flask_app.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/flask_app.txt

COPY app.py .

EXPOSE 5000
CMD ["python", "app.py"]


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
FROM mongo:7.0 AS gpt_db
LABEL service="gpt_db"

COPY init-mongo.js /docker-entrypoint-initdb.d/
EXPOSE 27017


# ---------------------------------------------------------------------------
# Redirect checker
# ---------------------------------------------------------------------------
FROM python_base AS redirect_box
LABEL service="redirect_check"

COPY scripts/redirect_check.py .
CMD ["python", "redirect_check.py"]


# ---------------------------------------------------------------------------
# Net tools (DNS / WHOIS / ASN / geolocation / cert)
# ---------------------------------------------------------------------------
FROM python_base AS net_tools
LABEL service="net_tools"

COPY requirements/net_tools.txt /tmp/net_tools.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/net_tools.txt

COPY scripts/net_tools.py .
COPY data/IP2LOCATION-LITE-DB11.BIN /opt/data/

ENV IP2LOC_DB_PATH=/opt/data/IP2LOCATION-LITE-DB11.BIN
CMD ["python", "net_tools.py"]


# ---------------------------------------------------------------------------
# Site OCR (trafilatura text extraction)
# ---------------------------------------------------------------------------
FROM python_base AS ocr_box
LABEL service="site_ocr"

COPY requirements/ocr.txt /tmp/ocr.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/ocr.txt

COPY scripts/site_ocr.py .
CMD ["python", "site_ocr.py"]


# ---------------------------------------------------------------------------
# Screenshot (headless Chrome + Tesseract OCR)
# Needs Ubuntu for Chrome – can't share the Alpine base
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS screenshot_box
LABEL service="screenshot"

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt

# System deps in one layer, clean up after
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget gnupg ca-certificates \
        python3 python3-pip \
        tesseract-ocr \
    && wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get install -y /tmp/chrome.deb \
    && rm -rf /tmp/chrome.deb /var/lib/apt/lists/*

COPY requirements/screenshot.txt /tmp/screenshot.txt
RUN pip install --no-cache-dir -r /tmp/screenshot.txt

COPY scripts/screenshot.py .
CMD ["python3", "screenshot.py"]


# ---------------------------------------------------------------------------
# AI Prompt (Claude API / Ollama)
# ---------------------------------------------------------------------------
FROM python_base AS ai_prompt
LABEL service="ai_prompt"

COPY requirements/ai_prompt.txt /tmp/ai_prompt.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/ai_prompt.txt

COPY scripts/ai_prompt.py .
CMD ["python", "create.py"]