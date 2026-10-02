# Hardened runtime image for the Secure Claude Enterprise Application.
#  - slim base, pinned minor version
#  - only runtime dependencies (no pytest, no build tools left behind)
#  - only app.py is copied in; tests, red-team tooling and .env never enter the image
#  - runs as an unprivileged user with a fixed UID
#  - gunicorn with ONE worker: the rate limiter and lockout are in-process state
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AUDIT_DB=/data/audit.db \
    PORT=8000

WORKDIR /app

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install -r requirements.txt "gunicorn>=23,<24"

COPY app.py .

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", \
     "--access-logfile", "-", "app:create_app()"]
