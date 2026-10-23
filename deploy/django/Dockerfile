# Scenario A internal application (telecom-lab-django:0.1)
#   python:3.12-slim + Django 6.0.8 + Gunicorn, SQLite at /app/data/db.sqlite3
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app/data

EXPOSE 8000
# health check used by Docker to mark the container healthy (slim image has no curl -> use python)
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/',timeout=3).status==200 else 1)"

ENTRYPOINT ["/entrypoint.sh"]
