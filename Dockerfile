FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    START_SCHEDULER=1 \
    HOME=/home/app

WORKDIR /app

RUN groupadd -r app && useradd -r -g app -m -d /home/app app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

COPY . .
RUN chown -R app:app /app \
    && chmod +x /app/docker-entrypoint.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).getcode()==200 else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["sh", "-c", "python3 -c 'from models import init_db; init_db(); print(\"JSON storage initialized\")' && exec gunicorn -w 1 -k gthread --threads 4 --timeout 60 --worker-tmp-dir /tmp -b 0.0.0.0:5000 app:app"]
