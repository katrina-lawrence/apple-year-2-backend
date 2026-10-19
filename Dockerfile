FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY docker-entrypoint.sh ./docker-entrypoint.sh

RUN pip install --no-cache-dir .
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8000

CMD ["./docker-entrypoint.sh"]
