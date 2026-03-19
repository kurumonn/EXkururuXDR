FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
COPY docs /app/docs

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -e ".[dev]"

EXPOSE 8810

CMD ["uvicorn", "exkururuxdr.api:app", "--host", "0.0.0.0", "--port", "8810"]
