FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=2.2.1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python3 -

WORKDIR /app

COPY pyproject.toml poetry.lock README.md /app/
RUN /root/.local/bin/poetry install --no-root --only main

COPY . /app
EXPOSE 5000
#CMD ["granian", "--interface", "wsgi", "--host", "::", "--port", "5000", "--access-log", "app:app"]
CMD ["/root/.local/bin/poetry", "run", "python3", "envoy_authz/app.py"]