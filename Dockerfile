FROM python:3.14-slim

ARG GRPC_HEALTH_PROBE_VERSION=v0.4.37
ARG TARGETARCH

ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=2.2.1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
    && curl -fsSLo /usr/local/bin/grpc_health_probe \
        "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${TARGETARCH}" \
    && chmod +x /usr/local/bin/grpc_health_probe \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python3 -

WORKDIR /app

COPY pyproject.toml poetry.lock README.md /app/
RUN /root/.local/bin/poetry install --no-root --only main

COPY . /app
EXPOSE 5000
#CMD ["granian", "--interface", "wsgi", "--host", "::", "--port", "5000", "--access-log", "app:app"]
CMD ["/root/.local/bin/poetry", "run", "python3", "envoy_authz/app.py"]