FROM postgres:16-bookworm AS pgtools
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git postgresql-client && rm -rf /var/lib/apt/lists/*
COPY --from=pgtools /usr/lib/postgresql/16 /usr/lib/postgresql/16
COPY --from=pgtools /usr/lib/x86_64-linux-gnu/libpq.so.5* /usr/lib/x86_64-linux-gnu/
ENV PATH=/usr/lib/postgresql/16/bin:$PATH
WORKDIR /app
COPY requirements.lock pyproject.toml README.md /app/
RUN pip install --no-cache-dir -r requirements.lock
COPY src /app/src
RUN pip install --no-cache-dir '.[test]'
COPY . /app
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "pytest", "-q"]

RUN pip install --no-cache-dir playwright && python -m playwright install --with-deps webkit
