FROM python:3.12-slim

WORKDIR /app

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY *.py .
COPY templates/ templates/
COPY Static/ static/

ENV LICENSE_DATA_DIR=/app/data

RUN mkdir -p /app/data

ENTRYPOINT ["python", "app_license.py"]
