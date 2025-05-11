FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY image_scanner.py .
COPY vulnerability_scan.py .
COPY .env.example .

#ENV NVD_API_KEY="" #user provides API key at runtime as env var

ENTRYPOINT ["python3", "vulnerability_scan.py"]
