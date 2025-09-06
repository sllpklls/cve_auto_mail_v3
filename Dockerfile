FROM python:3.11-slim

WORKDIR /app

# Chỉ cài đặt nếu thực sự cần
# RUN apt-get update && apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*

COPY main.py ./

RUN pip install --no-cache-dir nvdlib requests

ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8

CMD ["python", "main.py"]