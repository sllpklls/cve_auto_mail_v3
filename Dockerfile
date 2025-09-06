# Use official Python image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (if any needed for nvdlib, requests, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements.txt if exists, else install directly
COPY main.py ./

# Install Python dependencies
RUN pip install --no-cache-dir nvdlib requests

# Set environment variables (optional, for UTF-8)
ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8

# Run the script
CMD ["python", "main.py"]
