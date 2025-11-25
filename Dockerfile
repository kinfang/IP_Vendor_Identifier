# Use a slim Python image for a smaller final size
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_PORT 5000

# Install necessary system libraries for robust database connection
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code and templates
COPY realtime_dns_checker.py /app/
COPY templates /app/templates

# Gunicorn startup command (Production WSGI server)
# -w 4: 4 worker processes (adjust based on CPU cores, typically 2*cores + 1)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "realtime_dns_checker:APP"]