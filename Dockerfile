# Dockerfile for ip_vendor_identifier application

# Use the Alpine-based Python image for a minimal footprint.
# This uses the 'apk' package manager instead of 'apt-get'.
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_PORT 5000

# 1. Install system dependencies using apk
#    'build-base' provides essential build tools (like build-essential in Debian).
#    'mysql-client-dev' provides the necessary headers and libs for MySQL client (required by packages like mysqlclient).
RUN apk update && \
    apk add --no-cache \
        build-base \
        mariadb-dev \
    && \
    rm -rf /var/cache/apk/*

# Create working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt /app/
# pip install will now use the system headers installed by apk
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and templates
# NOTE: Ensure 'realtime_dns_checker.py' is correctly structured if your app name is 'realtime_dns_checker'
COPY realtime_dns_checker.py /app/
COPY templates /app/templates

# Gunicorn startup command (Production WSGI server)
# -w 4: 4 worker processes (adjust based on CPU cores)
# realtime_dns_checker:APP assumes 'APP' is the Flask/ASGI application object defined in 'realtime_dns_checker.py'
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "realtime_dns_checker:APP"]