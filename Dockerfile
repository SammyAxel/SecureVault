# Use official Python runtime as a parent image
FROM python:3.11-slim

LABEL org.opencontainers.image.authors="maintainer@example.com"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8

# Install build-time dependencies required for some packages (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and directories
RUN useradd -m -d /home/app -s /bin/bash app && \
    mkdir -p /app/uploads /app/instance && chown -R app:app /app

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy project files
COPY . .

# Generate certificates at build-time so image contains valid certs (best-effort)
# Note: still safe to generate at startup if certs are missing (start.sh checks)
RUN python generate_cert.py || (echo "Certificate generation at build failed"; exit 0)

# Make start script executable
RUN chmod +x start.sh

# Drop build deps to keep image small
RUN apt-get purge -y --auto-remove build-essential gcc && rm -rf /var/lib/apt/lists/* || true

# Switch to non-root user
USER app

# Expose port
EXPOSE 5000

# Healthcheck (allow self-signed cert with --insecure)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=5 \
  CMD curl -f --insecure https://localhost:5000/ || exit 1

# Run with start script (start.sh handles cert generation at runtime if needed)
CMD ["/bin/bash", "start.sh"]
