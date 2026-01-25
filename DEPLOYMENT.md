# SecureVault Deployment Guide

This guide describes how to deploy SecureVault in a production environment using Docker.

## Prerequisites

- Docker Engine & Docker Compose installed.
- A domain name (optional, but recommended for SSL).
- A reverse proxy (Nginx/Caddy) for SSL termination (highly recommended).

## Security Notes

- **Database**: This demo uses SQLite (`app_v2.db`). For high-concurrency production, switch to PostgreSQL.
- **SSL/TLS**: The application runs on HTTP by default. **You MUST use a reverse proxy with SSL (HTTPS)** to ensure the safety of the encryption keys during transit (even though files are E2EE, the initial key exchange and app delivery need HTTPS).
- **Secrets**: Change the `SECRET_KEY` in `server.py` (if applicable) or inject it via environment variables.
- **Rate Limiting**: Configured in `server.py` using `Flask-Limiter`. Default storage is in-memory. For multi-worker deployments (e.g., Gunicorn with multiple workers), use Redis as storage.

## Deployment Steps

### 1. Build and Run

1.  Clone the repository.
2.  Build the Docker image:
    ```bash
    docker-compose build
    ```
3.  Start the container in detached mode:
    ```bash
    docker-compose up -d
    ```

The application will be available at `http://localhost:5000`.

### 2. Persistence

- **Uploads**: Stored in `./uploads` (mapped to `/app/uploads` in container).
- **Database**: Stored in `./app_v2.db` (mapped to `/app/app_v2.db` in container).

Ensure these files/directories are backed up regularly.

### 3. Updates

To update the application:

1.  Pull the latest code.
2.  Rebuild the container:
    ```bash
    docker-compose build --no-cache
    ```
3.  Restart:
    ```bash
    docker-compose up -d
    ```

## Troubleshooting

- **Check Logs**:
    ```bash
    docker-compose logs -f
    ```
- **Enter Container**:
    ```bash
    docker-compose exec web bash
    ```

## Hardening Details

- **Base Image**: `python:3.11-slim` (Minimal footprint).
- **User**: Runs as non-root `appuser` (if configured in Dockerfile).
- **Server**: Uses `gunicorn` production WSGI server.
- **Headers**: Security headers enforced in `server.py`:
    - `Strict-Transport-Security` (HSTS)
    - `X-Frame-Options: DENY`
    - `X-Content-Type-Options: nosniff`
    - `Content-Security-Policy` (CSP)
- **Rate Limiting**: Anti-brute-force protection on `/register`, `/challenge`, `/verify`, and `/2fa/setup`.
