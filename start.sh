#!/bin/bash
set -euo pipefail

CERT_PATH="$PWD/cert.pem"
KEY_PATH="$PWD/key.pem"

# Generate certificates if they don't exist
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Generating self-signed certificates..."
    if ! python generate_cert.py; then
        echo "Error: generate_cert.py failed" >&2
        ls -la "$PWD" >&2
        exit 1
    fi
fi

# Ensure cert files exist
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Error: certificates not found after generation" >&2
    ls -la "$PWD" >&2
    exit 1
fi

# Start Gunicorn with SSL
exec gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --certfile="$CERT_PATH" --keyfile="$KEY_PATH" server:app
