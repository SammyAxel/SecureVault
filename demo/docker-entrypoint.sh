#!/bin/sh
# Copy seeded demo DB if data directory is empty (fresh volume)
if [ ! -f /app/data/securevault.db ]; then
  echo "[demo] Seeding database from /app/demo/securevault-demo.db …"
  cp /app/demo/securevault-demo.db /app/data/securevault.db
fi
exec "$@"
