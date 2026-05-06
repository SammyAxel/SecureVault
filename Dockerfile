# ============================================
# SecureVault v2 - Production Dockerfile
# Multi-stage build for optimized image
# ============================================

# Build stage - Backend
FROM node:22-bookworm-slim AS backend-builder

WORKDIR /app/backend
COPY backend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm cache clean --force
COPY backend/ ./
RUN npm run build

# Build stage - Frontend  
FROM node:22-bookworm-slim AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm cache clean --force
COPY frontend/ ./
RUN npm run build

# Production stage
FROM node:22-bookworm-slim AS production

# Security: create non-root user
RUN groupadd -g 1001 nodejs && \
    useradd -m -u 1001 -g nodejs securevault && \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy backend build
COPY --from=backend-builder --chown=securevault:nodejs /app/backend/dist ./dist
COPY --from=backend-builder --chown=securevault:nodejs /app/backend/package*.json ./

# Install only production dependencies (native compile for better-sqlite3)
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi && npm cache clean --force

# Copy frontend build
COPY --from=frontend-builder --chown=securevault:nodejs /app/frontend/dist ./frontend/dist

# Create data directories with correct permissions
RUN mkdir -p /app/data /app/uploads && \
    chown -R securevault:nodejs /app/data /app/uploads

# Switch to non-root user
USER securevault

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_URL=/app/data/securevault.db
ENV STORAGE_PATH=/app/uploads
ENV LOG_LEVEL=info

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:3000/api/health >/dev/null || exit 1

# Start server
CMD ["node", "dist/server.js"]
