# ============================================
# SecureVault v2 - Production Dockerfile
# Multi-stage build for optimized image
# ============================================

# Build stage - Backend
FROM node:24-alpine AS backend-builder

WORKDIR /app/backend
COPY backend/package*.json ./
# better-sqlite3: no prebuild for node24+musalpine; node-gyp needs a toolchain
RUN apk add --no-cache python3 make g++ \
  && npm install --ignore-scripts=false && npm cache clean --force
COPY backend/ ./
RUN npm run build

# Build stage - Frontend  
FROM node:24-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --ignore-scripts=false && npm cache clean --force
COPY frontend/ ./
RUN npm run build

# Production stage
FROM node:24-alpine AS production

# Security: create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S securevault -u 1001

WORKDIR /app

# Copy backend build
COPY --from=backend-builder --chown=securevault:nodejs /app/backend/dist ./dist
COPY --from=backend-builder --chown=securevault:nodejs /app/backend/package*.json ./

# Install only production dependencies (native compile for better-sqlite3)
RUN apk add --no-cache --virtual .native-build python3 make g++ \
  && npm install --omit=dev && npm cache clean --force \
  && apk del .native-build

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
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

# Start server
CMD ["node", "dist/server.js"]
