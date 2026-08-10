FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

# No package-lock simplifies the copy; there are zero runtime dependencies,
# so no npm install is required at runtime.
COPY backend/package.json backend/
COPY backend/server.js backend/
COPY backend/lib/ backend/lib/

COPY public/ public/

# Persistent volumes for site data and uploads (keep across restarts).
ENV STRIKEUP_STORE_DATA_DIR=/app/backend/data
ENV STRIKEUP_STORE_UPLOADS_DIR=/app/backend/uploads
RUN mkdir -p /app/backend/data /app/backend/uploads && chown -R node:node /app/backend
VOLUME ["/app/backend/data", "/app/backend/uploads"]

USER node
EXPOSE 8788
CMD ["node", "backend/server.js"]