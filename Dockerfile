# ─── Stage 1: Build frontend ───
FROM node:20-alpine AS frontend
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

# ─── Stage 2: Production server ───
FROM node:20-alpine AS production
WORKDIR /app

# Install production deps only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy built frontend
COPY --from=frontend /app/dist ./dist

# Copy server source (will run with tsx in prod, or compile separately)
COPY server ./server

# Serve static frontend from Express in production
ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/api/health || exit 1

CMD ["npx", "tsx", "server/index.ts"]
