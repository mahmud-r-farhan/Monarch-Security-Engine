FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src ./src
COPY vite.config.js tsconfig.json ./
RUN npm run build

FROM node:22-alpine AS production
WORKDIR /app
ENV NODE_ENV=production PORT=3000
RUN apk add --no-cache python3 go || true

COPY package*.json ./
RUN npm ci --omit=dev --omit=optional && npm cache clean --force

COPY --from=builder /app/dist ./dist
COPY src ./src
COPY public ./public
COPY demo ./demo
COPY services ./services

RUN mkdir -p /app/reports && chown -R node:node /app

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

LABEL org.opencontainers.image.source="https://github.com/mahmud-r-farhan/Monarch-Security-Engine"
LABEL org.opencontainers.image.description="Monarch Security Engine - Professional Web Vulnerability Scanner & Network Defense Platform"
LABEL org.opencontainers.image.licenses="Apache-2.0"

CMD ["node", "src/server.js"]
