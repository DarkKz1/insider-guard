# Fallback for Fly.io / any Docker host. node:20-slim + build tools for
# better-sqlite3 native compile.
FROM node:20-slim

# build deps for better-sqlite3
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install deps (compiles better-sqlite3)
COPY package*.json ./
RUN npm install --omit=dev || npm install

# app source
COPY . .

# sqlite lives on a mounted volume in prod
ENV DB_PATH=/data/insider.db
ENV PORT=3000
RUN mkdir -p /data

EXPOSE 3000

# seed (idempotent --keep) then start
CMD ["sh", "-c", "npm run seed -- --keep && npm start"]
