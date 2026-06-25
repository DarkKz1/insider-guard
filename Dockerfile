# Combined image: the pure-JS Node app + a LOCAL Ollama model runtime in one
# container. The detection engine has no native deps; Ollama is bundled ONLY to
# draft the IR-report narrative on-prem (no external API, no key). Used by
# Railway (primary) and any Docker host (Fly.io, etc.).
#
# Node 22 LTS (not 20): the real-time Live monitor (server/db-source.js) uses the
# built-in `node:sqlite`, which ships only on Node >=22.5. Node 20 is also EOL.
FROM node:22-slim

# curl/ca-certs to fetch the Ollama installer; zstd to extract it (the installer
# now ships a zstd-compressed bundle); tini for clean PID-1 signal handling.
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates tini zstd \
  && rm -rf /var/lib/apt/lists/*

# install the Ollama local-model runtime (CPU build; no systemd in the image —
# we start `ollama serve` ourselves from the entrypoint).
RUN curl -fsSL https://ollama.com/install.sh | sh

WORKDIR /app

# install app deps (pure JS — no native compile)
COPY package*.json ./
RUN npm install --omit=dev || npm install

# app source
COPY . .

ENV PORT=3000
# Ollama runs in THIS container on loopback; the Node server reaches it there.
ENV OLLAMA_HOST=127.0.0.1:11434
ENV OLLAMA_URL=http://127.0.0.1:11434
ENV OLLAMA_MODEL=qwen2.5:7b
# CPU inference is slow (~60s for 7B); give the report endpoint room. Still
# well above the liveness probe, which only gates the fast fallback.
ENV OLLAMA_TIMEOUT_MS=120000
# persist pulled models on a mounted volume (Railway volume at /root/.ollama)
ENV OLLAMA_MODELS=/root/.ollama/models

EXPOSE 3000

COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# tini reaps the backgrounded `ollama serve` cleanly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/entrypoint.sh"]
