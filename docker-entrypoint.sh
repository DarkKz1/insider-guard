#!/bin/sh
# Combined-container entrypoint: start the LOCAL model runtime, then the web app.
# The Node server comes up IMMEDIATELY (so Railway's /api/health probe passes),
# and the model is pulled in the BACKGROUND. Until the model is ready (first cold
# boot pulls a few GB), the report endpoint falls back to the deterministic mock —
# the app never blocks on, or crashes from, the model setup.
set -e

MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"

# 1) local model runtime (loopback only; the Node server reaches it at 127.0.0.1)
ollama serve &

# 2) background model pull — does NOT gate startup. Persisted on the mounted
#    volume (OLLAMA_MODELS), so it only downloads on the first boot.
(
  i=0
  while [ "$i" -lt 60 ]; do
    if ollama list >/dev/null 2>&1; then break; fi
    i=$((i + 1)); sleep 1
  done
  if ollama list 2>/dev/null | grep -q "$MODEL"; then
    echo "[entrypoint] model $MODEL already present"
  else
    echo "[entrypoint] pulling $MODEL (background; report uses mock until ready)…"
    ollama pull "$MODEL" || echo "[entrypoint] WARN: pull failed; report stays on mock"
  fi
) &

# 3) web app in the foreground (PID 1 via tini). Server self-seeds the demo corpus.
exec node server/server.js
