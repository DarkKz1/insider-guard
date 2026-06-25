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
#    The pull is RETRIED (a single attempt that silently swallowed a transient
#    registry/network failure was the bug: the model stayed absent and the report
#    fell back to mock forever, even though the daemon was up).
(
  i=0
  while [ "$i" -lt 60 ]; do
    if ollama list >/dev/null 2>&1; then break; fi
    i=$((i + 1)); sleep 1
  done
  if ollama list 2>/dev/null | awk '{print $1}' | grep -qxF "$MODEL"; then
    echo "[entrypoint] model $MODEL already present"
  else
    n=1
    while [ "$n" -le 5 ]; do
      echo "[entrypoint] pulling $MODEL (attempt $n/5; report uses mock until ready)…"
      if ollama pull "$MODEL"; then
        echo "[entrypoint] model $MODEL pulled — report will use the local LLM"
        break
      fi
      echo "[entrypoint] pull attempt $n failed; retrying in 3s…"
      n=$((n + 1)); sleep 3
    done
    [ "$n" -gt 5 ] && echo "[entrypoint] WARN: $MODEL not pulled after 5 attempts; report stays on mock"
  fi
) &

# 3) web app in the foreground (PID 1 via tini). Server self-seeds the demo corpus.
exec node server/server.js
