#!/bin/sh
set -eu

# Vite env vars are build-time, but we serve static files.
# This entrypoint writes a runtime JS config that the SPA reads.

python3 - <<'PY'
import json
import os

api_base = os.environ.get("PTW_API_BASE") or os.environ.get("VITE_API_BASE") or "/api"

# Write into the dist root so it can be fetched as /runtime-config.js
path = "/app/dist/runtime-config.js"
with open(path, "w", encoding="utf-8") as f:
    f.write("window.__PTW_RUNTIME_CONFIG__ = {\n")
    f.write(f"  API_BASE: {json.dumps(api_base)},\n")
    f.write("};\n")
print(f"[frontend] runtime-config.js written: API_BASE={api_base}")
PY

exec python3 -m http.server 8080 --directory /app/dist
