"""FastMCP server that exposes Ghidra read-only tools."""
import logging
import os
from typing import Any, Dict

import httpx
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
import uvicorn

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

GHIDRA_PIPE_BASE_URL = os.getenv("GHIDRA_PIPE_BASE_URL", "http://localhost:8000").rstrip("/")
MCP_HOST = os.getenv("GHIDRA_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("GHIDRA_MCP_PORT", "9000"))
REQUEST_TIMEOUT = float(os.getenv("GHIDRA_MCP_TIMEOUT", "90"))

# Allow local development origins by default; can be tightened via env var later
ALLOW_ORIGINS = os.getenv("GHIDRA_MCP_ALLOW_ORIGINS", "*")
STATELESS_HTTP = os.getenv("FASTMCP_STATELESS_HTTP", "true").strip().lower() in {"1", "true", "yes", "on"}

mcp = FastMCP("Ghidra MCP")


def _request_json(method: str, path: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    url = f"{GHIDRA_PIPE_BASE_URL}{path}"
    try:
        response = httpx.request(method, url, params=params, timeout=REQUEST_TIMEOUT)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Failed to reach ghidra_pipe at {url}: {exc}") from exc

    if response.status_code == 409:
        raise RuntimeError("No binary loaded in ghidra_pipe. Upload and analyze first.")
    if response.status_code == 404:
        raise RuntimeError(f"Target not found: {params}")
    if response.status_code >= 400:
        raise RuntimeError(f"ghidra_pipe error {response.status_code}: {response.text}")

    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("Unexpected response format from ghidra_pipe")
    return data


@mcp.tool
def decompile_function(target: str) -> Dict[str, Any]:
    """Decompile a single function by name or address."""
    return _request_json("GET", "/decompile", params={"addr": target})


@mcp.tool
def function_xrefs(target: str) -> Dict[str, Any]:
    """Get cross-references for a function by name or address."""
    return _request_json("GET", "/xrefs", params={"addr": target})


def _build_http_app():
    # Build CORS middleware configuration; allow wildcard or comma-separated list
    if ALLOW_ORIGINS.strip() == "*":
        allow_origins = ["*"]
    else:
        allow_origins = [o.strip() for o in ALLOW_ORIGINS.split(",") if o.strip()]

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=[
                "mcp-protocol-version",
                "mcp-session-id",
                "Authorization",
                "Content-Type",
            ],
            expose_headers=["mcp-session-id"],
        )
    ]

    return mcp.http_app(path="/mcp", middleware=middleware, stateless_http=STATELESS_HTTP)


if __name__ == "__main__":
    app = _build_http_app()
    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)
