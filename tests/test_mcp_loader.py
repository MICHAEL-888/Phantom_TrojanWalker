import sys
import types
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_load_mcp_tools_sets_timeout_for_streamable_http(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, connections):
            captured["connections"] = connections

        async def get_tools(self):
            return ["decompile_function", "function_xrefs"]

    fake_client_module = types.ModuleType("langchain_mcp_adapters.client")
    fake_client_module.MultiServerMCPClient = FakeClient
    monkeypatch.setitem(sys.modules, "langchain_mcp_adapters", types.ModuleType("langchain_mcp_adapters"))
    monkeypatch.setitem(sys.modules, "langchain_mcp_adapters.client", fake_client_module)

    agents_path = str(Path(__file__).resolve().parents[1] / "agents")
    if agents_path not in sys.path:
        sys.path.insert(0, agents_path)
    from mcp_loader import load_mcp_tools

    tools = await load_mcp_tools("http://mcp:9000/mcp")

    assert tools == ["decompile_function", "function_xrefs"]
    assert captured["connections"] == {
        "ghidra": {
            "transport": "http",
            "url": "http://mcp:9000/mcp",
            "timeout": 90.0,
            "sse_read_timeout": 300.0,
        },
    }
