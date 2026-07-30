"""MCP tool loading for the MalwareAnalysisAgent.

Refactor note: extracted from agent_core to isolate MCP client lifecycle from
agent orchestration. Tools are loaded from the ghidra_mcp service and passed
to create_deep_agent.
"""
import logging
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


async def load_mcp_tools(mcp_base_url: Optional[str]) -> List[Any]:
    """Load MCP tools from the configured ghidra_mcp service URL.

    Returns an empty list if no URL is configured or if loading fails (the
    agent can still operate without tools, producing a report from the initial
    function analyses alone).
    """
    if not mcp_base_url:
        return []

    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient(
        {
            "ghidra": {
                "transport": "http",
                "url": mcp_base_url,
            }
        }
    )
    try:
        tools = await client.get_tools()
        logger.info("Loaded %d MCP tools from %s", len(tools), mcp_base_url)
        return tools
    except Exception as exc:
        logger.warning("MCP get_tools failed: %s", exc)
        return []
