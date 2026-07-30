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

    Returns an empty list if no URL is configured. Loading failures propagate
    so the caller can apply its retry policy instead of silently dropping the
    forensic tools.
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
    tools = await client.get_tools()
    logger.info("Loaded %d MCP tools from %s", len(tools), mcp_base_url)
    return tools
