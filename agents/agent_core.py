import json
import logging
import asyncio
from typing import Any, Dict, List, Optional, Tuple

from langchain_openai import ChatOpenAI
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import SystemMessage, HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger(__name__)

# Keep retries controlled by agent-level loops only.
# This prevents N (agent) * M (SDK) retry multiplication.
SDK_MAX_RETRIES = 0


def _log_exception_group(prefix: str, exc: Exception) -> None:
    logger.exception("%s: %s", prefix, exc)
    group_type = getattr(__import__("builtins"), "BaseExceptionGroup", None)
    if group_type and isinstance(exc, group_type):
        for idx, sub_exc in enumerate(exc.exceptions):
            logger.error("%s sub[%d]: %r", prefix, idx, sub_exc)


def _response_to_text(resp: Any) -> str:
    content = getattr(resp, "content", None)
    return str(content) if content is not None else str(resp)


def _json_or_error_payload(agent_name: str, content: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
        # LLM should return JSON object; normalize non-dict JSON into an error payload.
        return {
            "error": "LLM JSON is not an object.",
            "agent": agent_name,
            "raw_response": content,
        }
    except Exception:
        return {
            "error": "Failed to parse AI JSON response.",
            "agent": agent_name,
            "raw_response": content,
        }


def _validate_api_key(agent_label: str, api_key: Optional[str]) -> None:
    """Validate LLM API key presence.

    Refactor note: isolate validation for reuse across agents.
    """
    if not api_key or api_key.strip() in {"", "YOUR_API_KEY_HERE"}:
        raise ValueError(
            f"Missing LLM API key in agents/config.yaml ({agent_label}.llm.api_key)"
        )


def _build_rate_limiter(rate_limit_cfg: Optional[Any]) -> Optional[InMemoryRateLimiter]:
    """Create a rate limiter if config is provided.

    Refactor note: reduces repeated construction logic.
    """
    if not rate_limit_cfg:
        return None
    return InMemoryRateLimiter(
        requests_per_second=rate_limit_cfg.requests_per_second,
        check_every_n_seconds=rate_limit_cfg.check_every_n_seconds,
        max_bucket_size=rate_limit_cfg.max_bucket_size,
    )


def _build_llm_params(
    agent_name: str,
    agent_cfg: Any,
    rate_limiter: Optional[InMemoryRateLimiter],
    include_response_format: bool = True,
) -> Dict[str, Any]:
    """Build LLM init params while filtering None values.

    Refactor note: centralizes default handling for consistency.
    """
    model_kwargs: Dict[str, Any] = {}
    if include_response_format:
        model_kwargs["response_format"] = {"type": "json_object"}
    if agent_cfg.llm.extra_body:
        model_kwargs["extra_body"] = agent_cfg.llm.extra_body

    params = {
        "name": agent_name,
        "base_url": agent_cfg.llm.base_url,
        "model": agent_cfg.llm.model_name,
        "api_key": agent_cfg.llm.api_key,
        # Disable SDK/internal retries; outer retry loop remains the single source of truth.
        "max_retries": SDK_MAX_RETRIES,
        "timeout": agent_cfg.llm.timeout,
        "max_completion_tokens": agent_cfg.llm.max_completion_tokens,
        "rate_limiter": rate_limiter,
        "model_kwargs": model_kwargs or None,
    }
    # 过滤掉为 None 的参数，确保空值时使用 LangChain 或 Provider 的默认值
    return {k: v for k, v in params.items() if v is not None}


def _create_llm(agent_name: str, agent_cfg: Any) -> ChatOpenAI:
    """Create a ChatOpenAI client with shared initialization logic."""
    _validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = _build_rate_limiter(agent_cfg.rate_limit)
    llm_params = _build_llm_params(agent_name, agent_cfg, rate_limiter, include_response_format=True)
    return ChatOpenAI(**llm_params)


def _create_summary_llm(agent_name: str, agent_cfg: Any) -> ChatOpenAI:
    """Create a lightweight ChatOpenAI client for summarization."""
    _validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = _build_rate_limiter(agent_cfg.rate_limit)
    llm_params = _build_llm_params(agent_name, agent_cfg, rate_limiter, include_response_format=False)
    return ChatOpenAI(**llm_params)

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        self.llm = _create_llm("FunctionAnalysisAgent", self.agent_config)
        # Retry attempts for JSON parse failures (fallback if not configured)
        self._json_retry_attempts = self._resolve_json_retry_attempts()

    def _resolve_json_retry_attempts(self) -> int:
        # Prefer configured max_retries; ensure at least 1 attempt.
        max_retries = getattr(self.agent_config.llm, "max_retries", None)
        if isinstance(max_retries, int) and max_retries > 0:
            return max_retries
        return 3

    def _truncate_code_for_context(self, code: str) -> str:
        max_input_tokens = getattr(self.agent_config.llm, "max_input_tokens", None)
        if not isinstance(max_input_tokens, int) or max_input_tokens <= 0:
            return code
        # Conservative approximation: keep a buffer for prompt + tool wrappers.
        max_char_limit = max(0, max_input_tokens - 10000)
        if max_char_limit > 0 and len(code) > max_char_limit:
            return code[:max_char_limit] + "\n... [Code truncated for AI analysis due to context limits] ..."
        return code

    async def analyze(self, code: str) -> dict:
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{code}")
        ]
        last_content = ""
        for attempt in range(1, self._json_retry_attempts + 1):
            try:
                response = await self.llm.ainvoke(messages)
            except Exception as exc:
                last_content = str(exc)
                logger.warning(
                    "FunctionAnalysisAgent LLM call failed (attempt %d/%d): %s",
                    attempt,
                    self._json_retry_attempts,
                    exc,
                )
                continue
            content = _response_to_text(response)
            last_content = content
            parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
            if "error" not in parsed:
                return parsed
            logger.warning(
                "FunctionAnalysisAgent JSON parse failed (attempt %d/%d)",
                attempt,
                self._json_retry_attempts,
            )
        raise LLMResponseError(
            "Failed to parse JSON response from FunctionAnalysisAgent",
            raw_response=last_content,
        )

    async def analyze_decompiled_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch analyze decompiled functions.

        Input: [{"name": str, "code": str}, ...]
        Output: [{"name": str, "analysis": dict}, ...]

                Notes:
                - Sequentially invokes the LLM per function.
                - JSON parse failures are captured per function to avoid aborting the batch.
        """
        if not items:
            return []

        prepared_names: List[str] = []
        prepared_codes: List[str] = []
        for item in items:
            name = item.get("name")
            if not name:
                continue
            code = item.get("code") or ""
            code = self._truncate_code_for_context(str(code))
            prepared_names.append(str(name))
            prepared_codes.append(code)

        if not prepared_names:
            return []

        async def _analyze_one(name: str, code: str) -> Dict[str, Any]:
            messages = [
                SystemMessage(content=self.agent_config.system_prompt),
                HumanMessage(content=str(code)),
            ]
            last_content = ""
            for attempt in range(1, self._json_retry_attempts + 1):
                try:
                    response = await self.llm.ainvoke(messages)
                except Exception as exc:
                    last_content = str(exc)
                    logger.warning(
                        "FunctionAnalysisAgent LLM call failed for %s (attempt %d/%d): %s",
                        name,
                        attempt,
                        self._json_retry_attempts,
                        exc,
                    )
                    continue
                content = _response_to_text(response)
                last_content = content
                parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
                if "error" not in parsed:
                    return parsed
                logger.warning(
                    "FunctionAnalysisAgent JSON parse failed for %s (attempt %d/%d)",
                    name,
                    attempt,
                    self._json_retry_attempts,
                )
            return {
                "error": "Failed to parse JSON response from FunctionAnalysisAgent",
                "agent": "FunctionAnalysisAgent",
                "raw_response": last_content,
            }

        analyses = await asyncio.gather(
            *[_analyze_one(name, code) for name, code in zip(prepared_names, prepared_codes)]
        )

        return [
            {"name": name, "analysis": analysis}
            for name, analysis in zip(prepared_names, analyses)
        ]

class MalwareAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.MalwareAnalysisAgent
        self.llm = _create_llm("MalwareAnalysisAgent", self.agent_config)
        self.summary_llm = _create_summary_llm("MalwareAnalysisAgentSummary", self.agent_config)
        self.mcp_base_url = self._resolve_mcp_base_url()
        self._json_retry_attempts = self._resolve_json_retry_attempts()

    def _resolve_json_retry_attempts(self) -> int:
        # Prefer configured max_retries; ensure at least 1 attempt.
        max_retries = getattr(self.agent_config.llm, "max_retries", None)
        if isinstance(max_retries, int) and max_retries > 0:
            return max_retries
        return 3

    def _retry_delay(self, attempt: int) -> float:
        # Simple bounded backoff to avoid hammering the provider.
        return float(min(2 * attempt, 10))

    def _resolve_mcp_base_url(self) -> Optional[str]:
        plugins = getattr(self.config, "plugins", {})
        mcp_cfg = plugins.get("mcp") if isinstance(plugins, dict) else None
        base_url = getattr(mcp_cfg, "base_url", None)
        return str(base_url).rstrip("/") if base_url else None

    def _resolve_tool_budget(self) -> Tuple[bool, int, int, int]:
        """Resolve MCP tool-calling budget from config.

        Returns:
            (enabled, max_tool_calls, max_agent_steps, max_tool_result_chars)
        """
        budget_cfg = getattr(self.agent_config, "tool_budget", None)
        enabled = True
        max_tool_calls = 12
        max_agent_steps = 30
        max_tool_result_chars = 120000

        if budget_cfg is not None:
            enabled_cfg = getattr(budget_cfg, "enabled", None)
            calls_cfg = getattr(budget_cfg, "max_tool_calls", None)
            steps_cfg = getattr(budget_cfg, "max_agent_steps", None)
            chars_cfg = getattr(budget_cfg, "max_tool_result_chars", None)

            if isinstance(enabled_cfg, bool):
                enabled = enabled_cfg
            if isinstance(calls_cfg, int) and calls_cfg > 0:
                max_tool_calls = calls_cfg
            if isinstance(steps_cfg, int) and steps_cfg > 0:
                max_agent_steps = steps_cfg
            if isinstance(chars_cfg, int) and chars_cfg > 0:
                max_tool_result_chars = chars_cfg

        # Hard-cap graph recursion to indirectly bound tool calls.
        # In ReAct-style loops, one tool call generally consumes ~2 steps (model + tool).
        derived_step_cap = max(4, max_tool_calls * 2 + 2)
        max_agent_steps = min(max_agent_steps, derived_step_cap)

        return enabled, max_tool_calls, max_agent_steps, max_tool_result_chars

    def _content_char_len(self, content: Any) -> int:
        if content is None:
            return 0
        if isinstance(content, str):
            return len(content)
        if isinstance(content, (int, float, bool)):
            return len(str(content))
        if isinstance(content, list):
            total = 0
            for item in content:
                if isinstance(item, dict):
                    total += self._content_char_len(item.get("text") or item.get("content") or item)
                else:
                    total += self._content_char_len(item)
            return total
        if isinstance(content, dict):
            return len(json.dumps(content, ensure_ascii=False))
        return len(str(content))

    async def _load_mcp_tools(self) -> List[Any]:
        if not self.mcp_base_url:
            return []

        client = MultiServerMCPClient(
            {
                "ghidra": {
                    "transport": "http",
                    "url": self.mcp_base_url,
                }
            }
        )
        try:
            tools = await client.get_tools()
        except Exception as exc:
            _log_exception_group("MCP get_tools failed", exc)
            return []
        return tools

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results,
        }
        tool_enabled, max_tool_calls, max_agent_steps, max_tool_result_chars = self._resolve_tool_budget()
        tools: List[Any] = []
        if tool_enabled and self.mcp_base_url:
            tools = await self._load_mcp_tools()
            logger.info(
                "MCP tool-calling mode enabled: tools=%d, max_tool_calls=%d, max_agent_steps=%d, max_tool_result_chars=%d",
                len(tools),
                max_tool_calls,
                max_agent_steps,
                max_tool_result_chars,
            )

        messages = [
            {
                "role": "system",
                "content": (
                    f"{self.agent_config.system_prompt}\n\n"
                    f"工具调用预算约束（必须遵守）：最多调用 {max_tool_calls} 次工具；"
                    f"工具返回累计总长度上限为 {max_tool_result_chars} 字符；"
                    "达到任一预算后必须停止继续调用工具，并基于现有证据完成最终 JSON 报告。"
                ),
            },
            {"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)},
        ]

        last_content = ""
        for attempt in range(1, self._json_retry_attempts + 1):
            try:
                content = await self._invoke_with_summarization_middleware(
                    messages,
                    tools=tools,
                    max_tool_calls=max_tool_calls,
                    max_agent_steps=max_agent_steps,
                    max_tool_result_chars=max_tool_result_chars,
                )
            except Exception as exc:
                last_content = str(exc)
                logger.warning(
                    "MalwareAnalysisAgent LLM call failed (attempt %d/%d): %s",
                    attempt,
                    self._json_retry_attempts,
                    exc,
                )
            else:
                last_content = content
                parsed = _json_or_error_payload("MalwareAnalysisAgent", content)
                if "error" not in parsed:
                    return parsed
                logger.warning(
                    "MalwareAnalysisAgent JSON parse failed (attempt %d/%d)",
                    attempt,
                    self._json_retry_attempts,
                )

            if attempt < self._json_retry_attempts:
                await asyncio.sleep(self._retry_delay(attempt))

        return {
            "error": "Failed to parse JSON response from MalwareAnalysisAgent",
            "agent": "MalwareAnalysisAgent",
            "raw_response": last_content,
        }

    async def _invoke_with_summarization_middleware(
        self,
        messages: List[Dict[str, str]],
        tools: List[Any],
        max_tool_calls: int,
        max_agent_steps: int,
        max_tool_result_chars: int,
    ) -> str:
        from langchain.agents import create_agent
        from langchain.agents.middleware import SummarizationMiddleware, AgentMiddleware

        class ToolBudgetMiddleware(AgentMiddleware):
            def __init__(
                self,
                outer: "MalwareAnalysisAgent",
                max_calls: int,
                max_chars: int,
            ):
                self._outer = outer
                self._max_calls = max_calls
                self._max_chars = max_chars

            def _extract_usage(self, messages: List[Any]) -> Tuple[int, int]:
                call_count = 0
                total_chars = 0
                for msg in messages or []:
                    msg_type = getattr(msg, "type", None) or getattr(msg, "role", None)
                    if msg_type != "tool":
                        continue
                    call_count += 1
                    total_chars += self._outer._content_char_len(getattr(msg, "content", None))
                return call_count, total_chars

            def wrap_model_call(self, request: Any, handler: Any) -> Any:
                call_count, total_chars = self._extract_usage(getattr(request, "messages", []))
                budget_exceeded = call_count >= self._max_calls or total_chars >= self._max_chars
                if budget_exceeded:
                    logger.info(
                        "MCP tool budget reached, disabling further tool calls: calls=%d/%d chars=%d/%d",
                        call_count,
                        self._max_calls,
                        total_chars,
                        self._max_chars,
                    )
                    return handler(request.override(tools=[]))
                return handler(request)

        max_input_tokens = getattr(self.agent_config.llm, "max_input_tokens", None)
        trigger_tokens = 100000
        if isinstance(max_input_tokens, int) and max_input_tokens > 0:
            trigger_tokens = int(max_input_tokens * 0.9)

        middleware = SummarizationMiddleware(
            model=self.summary_llm,
            trigger=("tokens", trigger_tokens),
            keep=("messages", 10),
            summary_prompt="你是一位拥有深厚逆向工程背景的**资深恶意软件分析师**，以下是你之前的分析结果，由于上下文长度限制，需要对其进行总结以便继续分析：",
        )
        budget_middleware = ToolBudgetMiddleware(
            outer=self,
            max_calls=max_tool_calls,
            max_chars=max_tool_result_chars,
        )
        agent = create_agent(
            model=self.llm,
            tools=tools,
            middleware=[budget_middleware, middleware],
        )
        if hasattr(agent, "ainvoke"):
            result = await agent.ainvoke(
                {"messages": messages},
                config={"recursion_limit": max_agent_steps},
            )
        else:
            result = agent.invoke(
                {"messages": messages},
                config={"recursion_limit": max_agent_steps},
            )

        if isinstance(result, dict) and "output" in result:
            return _response_to_text(result["output"])
        if isinstance(result, dict) and "messages" in result and result["messages"]:
            return _response_to_text(result["messages"][-1])
        return _response_to_text(result)
