"""LLM agents for function-level and malware-level analysis.

Refactor note: migrated from manual langchain create_agent + repair_json +
hand-rolled SummarizationMiddleware + ToolBudgetMiddleware to deepagent.
- Structured output via Pydantic response_format replaces manual JSON
  parsing/retry (no more repair_json or _json_or_error_payload).
- create_deep_agent includes SummarizationMiddleware (auto context compaction),
  TodoListMiddleware (planning), and SubAgentMiddleware by default — the
  146-line _invoke_with_summarization_middleware and ToolBudgetMiddleware
  inner class are deleted.
- Both agents now receive AppConfig via DI instead of calling load_config()
  internally (consistent with GhidraClient; config.yaml loaded once).
- Dead code removed: FunctionAnalysisAgent.analyze() (singular).
- Both FunctionAnalysisAgent and MalwareAnalysisAgent now use create_deep_agent
  with response_format=<PydanticModel>. The old ChatOpenAI.with_structured_output
  + SystemMessage/HumanMessage path in FunctionAnalysisAgent is retired, so
  langchain_core.messages is no longer imported here. A shared HarnessProfile
  registration on BaseAgent strips deepagent's built-in tools/prompts for both
  agents, keeping their model-facing surface identical.
"""
import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from config_loader import AppConfig
from exceptions import LLMResponseError
from schemas import FunctionAnalysisResult, MalwareReport
from llm_factory import create_llm, validate_api_key
from langfuse_utils import (
    create_langfuse_callback_handler,
    build_invoke_config,
    is_phantom_debug_enabled,
    get_debug_logger,
    to_pretty_json,
)
from mcp_loader import load_mcp_tools

logger = logging.getLogger(__name__)


class BaseAgent:
    """Shared base: config DI, retry resolution, truncation, debug logging,
    deepagent HarnessProfile registration.

    Refactor note: consolidates _resolve_json_retry_attempts, _invoke_config,
    and _packet_log which were duplicated across both agents. The deepagent
    HarnessProfile registration (formerly on MalwareAnalysisAgent only) is
    lifted here so FunctionAnalysisAgent shares the same built-in tool/prompt
    stripping after its migration to create_deep_agent.
    """

    # Tracks profile keys already registered in this process so repeated
    # agent construction (e.g. across worker restarts in the same interpreter,
    # or one agent constructing after another) does not re-log additive-merge
    # notices. Shared across all BaseAgent subclasses so FAA and MAA don't
    # re-register each other's keys.
    _registered_profile_keys: set[str] = set()

    def __init__(self, config: AppConfig, agent_name: str):
        self.config = config
        self.agent_name = agent_name
        self.agent_config = getattr(config, agent_name)
        self._langfuse_callback = create_langfuse_callback_handler()
        self._json_retry_attempts = self._resolve_json_retry_attempts()
        self._packet_debug_enabled = is_phantom_debug_enabled()
        self._packet_logger = get_debug_logger() if self._packet_debug_enabled else None

    def _resolve_json_retry_attempts(self) -> int:
        max_retries = getattr(self.agent_config.llm, "max_retries", None)
        if isinstance(max_retries, int) and max_retries > 0:
            return max_retries
        return 3

    def _invoke_config(self, run_name: str) -> Optional[Dict[str, Any]]:
        return build_invoke_config(
            callback_handler=self._langfuse_callback,
            run_name=run_name,
            tags=[self.agent_name],
        )

    def _packet_log(self, phase: str, payload: Dict[str, Any]) -> None:
        if not self._packet_logger:
            return
        self._packet_logger.info("[%s] %s", phase, to_pretty_json(payload))

    def _truncate_code_for_context(self, code: str) -> str:
        max_input_tokens = getattr(self.agent_config.llm, "max_input_tokens", None)
        if not isinstance(max_input_tokens, int) or max_input_tokens <= 0:
            return code
        # Conservative approximation: keep a buffer for prompt + tool wrappers.
        max_char_limit = max(0, max_input_tokens - 10000)
        if max_char_limit > 0 and len(code) > max_char_limit:
            return code[:max_char_limit] + "\n... [Code truncated for AI analysis due to context limits] ..."
        return code

    def _retry_delay(self, attempt: int) -> float:
        # Simple bounded backoff to avoid hammering the provider.
        return float(min(2 * attempt, 10))

    def _register_analysis_profile(self) -> None:
        """Register a HarnessProfile that strips deepagent's built-in tools,
        TodoListMiddleware, and the auto-added general-purpose subagent —
        none of which are relevant to malware or function analysis.

        Shared by FunctionAnalysisAgent and MalwareAnalysisAgent. Idempotent
        across instances and subclasses via the class-level
        ``_registered_profile_keys`` set, so constructing FAA after MAA (or
        vice versa) does not re-register (and re-log) the same profile.

        Registered under both ``openai:<model_name>`` and the bare ``openai``
        provider key so the profile resolves whether
        ``_harness_profile_for_model`` tries the combined ``provider:identifier``
        lookup first or falls back to the provider-only lookup. ChatOpenAI
        reports ``ls_provider="openai"``.
        """
        from deepagents import (
            GeneralPurposeSubagentProfile,
            HarnessProfile,
            register_harness_profile,
        )

        model_name = self.agent_config.llm.model_name
        profile = HarnessProfile(
            # Refactor note: deepagents >=0.6 removed SystemPromptConfig. The
            # new create_deep_agent always appends BASE_AGENT_PROMPT to
            # ``system_prompt``. Setting base_system_prompt="" here makes
            # _apply_profile_prompt replace BASE_AGENT_PROMPT with an empty
            # string, so only our domain prompt reaches the model (equivalent
            # to the old SystemPromptConfig(base=None)).
            base_system_prompt="",
            excluded_tools=frozenset({
                "write_todos",
                "ls", "read_file", "write_file", "edit_file", "delete",
                "glob", "grep", "execute",
            }),
            excluded_middleware=frozenset(),
            general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
        )
        for key in (f"openai:{model_name}", "openai"):
            if key in BaseAgent._registered_profile_keys:
                continue
            register_harness_profile(key, profile)
            BaseAgent._registered_profile_keys.add(key)


class FunctionAnalysisAgent(BaseAgent):
    """Per-function structured analysis using create_deep_agent.

    Refactor note: migrated from ChatOpenAI.with_structured_output +
    SystemMessage/HumanMessage to deepagent's create_deep_agent, matching
    MalwareAnalysisAgent's pattern. The shared HarnessProfile registration
    on BaseAgent strips deepagent's built-in tools/prompts (FilesystemMiddleware,
    SubAgentMiddleware, TodoListMiddleware, BASE_AGENT_PROMPT) so the model
    only sees our function-analysis system prompt + the decompiled code as a
    user message + response_format=FunctionAnalysisResult. No tools are
    passed (function analysis is pure text-in / structured-out), so the agent
    terminates in a single model step.

    The agent graph is constructed once in __init__ and reused across batches
    and across concurrent per-function invocations (LangGraph compiled graphs
    are stateless across ainvoke calls with fresh message inputs). Per-function
    failures are captured as error payloads so the batch is never aborted.
    Structured output is guaranteed by response_format; only network /
    rate-limit failures trigger the per-function error path.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config, "FunctionAnalysisAgent")
        validate_api_key("FunctionAnalysisAgent", self.agent_config.llm.api_key)
        self._llm = create_llm("FunctionAnalysisAgent", self.agent_config)
        self._register_analysis_profile()
        self._agent = self._build_agent()

    def _build_agent(self) -> Any:
        """Build the deepagent graph once for reuse across all batches.

        Refactor note: lazy import so agents/ can be imported without
        deepagents installed (e.g. for config validation in isolation).
        tools=[] + subagents=[] + the registered profile's
        GeneralPurposeSubagentProfile(enabled=False) ensures no tools, no
        auto-added GP subagent, and no `task` tool reach the model — only
        the function-analysis system prompt and response_format do.
        """
        from deepagents import create_deep_agent

        return create_deep_agent(
            model=self._llm,
            tools=[],
            system_prompt=self.agent_config.system_prompt,
            response_format=FunctionAnalysisResult,
            subagents=[],
        )

    async def analyze_decompiled_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Concurrently analyze decompiled functions.

        Input: [{"name": str, "code": str}, ...]
        Output: [{"name": str, "analysis": dict}, ...]

        Per-function failures are captured as error payloads so the batch is
        never aborted. Structured output is guaranteed by response_format;
        only network / rate-limit failures trigger the per-function error path.
        """
        if not items:
            return []

        prepared: List[Tuple[str, str]] = []
        for item in items:
            name = item.get("name")
            if not name:
                continue
            code = self._truncate_code_for_context(str(item.get("code") or ""))
            prepared.append((str(name), code))

        if not prepared:
            return []

        async def _analyze_one(name: str, code: str) -> Dict[str, Any]:
            # Refactor note: deepagent uses dict-shaped messages, not
            # langchain_core.messages. Each ainvoke starts a fresh graph
            # state, so concurrent calls on self._agent are independent.
            messages = [{"role": "user", "content": code}]
            invoke_config: Dict[str, Any] = {"recursion_limit": 8}
            base_config = self._invoke_config(f"FunctionAnalysisAgent.{name}")
            if base_config:
                invoke_config.update(base_config)

            self._packet_log("function_agent.request", {"name": name, "code_len": len(code)})
            try:
                result = await self._agent.ainvoke(
                    {"messages": messages},
                    config=invoke_config,
                )
            except Exception as exc:
                logger.warning("FunctionAnalysisAgent LLM call failed for %s: %s", name, exc)
                return {
                    "error": str(exc),
                    "agent": self.agent_name,
                    "raw_response": "",
                }

            structured = result.get("structured_response")
            if isinstance(structured, FunctionAnalysisResult):
                return structured.model_dump()
            # Refactor note: defensive fallback for unexpected return types.
            if isinstance(structured, dict):
                return structured

            # Refactor note: fallback — extract last message content if
            # structured_response is missing (rare with response_format set).
            result_msgs = result.get("messages") or []
            last_content = ""
            if result_msgs:
                last_content = getattr(result_msgs[-1], "content", str(result_msgs[-1]))
            logger.warning(
                "FunctionAnalysisAgent no structured_response for %s",
                name,
            )
            return {
                "error": "No structured_response from agent.",
                "agent": self.agent_name,
                "raw_response": last_content,
            }

        analyses = await asyncio.gather(
            *[_analyze_one(name, code) for name, code in prepared]
        )

        return [
            {"name": name, "analysis": analysis}
            for (name, _), analysis in zip(prepared, analyses)
        ]


class MalwareAnalysisAgent(BaseAgent):
    """Final malware report agent using deepagent with MCP tools.

    Refactor note: create_deep_agent replaces the hand-rolled 146-line
    _invoke_with_summarization_middleware + ToolBudgetMiddleware inner class.
    Built-in SummarizationMiddleware handles context compaction; response_format
    handles structured output; recursion_limit bounds tool calls. The 125-line
    retry loop is simplified to error-only retries (no JSON parse retries).

    deepagent strips: create_deep_agent forces a bundled BASE_AGENT_PROMPT,
    TodoListMiddleware (write_todos), FilesystemMiddleware (ls/read_file/
    write_file/edit_file/delete/glob/grep/execute), and SubAgentMiddleware
    (task + auto general-purpose subagent) into every agent. FilesystemMiddleware
    and SubAgentMiddleware are hard-required scaffolding and cannot be excluded
    via excluded_middleware. We neutralize them via the shared HarnessProfile
    registered on BaseAgent (_register_analysis_profile) that hides their tools
    with excluded_tools, disables the auto GP subagent, and excludes
    TodoListMiddleware; BASE_AGENT_PROMPT is dropped by setting
    base_system_prompt="" on the HarnessProfile and passing our malware prompt
    as a plain str to create_deep_agent. The net result: only the MCP
    verification tools, the malware system prompt, and response_format=
    MalwareReport reach the model — matching FunctionAnalysisAgent's cleanliness.
    """

    def __init__(self, config: AppConfig):
        super().__init__(config, "MalwareAnalysisAgent")
        validate_api_key("MalwareAnalysisAgent", self.agent_config.llm.api_key)
        self._llm = create_llm("MalwareAnalysisAgent", self.agent_config)
        self._summary_llm = create_llm("MalwareAnalysisAgentSummary", self.agent_config)
        self.mcp_base_url = self._resolve_mcp_base_url()
        self._register_analysis_profile()

    def _resolve_mcp_base_url(self) -> Optional[str]:
        mcp_cfg = self.config.plugins.get("mcp") if isinstance(self.config.plugins, dict) else None
        base_url = getattr(mcp_cfg, "base_url", None)
        return str(base_url).rstrip("/") if base_url else None

    def _resolve_tool_budget(self) -> Tuple[bool, int, int]:
        """Resolve (enabled, max_tool_calls, max_agent_steps) from config."""
        budget_cfg = getattr(self.agent_config, "tool_budget", None)
        enabled = True
        max_tool_calls = 12
        max_agent_steps = 30

        if budget_cfg is not None:
            if isinstance(budget_cfg.enabled, bool):
                enabled = budget_cfg.enabled
            if isinstance(budget_cfg.max_tool_calls, int) and budget_cfg.max_tool_calls > 0:
                max_tool_calls = budget_cfg.max_tool_calls
            if isinstance(budget_cfg.max_agent_steps, int) and budget_cfg.max_agent_steps > 0:
                max_agent_steps = budget_cfg.max_agent_steps

        # Hard-cap graph recursion to indirectly bound tool calls.
        # In ReAct-style loops, one tool call generally consumes ~2 steps.
        derived_step_cap = max(4, max_tool_calls * 2 + 2)
        max_agent_steps = min(max_agent_steps, derived_step_cap)

        return enabled, max_tool_calls, max_agent_steps

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        """Generate the final malware report using MCP tools for verification."""
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results,
        }
        tool_enabled, max_tool_calls, max_agent_steps = self._resolve_tool_budget()

        tools: List[Any] = []
        if tool_enabled and self.mcp_base_url:
            tools = await load_mcp_tools(self.mcp_base_url)
            logger.info(
                "MalwareAnalysisAgent: tools=%d, max_tool_calls=%d, max_agent_steps=%d",
                len(tools), max_tool_calls, max_agent_steps,
            )

        # Refactor note: lazy import so agents/ can be imported without
        # deepagents installed (e.g., for config validation in isolation).
        # deepagents >=0.6 dropped SystemPromptConfig; system_prompt now
        # accepts a plain str. The BASE_AGENT_PROMPT is neutralized via
        # base_system_prompt="" on the registered HarnessProfile above, so
        # passing our malware prompt here yields only our domain prompt
        # (base_prompt becomes "" and is appended harmlessly).
        # subagents=[] + the registered profile's GeneralPurposeSubagentProfile
        # (enabled=False) ensures no auto-added GP subagent and no `task` tool.
        from deepagents import create_deep_agent

        agent = create_deep_agent(
            model=self._llm,
            tools=tools,
            system_prompt=self.agent_config.system_prompt,
            response_format=MalwareReport,
            subagents=[],
        )

        messages = [{"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)}]

        invoke_config: Dict[str, Any] = {"recursion_limit": max_agent_steps}
        base_config = self._invoke_config("MalwareAnalysisAgent.analyze")
        if base_config:
            invoke_config.update(base_config)

        last_content = ""
        for attempt in range(1, self._json_retry_attempts + 1):
            self._packet_log(
                "malware_agent.request",
                {
                    "attempt": attempt,
                    "max_attempts": self._json_retry_attempts,
                    "tool_count": len(tools),
                    "max_agent_steps": max_agent_steps,
                },
            )
            try:
                result = await agent.ainvoke({"messages": messages}, config=invoke_config)
            except Exception as exc:
                last_content = str(exc)
                logger.warning(
                    "MalwareAnalysisAgent call failed (attempt %d/%d): %s",
                    attempt, self._json_retry_attempts, exc,
                )
                await asyncio.sleep(self._retry_delay(attempt))
                continue

            structured = result.get("structured_response")
            if isinstance(structured, MalwareReport):
                self._packet_log("malware_agent.response", {"structured": structured.model_dump()})
                return structured.model_dump()

            # Refactor note: fallback — extract last message content if
            # structured_response is missing (rare with response_format set).
            result_msgs = result.get("messages") or []
            if result_msgs:
                last_content = getattr(result_msgs[-1], "content", str(result_msgs[-1]))
            logger.warning(
                "MalwareAnalysisAgent no structured_response (attempt %d/%d)",
                attempt, self._json_retry_attempts,
            )
            await asyncio.sleep(self._retry_delay(attempt))

        raise LLMResponseError(
            "Failed to get structured response from MalwareAnalysisAgent",
            raw_response=last_content,
        )
