"""ChatOpenAI construction helpers.

Refactor note: extracted from agent_core to centralize LLM client creation and
shared validation. Both agents now receive AppConfig via dependency injection
instead of calling load_config() internally, so config.yaml is loaded once.
"""
import logging
from typing import Any, Dict, Optional

from langchain_openai import ChatOpenAI
from langchain_core.rate_limiters import InMemoryRateLimiter

from config_loader import AppConfig
from exceptions import ConfigurationError

logger = logging.getLogger(__name__)

# Refactor note: keep SDK retries at 0 so agent-level retry loops remain the
# single source of truth and avoid N (agent) * M (SDK) retry multiplication.
SDK_MAX_RETRIES = 0


class AutoToolChoiceChatOpenAI(ChatOpenAI):
    """Keep thinking models compatible with LangChain structured tools."""

    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: Any = None,
        strict: Optional[bool] = None,
        parallel_tool_calls: Optional[bool] = None,
        response_format: Any = None,
        **kwargs: Any,
    ) -> Any:
        return super().bind_tools(
            tools,
            tool_choice="auto",
            strict=strict,
            parallel_tool_calls=parallel_tool_calls,
            response_format=response_format,
            **kwargs,
        )


def validate_api_key(agent_label: str, api_key: Optional[str]) -> None:
    """Validate LLM API key presence.

    Refactor note: isolate validation for reuse across agents.
    """
    if not api_key or api_key.strip() in {"", "YOUR_API_KEY_HERE"}:
        raise ConfigurationError(
            f"Missing LLM API key in agents/config.yaml ({agent_label}.llm.api_key)"
        )


def build_rate_limiter(rate_limit_cfg: Optional[Any]) -> Optional[InMemoryRateLimiter]:
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


def build_llm_params(
    agent_name: str,
    agent_cfg: Any,
    rate_limiter: Optional[InMemoryRateLimiter],
) -> Dict[str, Any]:
    """Build LLM init params while filtering None values.

    Refactor note: centralizes default handling for consistency. Structured
    output is now applied via deepagent response_format (create_deep_agent),
    so response_format is no longer set on ChatOpenAI directly.
    """
    model_kwargs: Dict[str, Any] = {}
    if agent_cfg.llm.extra_body:
        model_kwargs["extra_body"] = agent_cfg.llm.extra_body

    streaming = getattr(agent_cfg.llm, "streaming", None)
    streaming_enabled = streaming if isinstance(streaming, bool) else True

    params = {
        "name": agent_name,
        "base_url": agent_cfg.llm.base_url,
        "model": agent_cfg.llm.model_name,
        "api_key": agent_cfg.llm.api_key,
        "max_retries": SDK_MAX_RETRIES,
        "timeout": agent_cfg.llm.timeout,
        "streaming": streaming_enabled,
        "max_completion_tokens": agent_cfg.llm.max_completion_tokens,
        "rate_limiter": rate_limiter,
        "model_kwargs": model_kwargs or None,
    }
    return {k: v for k, v in params.items() if v is not None}


def create_llm(
    agent_name: str,
    agent_cfg: Any,
    *,
    force_tool_choice_auto: bool = False,
) -> ChatOpenAI:
    """Create a ChatOpenAI client with shared initialization logic."""
    validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = build_rate_limiter(agent_cfg.rate_limit)
    llm_params = build_llm_params(agent_name, agent_cfg, rate_limiter)
    llm_class = AutoToolChoiceChatOpenAI if force_tool_choice_auto else ChatOpenAI
    return llm_class(**llm_params)
