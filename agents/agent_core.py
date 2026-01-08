import json
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain.agents import create_agent
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import AIMessage, SystemMessage, HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        
        # 从配置中初始化 Rate Limiter
        rl_config = self.agent_config.rate_limit
        rate_limiter = None
        if rl_config:
            rate_limiter = InMemoryRateLimiter(
                requests_per_second=rl_config.requests_per_second,
                check_every_n_seconds=rl_config.check_every_n_seconds,
                max_bucket_size=rl_config.max_bucket_size,
            )

        self.llm = ChatOpenAI(
            name="FunctionAnalysisAgent",
            base_url=self.agent_config.llm.base_url,
            model=self.agent_config.llm.model_name, 
            api_key=self.agent_config.llm.api_key, 
            max_retries=self.agent_config.llm.max_retries,
            timeout=self.agent_config.llm.timeout,
            max_completion_tokens=self.agent_config.llm.max_completion_tokens,
            rate_limiter=rate_limiter,
            model_kwargs={"response_format": {"type": "json_object"}}
            )

    async def analyze(self, code: str) -> dict:
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{code}")
        ]
        response = await self.llm.ainvoke(messages)
        try:
            return json.loads(response.content)
        except Exception:
            raise LLMResponseError("Failed to parse JSON response from FunctionAnalysisAgent", raw_response=response.content)

class MalwareAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.MalwareAnalysisAgent

        # 从配置中初始化 Rate Limiter
        rl_config = self.agent_config.rate_limit
        rate_limiter = None
        if rl_config:
            rate_limiter = InMemoryRateLimiter(
                requests_per_second=rl_config.requests_per_second,
                check_every_n_seconds=rl_config.check_every_n_seconds,
                max_bucket_size=rl_config.max_bucket_size,
            )

        self.llm = ChatOpenAI(
            name="MalwareAnalysisAgent",
            base_url=self.agent_config.llm.base_url,
            model=self.agent_config.llm.model_name, 
            api_key=self.agent_config.llm.api_key, 
            max_retries=self.agent_config.llm.max_retries,
            timeout=self.agent_config.llm.timeout,
            max_completion_tokens=self.agent_config.llm.max_completion_tokens,
            rate_limiter=rate_limiter,
            model_kwargs={"response_format": {"type": "json_object"}}
            )

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results
        }
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{json.dumps(context, ensure_ascii=False, indent=2)}")
        ]
        response = await self.llm.ainvoke(messages)
        try:
            return json.loads(response.content)
        except Exception:
            raise LLMResponseError("Failed to parse JSON response from MalwareAnalysisAgent", raw_response=response.content)

