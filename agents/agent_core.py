import json
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain.agents import create_agent
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import AIMessage, SystemMessage, HumanMessage

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        self.llm = ChatDeepSeek(
            model=self.agent_config.llm.model_name, 
            api_key=self.agent_config.llm.api_key, 
            max_retries=self.agent_config.llm.max_retries,
            temperature=self.agent_config.llm.temperature,
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
        self.llm = ChatDeepSeek(
            model=self.agent_config.llm.model_name, 
            api_key=self.agent_config.llm.api_key, 
            max_retries=self.agent_config.llm.max_retries,
            temperature=self.agent_config.llm.temperature,
            model_kwargs={"response_format": {"type": "json_object"}}
            )

    async def analyze(self, analysis_results: list, metadata: dict, callgraph: dict) -> dict:
        context = {
            "metadata": metadata,
            "callgraph": callgraph,
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

