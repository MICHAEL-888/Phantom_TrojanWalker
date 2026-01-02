import json
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain.agents import create_agent
from config_loader import load_config
from langchain.messages import AIMessage, SystemMessage, HumanMessage

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        agent_config = self.config.FunctionAnalysisAgent
        self.llm = ChatDeepSeek(
            model=agent_config.llm.model_name, 
            api_key=agent_config.llm.api_key, 
            max_retries=agent_config.llm.max_retries,
            temperature=agent_config.llm.temperature,
            model_kwargs={"response_format": {"type": "json_object"}}
            )

        # 使用简单的 ReAct 代理
        self.agent = create_agent(
            self.llm, 
            system_prompt=agent_config.system_prompt
            )

class MalwareAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        agent_config = self.config.MalwareAnalysisAgent
        self.llm = ChatDeepSeek(
            model=agent_config.llm.model_name, 
            api_key=agent_config.llm.api_key, 
            max_retries=agent_config.llm.max_retries,
            temperature=agent_config.llm.temperature,
            model_kwargs={"response_format": {"type": "json_object"}}
            )

        # 使用简单的 ReAct 代理
        self.agent = create_agent(
            self.llm, 
            system_prompt=agent_config.system_prompt
            )

