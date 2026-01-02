import yaml
import os
from pydantic import BaseModel, Field
from typing import Dict, Optional

class LLMConfig(BaseModel):
    model_name: str
    temperature: float
    api_key: str
    base_url: Optional[str] = None
    max_retries: Optional[int] = None

class PluginConfig(BaseModel):
    base_url: str
    endpoints: Dict[str, str]

class AgentConfig(BaseModel):
    system_prompt: str = ""
    system_prompt_path: Optional[str] = None
    llm: LLMConfig

class AppConfig(BaseModel):
    plugins: Dict[str, PluginConfig]
    FunctionAnalysisAgent: AgentConfig
    MalwareAnalysisAgent: AgentConfig

def load_config(config_path: str = None) -> AppConfig:
    if config_path is None:
        # 默认查找与当前文件同目录下的 config.yaml
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
        
    with open(config_path, "r", encoding="utf-8") as f:
        config = AppConfig(**yaml.safe_load(f))
    
    # 加载各个 Agent 的系统提示词
    for agent_name in ["FunctionAnalysisAgent", "MalwareAnalysisAgent"]:
        agent_config = getattr(config, agent_name)
        if agent_config.system_prompt_path:
            prompt_path = agent_config.system_prompt_path
            # 如果是相对路径，则相对于配置文件所在目录
            if not os.path.isabs(prompt_path):
                prompt_path = os.path.join(os.path.dirname(config_path), prompt_path)
            
            if os.path.exists(prompt_path):
                with open(prompt_path, "r", encoding="utf-8") as f:
                    agent_config.system_prompt = f.read()
                
    return config

if __name__ == "__main__":
    config = load_config()
    print(config.model_dump())
