import json
from agent_core import FunctionAnalysisAgent
from langchain.messages import HumanMessage
from langchain_core.messages import BaseMessage

if __name__ == "__main__":
    bot = FunctionAnalysisAgent()
    content_text = """现在正在运行测试，请按照要求假装输出一份报告"""
    user_message = HumanMessage(content=content_text)
    response = bot.agent.invoke(user_message)
    

    print("--- 分析报告 ---")
    # 打印整个对话流
    for m in response.get("messages", []):
        if isinstance(m, BaseMessage):
            m.pretty_print()
  
