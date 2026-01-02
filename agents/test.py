import json
import asyncio
from agent_core import FunctionAnalysisAgent
from langchain.messages import HumanMessage
from langchain_core.messages import BaseMessage

async def main():
    bot = FunctionAnalysisAgent()
    content_text = """void test() { int a = 1; }"""
    response = await bot.analyze(content_text)
    print("--- 分析报告 ---")
    print(json.dumps(response, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())
  
