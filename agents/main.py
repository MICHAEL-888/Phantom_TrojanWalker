import json
from agent_core import FunctionAnalysisAgent
from langchain.messages import HumanMessage

if __name__ == "__main__":
    bot = FunctionAnalysisAgent()
    content_text = """test"""
    user_message = HumanMessage(content=content_text)
    response = bot.agent.invoke(user_message)
    
    # 获取并解析内容
    content_text = response.get('output', '') if isinstance(response, dict) else getattr(response, 'content', str(response))
    if isinstance(response, dict) and response.get('messages'):
        content_text = getattr(response['messages'][-1], 'content', str(response['messages'][-1]))

    print("--- 分析报告 ---")
    try:
        print(json.dumps(json.loads(content_text), indent=4, ensure_ascii=False))
    except:
        print(content_text)
