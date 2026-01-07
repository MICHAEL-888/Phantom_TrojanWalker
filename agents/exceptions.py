class TrojanWalkerError(Exception):
    """项目基类异常"""
    pass

class RizinBackendError(TrojanWalkerError):
    """远程 Rizin 后端服务不可达或通信失败"""
    pass

class RizinAnalysisError(RizinBackendError):
    """后端执行命令 (如 aaa) 逻辑失败"""
    pass

class AgentError(TrojanWalkerError):
    """AI Agent 相关的基类异常"""
    pass

class LLMResponseError(AgentError):
    """LLM 返回内容无法解析或格式不符合预期 (JSON 错误)"""
    def __init__(self, message, raw_response=None):
        super().__init__(message)
        self.raw_response = raw_response

class ConfigurationError(TrojanWalkerError):
    """配置加载失败或配置项缺失"""
    pass
