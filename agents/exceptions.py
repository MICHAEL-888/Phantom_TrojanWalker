class TrojanWalkerError(Exception):
    """项目基类异常"""
    pass

class GhidraBackendError(TrojanWalkerError):
    """远程 Ghidra 后端服务不可达或通信失败"""
    pass


class GhidraConnectionError(GhidraBackendError):
    """远程 Ghidra 后端在请求完成前断开连接"""
    pass


class GhidraTimeoutError(GhidraBackendError):
    """远程 Ghidra 后端请求超时"""

    def __init__(self, message: str, endpoint: str | None = None):
        super().__init__(message)
        self.endpoint = endpoint

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
