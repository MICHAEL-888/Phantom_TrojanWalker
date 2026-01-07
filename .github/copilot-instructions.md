# Phantom TrojanWalker - AI 恶意软件分析框架指南

Phantom TrojanWalker 是一个结合了 LangChain (DeepSeek) 与 Rizin (`rz-pipe`) 的自动化恶意软件分析框架。

## 🏗 核心架构
- **Rizin 后端** ([module/rz_pipe/main.py](module/rz_pipe/main.py)): 基于 FastAPI (Port 8000) 封装 `RizinAnalyzer` ([module/rz_pipe/analyzer.py](module/rz_pipe/analyzer.py))，通过 `rzpipe` 提供二进制分析能力。
- **业务中控** ([agents/main.py](agents/main.py)): 基于 FastAPI (Port 8001) 的编排层，管理分析流水线。
- **AI 智能体层**: 
    - `FunctionAnalysisAgent`: 针对单个函数代码进行审计。
    - `MalwareAnalysisAgent`: 综合所有发现生成最终报告。
- **配置管理**: 使用 Pydantic 模型在 [agents/config_loader.py](agents/config_loader.py) 中定义，从 [agents/config.yaml](agents/config.yaml) 加载。

## 🔄 开发工作流
- **启动后端**: `python module/rz_pipe/main.py` (需安装 `rizin` 和 `rz-ghidra`)
- **启动中控**: `python agents/main.py` (需配置 API Key)
- **分析测试**: 使用 POST 请求上传二进制文件至 `http://localhost:8001/analyze`
- **提示词迭代**: 直接修改 [agents/prompt/](agents/prompt/) 下的 Markdown 文件，中控会自动加载最新内容。

## 📏 项目开发规范
- **Rizin 交互**: 
    - 绝不直接运行 shell 命令，始终使用 `RizinAnalyzer` 实例。
    - 优先使用 `cmdj` 获取 JSON 格式结果（如 `aflj`, `ij`, `pdgj`）。
    - 反编译必须使用 `pdgj @ <addr>` 以支持 Ghidra 插件。
- **AI 交互**:
    - AI Agent 必须配置 `response_format: {"type": "json_object"}` 确保输出为 JSON。
    - 返回结果需经过 `json.loads` 校验，格式错误时抛出 `LLMResponseError`。
- **异步处理**: 
    - 采用 FastAPI 异步架构，IO 操作（HTTP 请求、LLM 调用）必须使用 `async/await`。
    - 跨服务通信使用 `httpx.AsyncClient`。
- **异常处理**:
    - 使用 [agents/exceptions.py](agents/exceptions.py) 中定义的自定义异常（如 `RizinBackendError`, `AgentError`）。

## 🔌 核心集成点
- **二进制指令**: `aaa` (深度分析), `aflj` (函数列表), `izj` (字符串), `pdgj` (反编译代码), `agC json` (调用图)。
- **LLM 引擎**: 兼容 OpenAI 格式的 API（默认为 DeepSeek-Reasoner）。

