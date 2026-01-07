# Phantom TrojanWalker - AI 恶意软件分析框架指南

Phantom TrojanWalker 是一个高度模块化的二进制分析平台，结合了 Rizin (`rz-pipe`) 的底层分析能力、LangChain 的 AI 网络编排以及 FastAPI/React 的现代全栈架构。

## 🏗 全栈架构
- **Rizin 模块** ([module/rz_pipe/](module/rz_pipe/)): 二进制分析引擎，封装 `rzpipe` 和 `Ghidra` 插件。
- **AI 智能体层** ([agents/](agents/)): 核心逻辑层，包含 `FunctionAnalysisAgent` (代码审计) 和 `MalwareAnalysisAgent` (综合评估)。
- **持久化后端** ([backend/](backend/)): v2.0 任务引擎，提供 SQLite 存储和异步分析队列（Worker 模式）。
- **前端页面** ([frontend/](frontend/)): React + Tailwind + Lucide 组件库构建的分析看板。

## 🔄 核心开发流水线
1. **启动 Rizin 引擎**: `python module/rz_pipe/main.py` (默认端口 8000)。
2. **启动分析后台**: `python backend/main.py` (默认端口 8001)。
3. **启动前端**: `cd frontend; npm run dev` (Vite 默认端口 5173)。
4. **添加新能力**: 在 `RizinAnalyzer` ([module/rz_pipe/analyzer.py](module/rz_pipe/analyzer.py)) 中新增底层方法 -> 在 `agents/agent_core.py` 中封装为 Tool -> 在 `agents/analysis_coordinator.py` 中编排。

## 📏 二进制与 AI 开发规范
- **Rizin 交互**:
    - **禁止执行原生 Shell**: 必须通过 `RizinAnalyzer` 实例调用 `cmd` 或 `cmdj`。
    - **优先 JSON**: 使用 `cmdj` 获取结构化数据（如 `aflj`, `izj`, `ij`）。
    - **反编译标准**: 调用 `pdgj @ <addr>` 必须确保 `rz-ghidra` 插件已加载。
- **AI Agent 开发**:
    - **强制 JSON 响应**: 模型必须配置 `response_format: {"type": "json_object"}`。
    - **Prompts**: 位于 [agents/prompt/](agents/prompt/)，修改后无需重启，后台会自动重载 Markdown 内容。
- **数据流与异步**:
    - **后端通信**: 使用 `httpx.AsyncClient` 进行跨服务调用。
    - **任务持久化**: 始终通过 `backend/models/task.py` 中的 `AnalysisTask` 模型记录状态，不要在内存中存储大批量任务。

## 🔌 技术栈集成
- **Binary**: `rzpipe`, `rz-ghidra`.
- **LLM**: `langchain-deepseek` (DeepSeek-Reasoner).
- **Backend**: FastAPI, SQLAlchemy (SQLite), aiofiles.
- **Frontend**: Vite, React, TailwindCSS, Axios.

## ⚠️ 异常等级
- `RizinBackendError`: 引擎层错误（如文件加载失败、插件缺失）。
- `LLMResponseError`: 模型幻觉或格式错误。
- `TrojanWalkerError`: 业务逻辑异常，统一在 `agents/exceptions.py` 定义。

