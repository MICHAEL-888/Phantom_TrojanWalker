# Phantom TrojanWalker：AI 编码助手工作指南

## 架构与数据流（先读这些文件）
- Rizin 引擎服务（:8000）：[module/rz_pipe/main.py](../module/rz_pipe/main.py) 暴露 `/upload`、`/analyze`、`/functions`、`/strings`、`/callgraph`、`/decompile_batch`。
- 后端任务服务（:8001）：[backend/main.py](../backend/main.py) + [backend/api/endpoints.py](../backend/api/endpoints.py)；任务持久化在 [backend/models/task.py](../backend/models/task.py)（SQLite）。
- AI 编排：Coordinator 在 [agents/analysis_coordinator.py](../agents/analysis_coordinator.py)，通过 [agents/rizin_client.py](../agents/rizin_client.py) 调 Rizin HTTP；再并发调用 LLM（见 [agents/agent_core.py](../agents/agent_core.py)）。

## 本地/容器启动（优先 docker-compose）
- 一键：`docker compose up --build`（见 [docker-compose.yml](../docker-compose.yml)）
  - `ph_rzpipe`：`127.0.0.1:8000`
  - `ph_backend`：`127.0.0.1:8001`（API 前缀 `/api`）
  - `ph_frontend`：`127.0.0.1:8080`（通过 `VITE_API_BASE=/api` 走后端）
- 纯本地（开发调试）：`python module/rz_pipe/main.py` + `python backend/main.py`；前端 `cd frontend && npm run dev`。

## 关键约定（写代码时按这个来）
- Rizin 交互只通过 `RizinAnalyzer`/`rzpipe`：优先 `cmdj` 拿结构化数据（`aflj`/`izj`/`ij`/`agC json`）；反编译用 `pdgj @ <addr_or_name>`（见 [module/rz_pipe/analyzer.py](../module/rz_pipe/analyzer.py)）。
- Rizin HTTP 路由名从 `agents/config.yaml` 的 `plugins.rizin.endpoints` 读取；新增接口时同步更新配置（`RizinClient._request()` 会按 key 组 URL）。
- LLM 必须返回 JSON：`agents/agent_core.py` 为两个 Agent 都设置了 `model_kwargs={"response_format": {"type": "json_object"}}`，解析失败会抛 `LLMResponseError`。
- Prompt 来源：`agents/config.yaml` 可配置 `system_prompt_path`，由 [agents/config_loader.py](../agents/config_loader.py) 在启动时读入；修改 prompt 后需要重启后端/worker 让配置重新加载。

## 任务系统行为（影响你怎么改后端）
- 去重：`/api/analyze` 按文件内容 `sha256` 查重（pending/processing/completed 直接复用任务）。
- 队列：worker 在 [backend/worker/worker.py](../backend/worker/worker.py) 中用 `asyncio.Queue`；并用 `_analysis_lock` 强制“同一时间只跑一个二进制分析”。
- 结果落库：analysis 的 `metadata/functions/strings/decompiled_code/function_analyses/malware_report` 分列写入 `AnalysisTask`。

## AI 分析细节（避免误判为 bug）
- Function 级分析默认只跑 `fcn.*` 自动命名函数（见 [agents/analysis_coordinator.py](../agents/analysis_coordinator.py)）。
- 反编译代码会按 `max_input_tokens` 做截断（保留余量），并用 `max_concurrency` + Semaphore 控并发。

