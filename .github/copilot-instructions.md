# Phantom TrojanWalker：Copilot/AI Coding 指南

## 大图（先理解边界）
- Rizin 引擎服务（:8000）：[module/rz_pipe/main.py](../module/rz_pipe/main.py) 维护“当前打开的二进制”全局状态；提供 `/upload`→`/analyze`→`/metadata`/`/functions`/`/strings`/`/callgraph`/`/decompile_batch`。
- 后端任务服务（:8001，API 前缀 `/api`）：[backend/api/endpoints.py](../backend/api/endpoints.py) 负责上传/去重/落库；worker 在 [backend/worker/worker.py](../backend/worker/worker.py) 异步出队执行分析；任务模型在 [backend/models/task.py](../backend/models/task.py)（SQLite）。
- AI 编排：Coordinator 在 [agents/analysis_coordinator.py](../agents/analysis_coordinator.py)，通过 [agents/rizin_client.py](../agents/rizin_client.py) 调 Rizin HTTP，再调用 LLM Agents（[agents/agent_core.py](../agents/agent_core.py)）。
- 前端：开发态 Vite 代理见 [frontend/vite.config.js](../frontend/vite.config.js)；容器/生产用 [frontend/server.mjs](../frontend/server.mjs) 代理 `/api/* -> PTW_BACKEND_BASE_URL`。

## 常用启动方式
- Docker（推荐）：`docker compose up --build`（见 [docker-compose.yml](../docker-compose.yml)）。
- 纯本地三进程：`python module/rz_pipe/main.py`（8000）+ `python backend/main.py`（8001）+ `cd frontend && npm run dev`（5173）。

## 项目约定（改代码要对齐）
- Rizin 交互只走 `RizinAnalyzer`：优先 `cmdj()` 获取结构化输出（`aflj`/`izj`/`ij`/`agC json`），反编译使用 `pdgj @ <addr_or_name>`（见 [module/rz_pipe/analyzer.py](../module/rz_pipe/analyzer.py)）。
- Rizin HTTP 路由来自 `agents/config.yaml` 的 `plugins.rizin.endpoints`；新增/改接口要同步更新配置。批量反编译为 `POST /decompile_batch`，body 是 JSON 数组（[agents/rizin_client.py](../agents/rizin_client.py)）。
- LLM 必须返回 JSON：两类 agent 都用 `response_format: json_object`，解析失败会抛 `LLMResponseError`（[agents/agent_core.py](../agents/agent_core.py)）。
- Prompt 从 `system_prompt_path` 加载（[agents/config_loader.py](../agents/config_loader.py)）；修改 prompt 后需要重启后端/worker 才会重新加载。

## 任务系统与并发（容易踩坑）
- 去重：`POST /api/analyze` 按文件内容 `sha256` 查重（pending/processing/completed 直接复用任务）。
- 单并发分析：worker 用 `_analysis_lock` 强制同一时刻只跑一个分析（因为 rzpipe 服务侧也是“单 analyzer 全局状态”）。
- 结果落库是“分列”：`metadata_info/functions/strings/decompiled_code/function_analyses/malware_report` 写入 `AnalysisTask`，不要改成一个大 blob（见 [backend/worker/worker.py](../backend/worker/worker.py)）。

## AI 分析策略（别当成 bug）
- 函数级分析只跑 `fcn.*` 自动命名函数 + 常见入口点（main/WinMain/DllMain 等），并发由 `max_concurrency` 控制；反编译过长会按 `max_input_tokens` 做截断（[agents/analysis_coordinator.py](../agents/analysis_coordinator.py)）。
- 最终报告只喂 “ATT&CK 有匹配（attack_matches 非空）” 的重点函数，减少噪音（同上）。

## 配置注意
- `agents/config.yaml` 应对齐 [agents/config.yaml.example](../agents/config.yaml.example)：代码目前按 `plugins.rizin` 取配置（[backend/core/factory.py](../backend/core/factory.py)）。
- 不要在日志/PR/issue 中泄露 `api_key`；优先用示例配置并在本地注入密钥。

