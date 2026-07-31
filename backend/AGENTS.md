# backend

## 职责与边界

此模块是唯一的浏览器 API 和任务系统。它流式接收样本、计算 SHA-256、去重、将任务写入 SQLite，并通过单消费者 worker 调用 `agents`。

前端只调用 `/api/*`。本模块不直接执行 pyghidra、编写 LLM prompt 或调用 MCP 工具。

## 关键文件

| 文件 | 作用 |
| --- | --- |
| `main.py` | FastAPI 应用、CORS、生命周期、表和索引初始化、遗留列清理、worker 启停 |
| `api/endpoints.py` | 上传、任务查询、按 hash 查询和历史列表 |
| `models/task.py` | `AnalysisTask` SQLAlchemy 模型 |
| `worker/worker.py` | 内存队列、启动恢复、串行分析和状态回写 |
| `database.py` | SQLite 路径、遗留 DB 迁移、WAL/busy timeout、session |
| `core/factory.py` | 加载一次 agents 配置并构造协调器 |

## 数据与 API 契约

`AnalysisTask` 的外部标识是 `task_id` UUID；`id` 仅用于内部队列。任务状态只能为 `pending`、`processing`、`completed` 或 `failed`。

结果字段仅有：

- `metadata_info`，API 中映射为 `metadata`
- `malware_report`

不要新增或恢复 `functions`、`strings`、`decompiled_code`、`function_xrefs` 或 `function_analyses` 列。应用启动时会删除这些遗留列。

| 路由 | 行为 |
| --- | --- |
| `POST /api/analyze` | 接收 `file` 与可选 `sha256`；服务端重新计算 hash，验证后去重、落盘并排队 |
| `GET /api/tasks/{task_id}` | 返回状态、样本元信息、`metadata`、`malware_report`、错误和时间戳 |
| `GET /api/result/{sha256}` | 返回此 hash 最近一条任务；不含 `created_at` 和 `finished_at` |
| `GET /api/history?limit=10` | 返回最近任务摘要；`limit` 范围为 1 到 200 |

`POST /api/analyze` 只复用 `pending`、`processing`、`completed` 任务。失败样本可以重新提交。上传落在 `data/uploads/<sha256>`，默认大小上限为 200 MB，可由 `PTW_MAX_UPLOAD_BYTES` 覆盖。

## Worker 与并发

`AnalysisWorker` 使用内存 `asyncio.Queue`。启动时会把 `processing` 回退为 `pending`，再将所有未完成任务入队；因此该队列不是跨进程队列。

`_analysis_lock` 是正确性约束，不是可随意优化的限流：Ghidra Pipe 的 analyzer 是全局单实例。接受上传可以并发，实际分析必须串行。`run_analysis()` 读取存储的二进制，调用 `coordinator.analyze_content(task.sha256, content)`，并只保存其 `metadata` 和 `malware_report`。

## 配置与运行

- `BACKEND_HOST`，默认 `0.0.0.0`
- `BACKEND_PORT`，默认 `8001`
- `BACKEND_RELOAD`，直接执行 `python backend/main.py` 时默认启用
- `PTW_CORS_ORIGINS`，逗号分隔的 CORS 来源；默认含 `5173`、`3000`、`8080`
- `PTW_GHIDRA_BASE_URL`，由 agents 配置加载器使用，覆盖 Ghidra 服务地址

```bash
python backend/main.py
uvicorn backend.main:app --host 0.0.0.0 --port 8001
pytest
```

## 修改检查清单

- 新 API：在 `api/endpoints.py` 添加路由，并保持前端通过 `/api` 访问。
- 新持久化字段：同步模型、worker 回写、任务查询响应和前端消费者；需要提供 SQLite 迁移路径。
- 新协调器依赖：由 `core/factory.py` 统一装配，避免在路由中重复加载配置或构造 LLM client。
- 调整任务并发前，先把 Ghidra Pipe 重构为每任务独立会话或容器池，并同步修改 API 与 worker。
