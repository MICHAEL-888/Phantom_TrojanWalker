# Phantom TrojanWalker

## 项目概览

Phantom TrojanWalker 是面向恶意样本的静态分析系统。浏览器上传样本后，FastAPI 后端持久化任务并串行驱动 Ghidra 和 LLM 分析，React 前端轮询结果并展示报告。

运行链路：`frontend` -> `/api` -> `backend/worker` -> `agents` -> `ghidra_pipe`；最终报告的 LLM 可通过 `ghidra_mcp` 进行只读验证。

## 目录地图

| 位置 | 职责 |
| --- | --- |
| `backend/` | 对外 API、SQLite 任务表、上传去重和单消费者 worker |
| `agents/` | Ghidra HTTP 客户端、分析编排、LLM agents、prompt 和配置 |
| `module/ghidra_pipe/` | pyghidra/FastAPI 静态分析服务 |
| `module/ghidra_mcp/` | 暴露反编译与交叉引用的 FastMCP 服务 |
| `frontend/` | React/Vite 用户界面和生产反向代理 |
| `docker/` | 三个服务的镜像定义和 Ghidra 进程包装脚本 |
| `tests/` | 协调器的异步单元测试 |
| `data/` | 运行时 SQLite、WAL 文件与按 SHA-256 命名的上传样本 |

各模块下的 `AGENTS.md` 记录更具体的边界与契约。

## 当前架构约束

- Ghidra Pipe 只有一个进程级 `analyzer`。`backend/worker/worker.py` 的 `asyncio.Lock` 必须保留，分析样本不能并发执行。
- 前端始终请求相对路径 `/api`。开发环境由 Vite 代理，生产环境由 `frontend/server.mjs` 代理；浏览器不得直接调用 Ghidra、MCP 或 agents。
- `AnalysisTask` 只持久化 `metadata_info` 和 `malware_report` 两个结果 JSON 字段。函数、字符串、交叉引用和反编译内容仅用于本次协调器流水线，不能假设它们可由 API 查询。
- 协调器在函数初筛没有 ATT&CK 匹配时直接返回 `risk_level: safe` 的报告，并跳过最终恶意软件 LLM 复核。
- Ghidra 路由改动必须同步 `module/ghidra_pipe/main.py`、`agents/config.yaml`、`agents/ghidra_client.py`，并在需要时更新协调器。
- Prompt、`agents/schemas.py` 和 `frontend/src/components/ReportView.jsx` 共同定义报告契约，修改其中一处时要检查另外两处。

## 运行与验证

```bash
# 完整栈，默认入口
docker compose up --build

# Python 测试
pytest

# 前端生产构建
npm --prefix frontend run build

# 本地开发，需要四个进程
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python module/ghidra_pipe/main.py
python module/ghidra_mcp/main.py
python backend/main.py
npm --prefix frontend run dev
```

默认端口：Ghidra Pipe `8000`、MCP `9000`、后端 `8001`、Vite `5173`、容器前端 `8080`。Compose 将端口绑定到 `127.0.0.1`。

## 开发规则

- 样本和分析结果属于敏感运行时数据；不得提交 `data/`、真实 API 密钥或分析样本。
- 上传接口采用流式写入、服务端 SHA-256 校验和内容去重。不要以用户文件名创建文件路径，亦不要绕过大小限制。
- 任务状态为 `pending`、`processing`、`completed` 或 `failed`。worker 在启动时会将未完成任务重新排队。
- 优先修改实际链路中的支持入口 `backend/main.py`。`agents/main.py` 是遗留实验入口，不属于 Compose 主路径。
- CI 只构建三份 Docker 镜像，不会运行 pytest；涉及 Python 行为时需在本地运行测试。
