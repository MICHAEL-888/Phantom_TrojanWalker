# module

## 服务边界

`module/` 包含两个协作服务：

- `ghidra_pipe/`：基于 pyghidra 的 FastAPI 静态分析服务，默认端口 `8000`。
- `ghidra_mcp/`：将 Pipe 的单函数反编译和交叉引用包装为 FastMCP HTTP 工具，默认端口 `9000`，路径 `/mcp`。

它们不负责样本去重、任务持久化、队列或 LLM 判断。浏览器不能直接调用这两个服务。

## 关键约束

`ghidra_pipe/main.py` 维护一个全局 `analyzer` 和 `threading.RLock`。`POST /upload` 会关闭旧 analyzer 并打开新样本，其他分析路由都依赖该当前状态。这只保证单进程的请求互斥，不提供多样本会话隔离。

因此系统只能同时分析一个样本。该约束由 `backend/worker/worker.py` 的 `_analysis_lock` 维护，不能通过在客户端增加并发请求来规避。

分析结束时 agents 会调用 `POST /close`。Compose 设置 `GHIDRA_RESTART_AFTER_CLOSE=1`，Pipe 会在释放资源后退出，以便容器以全新 JVM 重启；修改该行为前须评估内存释放、健康检查和 worker 重试。

## Ghidra Pipe

| 位置 | 作用 |
| --- | --- |
| `ghidra_pipe/main.py` | FastAPI 路由、上传、analyzer 生命周期、内存诊断和强制终止 |
| `ghidra_pipe/analyzer.py` | `GhidraAnalyzer`、pyghidra 生命周期和高层分析方法 |
| `_jvm.py` | JVM/Java 类初始化与缓存 |
| `addressing.py` | 函数名和地址解析 |
| `decompile.py` | 单函数与批量反编译 |
| `xrefs.py` | callers/callees 查询和批量查询 |
| `callgraph.py` | 以函数入口地址为标识构建调用图 |
| `pe_metadata.py` | PE 专用元数据 |
| `formatting.py` | 显示格式化辅助函数 |

当前 HTTP 路由：

| 路由 | 行为 |
| --- | --- |
| `GET /health_check` | 服务健康状态 |
| `GET /memory` | 进程、cgroup 和 JVM 内存快照 |
| `POST /upload` | 流式保存样本并打开 analyzer |
| `GET /analyze` | 执行 Ghidra `analyzeAll` |
| `POST /stop_analysis` | 计划强制终止 Pipe 进程，用于超时恢复 |
| `POST /close` | 关闭 analyzer；按环境变量决定是否重启进程 |
| `GET /metadata`、`/functions`、`/exports`、`/strings`、`/callgraph` | 返回静态分析数据 |
| `GET /decompile?addr=...` | 反编译单个函数 |
| `POST /decompile_batch` | 反编译 JSON 字符串数组 |
| `GET /xrefs?addr=...`、`POST /xrefs_batch` | 单个或批量 callers/callees |

上传文件保存在 `data/uploads/<sha256>`，不得通过客户端文件名生成路径。未上传样本时需要 analyzer 的接口返回 `409`。批量反编译会跳过失败条目，调用方必须接受缺项。

## MCP 服务

`ghidra_mcp/main.py` 通过 `GHIDRA_PIPE_BASE_URL` 访问 Pipe，使用 FastMCP 在 `/mcp` 暴露：

- `decompile_function(target)`
- `function_xrefs(target)`

相关环境变量：`GHIDRA_MCP_HOST`、`GHIDRA_MCP_PORT`、`GHIDRA_MCP_TIMEOUT`、`GHIDRA_MCP_ALLOW_ORIGINS`、`FASTMCP_STATELESS_HTTP`。工具只读当前 analyzer，必须在上传和分析之后使用。

## 本地运行与变更

本地运行前需可用的 Ghidra 安装和 `GHIDRA_INSTALL_DIR`。依赖清单在 `requirements-ghidra.txt`。

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python module/ghidra_pipe/main.py
python module/ghidra_mcp/main.py
```

新增 Pipe API 时，在 `GhidraAnalyzer` 实现业务逻辑、在 `main.py` 加路由、更新 `agents/config.yaml` 和客户端方法，并为异常、无 analyzer、批量缺项等响应语义添加测试。需要多样本并发时，应设计带 session ID 的隔离 API 或多容器池，而不是共享全局 analyzer。
