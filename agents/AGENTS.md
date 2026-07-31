# agents

## 职责与入口

此模块把 Ghidra 静态分析数据转成结构化的函数级判断和最终恶意软件报告。支持路径是：

`backend/worker` -> `backend/core/factory.create_coordinator()` -> `AnalysisCoordinator`

`agents/main.py` 是遗留实验 FastAPI 入口，不用于 Compose 或生产主链路。本模块不负责任务持久化、排队、去重和浏览器 API。

## 关键文件

| 文件 | 作用 |
| --- | --- |
| `analysis_coordinator.py` | Ghidra 调用顺序、函数筛选、初筛和最终报告编排 |
| `ghidra_client.py` | 基于 httpx 的 Ghidra HTTP 客户端、超时和传输重试 |
| `agent_core.py` | Function/Malware 两类 deepagents agent、重试、截断、MCP 工具加载 |
| `schemas.py` | `FunctionAnalysisResult` 和 `MalwareReport` 的 Pydantic 输出契约 |
| `config_loader.py` | YAML 配置、环境覆盖和 prompt 文件加载 |
| `config.yaml.example` | 端点、LLM 和工具预算的可提交模板 |
| `prompt/*.md` | 两类 agent 的领域提示词 |
| `mcp_loader.py` | 加载 Ghidra MCP 的只读工具 |

## 分析流水线

`AnalysisCoordinator.analyze_content(filename, content, content_type)` 依次执行：

1. Ghidra 健康检查（Pipe 重启期间按上限 120 秒的指数退避等待恢复）、上传、自动分析。
2. 拉取元数据、函数、导出表和字符串。
3. 选择 `FUN_*`、常见入口点和导出函数，获取其交叉引用和批量反编译结果。
4. 丢弃无调用者且非入口/非导出的候选函数，调用 `FunctionAnalysisAgent` 并发做结构化分析。
5. 仅把 `attack_matches` 非空的函数交给 `MalwareAnalysisAgent` 做最终报告。
6. 无 ATT&CK 初筛命中时，返回固定的安全报告，跳过最终 LLM 调用。
7. 无论成功或失败，都调用 Ghidra `/close` 释放当前程序。

协调器的返回值只包含 `metadata` 和 `malware_report`。函数、字符串、xrefs 和反编译结果仅用于当前请求，不会由 backend 持久化。

## Ghidra 与 MCP 契约

`GhidraClient` 从 `plugins.ghidra.endpoints` 解析路由。当前流水线依赖 `health_check`、`upload`、`analyze`、`metadata`、`functions`、`exports`、`strings`、`xrefs_batch`、`decompile_batch` 和 `close`；超时时还会使用 `stop_analysis`。

批量反编译可能缺少失败项，上游代码必须继续处理可用结果。Ghidra 端是全局单 analyzer，跨样本串行由 backend worker 保证，不能从此模块绕过该限制。

最终报告 agent 可从 `plugins.mcp.base_url` 加载 `decompile_function`、`function_xrefs` 工具。工具预算由 `MalwareAnalysisAgent.tool_budget` 控制。

新增或修改 Ghidra 能力时，必须同步：

1. `module/ghidra_pipe/analyzer.py` 和 `module/ghidra_pipe/main.py`
2. `config.yaml` 与 `config.yaml.example` 的 endpoint mapping
3. `ghidra_client.py`
4. `analysis_coordinator.py`，以及需要持久化时的 backend 和前端

## LLM 与配置约束

两类 agent 都用 `deepagents.create_deep_agent(..., response_format=<Pydantic schema>)` 获取结构化输出。函数级单项失败会返回 error payload 而不中断整批；最终报告的失败会使整个任务失败。

Prompt 和 `schemas.py` 是同一输出协议。增减字段时要同步更新二者，并核对 `ReportView.jsx` 的消费字段。分析结论必须由反编译代码、MCP 返回或提供的元数据支持，不要在 prompt 或代码中引入无证据推断。

`load_config()` 支持：

- `PTW_GHIDRA_BASE_URL` 和 `PTW_MCP_BASE_URL`
- `PTW_LLM_API_KEY`，供两个 agent 共用
- `PTW_FUNCTIONANALYSISAGENT_API_KEY`、`PTW_MALWAREANALYSISAGENT_API_KEY`
- `PTW_FUNCTIONANALYSISAGENT_MODEL`、`PTW_MALWAREANALYSISAGENT_MODEL`

真实密钥应经环境变量提供，不应写入或提交 `config.yaml`。`factory.py` 是主链路唯一的配置加载点。

## 验证

```bash
pytest tests/test_analysis_coordinator.py
```

现有测试覆盖“无候选函数”和“无 ATT&CK 命中”时跳过最终复核，以及有匹配时调用最终复核的分支。变更筛选、报告短路或清理逻辑时须同步扩展这些测试。
