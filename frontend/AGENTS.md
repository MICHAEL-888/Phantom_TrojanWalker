# frontend

## 职责与边界

此模块是 React/Vite 单页应用，提供样本上传、任务状态查看、历史记录和最终报告展示。所有请求都经相对路径 `/api` 到 backend；不得从浏览器直接访问 Ghidra Pipe、MCP 或 agents。

页面路由：

- `/`：`src/pages/Home.jsx`，选择或拖放样本、浏览器端 SHA-256 预查和上传。
- `/task/:taskId`：`src/pages/TaskDetail.jsx`，查询并每 30 秒轮询任务状态。
- `/history`：`src/pages/History.jsx`，历史列表与 SHA-256 查询。

## 关键文件

| 文件 | 作用 |
| --- | --- |
| `src/App.jsx` | 路由、固定导航和滚动行为 |
| `src/lib/api.js` | Axios API client；`API_BASE` 必须保持为 `/api` |
| `src/lib/utils.js` | SHA-256、上传表单和展示数据辅助函数 |
| `src/pages/Home.jsx` | 样本选择、预查去重、上传和跳转 |
| `src/pages/TaskDetail.jsx` | AbortController 管理的轮询和任务状态展示 |
| `src/pages/History.jsx` | 最近任务和 hash 搜索 |
| `src/components/ReportView.jsx` | metadata 与 `MalwareReport` 字段的渲染 |
| `vite.config.js` | 开发和 preview 时将 `/api` 代理到 `http://localhost:8001` |
| `server.mjs` | 容器生产静态服务和同源 `/api/*` 反向代理 |

## API 数据流

Home 使用 Web Crypto 计算 SHA-256，然后请求 `GET /api/result/{sha256}`。命中非 `failed` 任务时直接进入对应任务页；未命中或失败任务才上传。

上传调用 `POST /api/analyze`，`FormData` 包含 `file` 和可选 `sha256`。后端会重新计算并验证 hash，因此不要把浏览器 hash 当成可信数据。

TaskDetail 请求 `GET /api/tasks/{task_id}`：`pending` 与 `processing` 继续轮询，`completed` 传给 `ReportView`，`failed` 显示 `error`。History 调用 `GET /api/history?limit=50`，hash 搜索使用 `GET /api/result/{sha256}`。

任务响应只包含 `metadata` 和 `malware_report` 两个分析结果字段。不要添加对函数、字符串、反编译内容或 `include_heavy` 的客户端依赖，它们不属于当前 backend API。

## 报告契约

`ReportView` 消费：

- `metadata.bin` 和 `metadata.core`
- `malware_report.threat_type`、`risk_level`、`malware_name`、`attack_chain`、`reason`
- `malware_report.key_ttps`、`malicious_functions`、`extracted_iocs`

报告字段源自 `agents/schemas.py` 与 prompt。变更报告显示时先同步它们，并确认安全短路报告的默认字段仍可正常显示。

## 运行与部署

```bash
npm --prefix frontend run dev
npm --prefix frontend run build
npm --prefix frontend run preview
```

开发和 `vite preview` 使用 Vite proxy。生产镜像先运行 Vite build，再由 `server.mjs` 提供 `dist`；后端地址仅由服务端的 `PTW_BACKEND_BASE_URL` 使用，默认 `http://host.docker.internal:8001`。Compose 会将其设为 `http://ph_backend:8001`。

`public/runtime-config.js` 当前不是运行中的 API 配置来源。不要基于它实现请求逻辑，保持 `/api` 同源模式。

## 修改规则

- API 变更先更新 backend，再集中更新 `src/lib/api.js` 和各页面调用点。
- 保留任务页的取消逻辑：卸载或切换任务时应中止未完成请求并清理 interval。
- 浏览器 SHA-256 会将整个文件读入内存；后端的 200 MB 限制仍是权威限制。需要支持更大文件时应评估浏览器内存体验和后端配置。
- 新增任务状态时同步后端常量、TaskDetail、History 的图标和 badge 映射。
