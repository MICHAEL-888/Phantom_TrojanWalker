# Phantom TrojanWalker 公开 API 文档

面向 `https://phantom.num123.top` 部署的自动化调用文档。前端 `server.mjs` 将同源 `/api/*` 反代到 backend，因此所有接口的完整地址均为 `https://phantom.num123.top/api/...`。无认证，`Content-Type: application/json`（上传除外）。

任务状态枚举：`pending`（排队）、`processing`（分析中）、`completed`、`failed`。系统一次只串行分析一个样本，提交后须轮询。

## 接口总览

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/analyze` | 上传样本（multipart），去重后创建并排队任务 |
| GET | `/api/tasks/{task_id}` | 按任务 UUID 查状态与完整结果 |
| GET | `/api/result/{sha256}` | 按样本 hash 查最近一次结果 |
| GET | `/api/history?limit=N` | 最近任务摘要列表（`limit` 1~200，缺省 10） |

## POST /api/analyze

表单字段：`file`（必填，样本文件）、`sha256`（可选，64 位十六进制，服务端会校验与实际值一致）。

- 服务端重启计算 hash 并落盘 `data/uploads/<sha256>`；默认大小上限 200 MB（`PTW_MAX_UPLOAD_BYTES` 可调）。
- 去重：已存在 `pending`/`processing`/`completed` 的相同 hash 任务时返回已有任务；**`failed` 任务可重新提交**。

**成功 200（新任务）**

```json
{
  "task_id": "2f8b1f0e-...-uuid",
  "status": "pending",
  "message": "Analysis queued.",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

去重命中时 `message` 为 `"Analysis already <status>."`，`status` 为已有任务状态。

**错误**：400 无效 sha256 格式 / hash 不匹配；413 文件过大；500 存储失败。错误体均为 `{"detail": "<描述>"}`。

## GET /api/tasks/{task_id}

**响应 200**

```json
{
  "task_id": "2f8b1f0e-...-uuid",
  "status": "completed",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "filename": "sample.exe",
  "metadata": { ... },
  "malware_report": { ... },
  "error": null,
  "created_at": "2026-08-12T10:00:00",
  "finished_at": "2026-08-12T10:02:13"
}
```

- `metadata` 与 `malware_report` 在分析完成前为 `null`；`error` 为失败原因文本，否则 `null`。
- 404：任务不存在（`{"detail": "Task not found"}`）。

## GET /api/result/{sha256}

与 tasks 接口同结构，返回该 hash 最近一次任务，但**不含 `created_at`/`finished_at`**。404：无分析记录（`{"detail": "Analysis not found"}`）。

## GET /api/history?limit=N

**响应 200**：摘要数组，不含 `metadata`/`malware_report`。`limit` 超出 1~200 或非整数返回 422。

```json
[
  {
    "task_id": "2f8b1f0e-...-uuid",
    "status": "completed",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "filename": "sample.exe",
    "created_at": "2026-08-12T10:00:00",
    "finished_at": "2026-08-12T10:02:13",
    "error": null
  }
]
```

## 结果数据结构

**`metadata`**（Ghidra 生成）：

```json
{
  "core": { "file": "sample.exe", "format": "PE32", "mode": "32", "type": "executable", "size": 148480, "humansz": "145K" },
  "bin": { "arch": "x86", "bits": 32, "machine": "x86", "os": "Windows", "endian": "little", "compiler": "default", "subsys": "GUI", "signed": false, "compiled": "2026-01-05T03:00:00+00:00" }
}
```

`subsys`/`signed`/`compiled` 仅 PE 有值；格式相关字段未知时为 `"unknown"`。

**`malware_report`**（结构化报告）：

```json
{
  "threat_type": "trojan",
  "risk_level": "high",
  "malware_name": "N/A",
  "attack_chain": "攻击链描述",
  "reason": "结论依据",
  "malicious_functions": [
    { "name": "FUN_00401030", "reason": "...", "severity": "high", "mapped_techniques": ["T1055"] }
  ],
  "key_ttps": [
    { "technique_id": "T1055", "technique_name": "Process Injection", "tactics": ["Defense Evasion"], "evidence_refs": [{ "function_name": "FUN_00401030", "evidence": "..." }] }
  ],
  "extracted_iocs": {
    "domains": [], "ips": [], "urls": [], "file_paths": [], "registry_keys": [], "mutexes": [], "process_names": [], "service_names": []
  }
}
```

- `threat_type` 无威胁时固定 `"clean"`；`risk_level` 取值 `safe`/`low`/`medium`/`high`/`critical`，无 ATT&CK 命中时固定 `"safe"`；`malware_name` 未识别为 `"N/A"`。

## 自动化调用流程

1. （可选）预查：`GET /api/result/{sha256}`，命中非 `failed` 任务则复用结果。
2. 上传：`POST /api/analyze`（multipart），取 `task_id`。
3. 轮询 `GET /api/tasks/{task_id}`（建议 5~30 秒间隔），至 `completed` 取 `metadata` + `malware_report`，`failed` 读 `error` 后可重新提交。