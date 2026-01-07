# Phantom TrojanWalker - AI Malware Analysis Framework

This project is an AI-powered malware analysis framework that combines LangChain (DeepSeek) with Rizin (`rz-pipe`) for deep binary inspection.

## 🏗 Architecture Overview
- **Rizin Backend**: [module/rz_pipe/main.py](module/rz_pipe/main.py) (FastAPI, port 8000) wraps `RizinAnalyzer` ([module/rz_pipe/analyzer.py](module/rz_pipe/analyzer.py)) to provide structured binary data (metadata, functions, strings, decompilation).
- **Orchestration Service**: [agents/main.py](agents/main.py) (FastAPI, port 8001) manages the full analysis pipeline, coordinating between the Rizin backend and AI agents.
- **AI Agent Core**: [agents/agent_core.py](agents/agent_core.py) uses `langchain-deepseek` to implement `FunctionAnalysisAgent` (per-function code audit) and `MalwareAnalysisAgent` (final report generation).
- **Configuration**: Managed by [agents/config_loader.py](agents/config_loader.py) using Pydantic, loading from [agents/config.yaml](agents/config.yaml).

## 🔄 Data Flow
1. **Target Binary** is uploaded to Port 8001 ([agents/main.py](agents/main.py)).
2. **Orchestration Service** uploads to Backend (Port 8000) and triggers `aaa` analysis.
3. **Data Retrieval**: Metadata, functions, callgraphs, and decompiled code are fetched via REST API from the Backend.
4. **AI Analysis**: 
    - `FunctionAnalysisAgent` audits each `fcn.*` function using rules in [agents/prompt/FunctionAnalysisAgent.md](agents/prompt/FunctionAnalysisAgent.md).
    - `MalwareAnalysisAgent` synthesizes all findings into a final JSON report based on [agents/prompt/MalwareAnalysisAgent.md](agents/prompt/MalwareAnalysisAgent.md).

## 🛠 Critical Workflows
- **Start Rizin Backend**: `python module/rz_pipe/main.py`
- **Start Orchestration Service**: `python agents/main.py`
- **Testing**: Use `python agents/main.py` and send a POST request with a file to `http://localhost:8001/analyze`.
- **System Prompts**: Update expert knowledge by editing Markdown files in [agents/prompt/](agents/prompt/).

## 📏 Project Conventions
- **Malware Analysis Logic**: Strictly follow detection criteria (Injection, Persistence, C2, Shellcode) defined in [FunctionAnalysisAgent.md](agents/prompt/FunctionAnalysisAgent.md#L45).
- **Service Interaction**: Services communicate via HTTP using endpoints defined in [agents/config.yaml](agents/config.yaml).
- **Binary Analysis**: Always use `RizinAnalyzer` ([module/rz_pipe/analyzer.py](module/rz_pipe/analyzer.py)) for interacting with `rzpipe`. Prefer `cmdj` for JSON results.
- **Async Execution**: Both services are built on FastAPI/Asyncio. Use `httpx.AsyncClient` for cross-service requests.

## 🔌 Integration Points
- **Rizin**: Requires `rizin` and `rz-ghidra` (for `pdgj` command) installed on the system.
- **LLM**: Primary engine is `deepseek-chat` via `langchain-deepseek`.
- **API Response**: AI agents must return valid JSON (configured via `response_format: {"type": "json_object"}`).
