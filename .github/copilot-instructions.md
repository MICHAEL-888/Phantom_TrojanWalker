# Phantom TrojanWalker - AI Malware Analysis Framework

This project is an AI-powered malware analysis framework that combines LangChain (DeepSeek) with Rizin (`rz-pipe`) for deep binary inspection.

## 🏗 Architecture Overview
- **Agent Core**: `agents/agent_core.py` manages the AI agent logic using LangChain and DeepSeek. It is designed to be a ReAct agent that uses tools to interact with the binary analysis backend.
- **Binary Analysis Backend**: `module/rz_pipe/` contains a FastAPI service (`main.py`) that wraps `RizinAnalyzer` (`analyzer.py`). It provides structured JSON data from `rizin` (e.g., functions, strings, decompilation).
- **Configuration**: `agents/config.yaml` and `agents/config_loader.py` (using Pydantic) manage LLM settings, plugin endpoints, and prompt paths.
- **Prompts**: System prompts are stored in `agents/prompt/` (e.g., `FunctionAnalysisAgent.txt`). These prompts contain the "expert knowledge" for malware detection.

## 🔄 Data Flow
1. **Target Binary** is uploaded to the Rizin Backend (`/upload`).
2. **Rizin Backend** performs static analysis (`aaa`) and exposes results via REST API.
3. **AI Agent** (in `agents/agent_core.py`) fetches binary metadata, strings, and decompiled code via HTTP requests to the backend.
4. **AI Agent** processes the data based on the expert rules in `agents/prompt/` and generates a JSON analysis report.

## 🛠 Critical Workflows
- **Start Rizin Backend**: Run `python module/rz_pipe/main.py` (starts on port 8000 by default).
- **Run Analysis**: Run `python agents/main.py` to execute the agent against a target.
- **Configuration**: Update `config.yaml` to change LLM models, API keys, or plugin endpoints.

## 📏 Project Conventions
- **Malware Analysis Principles**: Follow the strict guidelines in [prompt/FunctionAnalysisAgent.txt](prompt/FunctionAnalysisAgent.txt). Focus on evidence-based detection (Process Injection, Persistence, C2) and avoid false positives (complex code, entropy).
- **Configuration**: Always use `agents/config_loader.py` and Pydantic models for accessing settings. Do not hardcode API keys or URLs.
- **Binary Analysis**: Use the `RizinAnalyzer` class in [module/rz_pipe/analyzer.py](module/rz_pipe/analyzer.py) for interacting with `rzpipe`. Prefer JSON-returning commands (`cmdj`).
- **API Design**: The Rizin backend uses FastAPI. New analysis capabilities should be added as endpoints in [module/rz_pipe/main.py](module/rz_pipe/main.py).

## 🔌 Integration Points
- **LLM**: Uses `langchain-deepseek` for the primary analysis engine.
- **Rizin**: Requires `rizin` and `rz-ghidra` plugin for decompilation (`pdcj` command).
- **Communication**: The agent interacts with the Rizin backend via HTTP requests defined in the `plugins` section of `config.yaml`.
