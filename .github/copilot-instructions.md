# Phantom TrojanWalker - AI Malware Analysis Framework

This project is an AI-powered malware analysis framework that combines LangChain (DeepSeek) with Rizin (`rz-pipe`) for deep binary inspection.

## 🏗 Architecture Overview
- **Agent Core**: `agents/agent_core.py` manages the AI agent logic using LangChain and DeepSeek. It defines `FunctionAnalysisAgent` and `MalwareAnalysisAgent`.
- **Orchestration Service**: `agents/main.py` is a FastAPI service (port 8001) that orchestrates data collection from the Rizin backend and prepares data for analysis.
- **Binary Analysis Backend**: `module/rz_pipe/` contains a FastAPI service (`main.py`, port 8000) that wraps `RizinAnalyzer` (`analyzer.py`). It provides structured JSON data from `rizin` (e.g., functions, strings, decompilation).
- **Configuration**: `agents/config.yaml` and `agents/config_loader.py` (using Pydantic) manage LLM settings, plugin endpoints, and prompt paths.
- **Prompts**: System prompts are stored in `agents/prompt/` as Markdown files (e.g., `FunctionAnalysisAgent.md`, `MalwareAnalysisAgent.md`). These prompts contain the "expert knowledge" for malware detection.

## 🔄 Data Flow
1. **Target Binary** is uploaded to the Rizin Backend (`/upload`) via the Orchestration Service.
2. **Rizin Backend** performs static analysis (`aaa`) and exposes results via REST API.
3. **Orchestration Service** (in `agents/main.py`) fetches binary metadata, strings, and decompiled code via HTTP requests to the Rizin backend.
4. **AI Agent** (in `agents/agent_core.py`) processes the collected data based on the expert rules in `agents/prompt/` and generates a JSON analysis report.

## 🛠 Critical Workflows
- **Start Rizin Backend**: Run `python module/rz_pipe/main.py` (starts on port 8000).
- **Start Orchestration Service**: Run `python agents/main.py` (starts on port 8001).
- **Run Test**: Run `python agents/test.py` to verify agent logic.
- **Configuration**: Update `config.yaml` to change LLM models, API keys, or plugin endpoints.

## 📏 Project Conventions
- **Malware Analysis Principles**: Follow the strict guidelines in [../agents/prompt/FunctionAnalysisAgent.md](../agents/prompt/FunctionAnalysisAgent.md). Focus on evidence-based detection (Process Injection, Persistence, C2) and avoid false positives.
- **Configuration**: Always use [../agents/config_loader.py](../agents/config_loader.py) and Pydantic models for accessing settings. Do not hardcode API keys or URLs.
- **Binary Analysis**: Use the `RizinAnalyzer` class in [../module/rz_pipe/analyzer.py](../module/rz_pipe/analyzer.py) for interacting with `rzpipe`. Prefer JSON-returning commands (`cmdj`).
- **API Design**: Both the Rizin backend and the Orchestration service use FastAPI. New analysis capabilities should be added as endpoints in their respective `main.py` files.

## 🔌 Integration Points
- **LLM**: Uses `langchain-deepseek` for the primary analysis engine.
- **Rizin**: Requires `rizin` and `rz-ghidra` plugin for decompilation (`pdcj` command).
- **Communication**: The orchestration service interacts with the Rizin backend via HTTP requests defined in the `plugins` section of `config.yaml`.
