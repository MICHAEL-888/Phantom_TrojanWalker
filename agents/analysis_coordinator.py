import logging
import json
from typing import Dict, Any, List
from fastapi import UploadFile

from rizin_client import RizinClient
from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
# 虽然这里可能不直接捕获异常（由上层处理），但导入以便类型注解或特定的 try-catch
from exceptions import RizinBackendError, LLMResponseError
from langchain.messages import SystemMessage, HumanMessage

logger = logging.getLogger(__name__)

class AnalysisCoordinator:
    def __init__(self, rizin_client: RizinClient, func_agent: FunctionAnalysisAgent, malware_agent: MalwareAnalysisAgent):
        self.rizin = rizin_client
        self.func_agent = func_agent
        self.malware_agent = malware_agent

    async def analyze_file(self, file: UploadFile) -> Dict[str, Any]:
        content = await file.read()
        return await self.analyze_content(file.filename, content, file.content_type)

    async def analyze_content(self, filename: str, content: bytes, content_type: str = "application/octet-stream") -> Dict[str, Any]:
        logger.info(f"Start analyzing file: {filename}")

        def _normalize_func_name(name: str) -> str:
            if not name:
                return ""
            base = str(name).strip()
            # rizin often prefixes symbols, keep the last segment for matching
            for prefix in ("sym.", "fcn.", "sub.", "loc.", "imp.", "obj.", "dbg."):
                if base.startswith(prefix):
                    base = base[len(prefix):]
            # Sometimes symbols still contain dots after stripping a single prefix
            if "." in base:
                base = base.split(".")[-1]
            base = base.lstrip("_")
            return base.lower()

        def _is_ai_target_function(name: str) -> bool:
            if not name:
                return False
            if str(name).startswith("fcn."):
                return True
            normalized = _normalize_func_name(str(name))
            # Cover common entrypoints across C/C++ and Windows binaries
            interesting = {
                "main",
                "wmain",
                "winmain",
                "wwinmain",
                "dllmain",
                # Common CRT/loader entrypoints
                "maincrtstartup",
                "winmaincrtstartup",
                "dllmaincrtstartup",
                "tmaincrtstartup",
                "wtmaincrtstartup",
            }
            return normalized in interesting
        
        # 1. Check Health
        logger.info("Step 1: Checking Rizin backend health...")
        await self.rizin.check_health()

        # 2. Upload
        logger.info(f"Step 2: Uploading file '{filename}' to backend...")
        await self.rizin.upload_file(filename, content, content_type)

        # 3. Trigger Analysis
        logger.info("Step 3: Triggering Rizin deep analysis (aaa)...")
        await self.rizin.trigger_analysis()

        # 4. Fetch Metadata
        logger.info("Step 4: Fetching binary metadata...")
        metadata = await self.rizin.get_metadata()

        # 5. Fetch Functions
        logger.info("Step 5: Fetching and filtering functions...")
        raw_funcs = await self.rizin.get_functions()
        
        functions_data = [
            {
                "name": f.get("name"),
                "offset": f.get("offset"),
                "size": f.get("size"),
                "signature": f.get("signature")
            }
            for f in raw_funcs
        ]

        # 6. Fetch Strings
        logger.info("Step 6: Fetching strings from binary...")
        strings_data = await self.rizin.get_strings()

        # 7. Call Graph
        logger.info("Step 7: Generating global call graph...")
        callgraph_data = await self.rizin.get_callgraph()

        # 8. Decompile (Batch)
        logger.info(f"Step 8: Decompiling functions (Batch mode)...")
        
        # 提取所有函数名称
        func_names = [f["name"] for f in functions_data if f.get("name")]
        
        # 调用批量反编译接口 (后端支持通过名称或地址反编译)
        decompiled_codes_raw = await self.rizin.get_decompiled_codes_batch(func_names)
        
        # 将原始结果直接映射到最终结果
        decompiled_codes = []
        # 后端返回格式为 [{"address": "name_or_addr", "code": "..."}]
        for item in decompiled_codes_raw:
            name = item.get("address") # 在这里 address 字段将包含我们发送的名称
            code = item.get("code")
            if code and name:
                decompiled_codes.append({
                    "name": name,
                    "code": code
                })

        # 9. AI Analysis (Parallel)
        logger.info(f"Step 9: Analyzing {len(decompiled_codes)} decompiled functions...")

        # 分析目标函数：fcn.* 自动命名函数 + 常见入口函数（main/WinMain/DllMain 等）
        target_funcs = [
            item
            for item in decompiled_codes
            if _is_ai_target_function(item.get("name"))
        ]
        
        if not target_funcs:
            logger.info("No target functions found for AI analysis, skipping function analysis step.")
            function_analysis_results = []
        else:
            # LangChain supports native concurrency limiting via RunnableConfig.max_concurrency.
            # We batch the requests and let LangChain manage parallelism.
            max_input_tokens = getattr(self.func_agent.agent_config.llm, "max_input_tokens", None)
            max_char_limit = None
            if isinstance(max_input_tokens, int):
                max_char_limit = max(0, max_input_tokens - 10000)

            prepared_codes = []
            prepared_names = []
            for item in target_funcs:
                code = item.get("code") or ""
                if isinstance(max_char_limit, int) and max_char_limit > 0 and len(code) > max_char_limit:
                    code = code[:max_char_limit] + "\n... [Code truncated for AI analysis due to context limits] ..."
                prepared_codes.append(code)
                prepared_names.append(item.get("name"))

            # Use LangChain's built-in concurrency limiting on batch calls.
            message_batches = [
                [
                    SystemMessage(content=self.func_agent.agent_config.system_prompt),
                    HumanMessage(content=str(code)),
                ]
                for code in prepared_codes
            ]
            config = {"max_concurrency": self.func_agent.agent_config.max_concurrency}

            try:
                responses = await self.func_agent.llm.abatch(message_batches, config=config)
            except AttributeError:
                # Fallback for older LangChain versions that may not expose `abatch`.
                responses = self.func_agent.llm.batch(message_batches, config=config)

            analyses: List[dict] = []
            for resp in responses:
                content = getattr(resp, "content", None)
                if content is None:
                    content = str(resp)
                try:
                    analyses.append(json.loads(content))
                except Exception as e:
                    analyses.append({"error": f"Failed to parse JSON: {e}", "raw_response": content})

            function_analysis_results = [
                {"name": name, "analysis": analysis}
                for name, analysis in zip(prepared_names, analyses)
            ]

        # 9.5 Filter key functions (ATT&CK matched)
        # 只把“能映射到 ATT&CK 的重点函数”交给最终报告 Agent，减少噪音。
        # 规则：只要 attack_matches 非空，就视为重点函数（不依赖 confidence 阈值）。

        key_function_analysis_results = []
        for item in function_analysis_results:
            analysis = item.get("analysis") if isinstance(item, dict) else None
            if not isinstance(analysis, dict):
                continue
            # skip errored analyses
            if "error" in analysis:
                continue
            attack_matches = analysis.get("attack_matches")
            if isinstance(attack_matches, list) and len(attack_matches) > 0:
                key_function_analysis_results.append(item)

        logger.info(
            "Step 9.5: Selected %d key functions (ATT&CK matched)",
            len(key_function_analysis_results),
        )

        # 10. Malware Report
        logger.info("Step 10: Generating final malware analysis report (ATT&CK-focused)...")
        final_malware_report = await self.malware_agent.analyze(
            analysis_results=key_function_analysis_results,
            metadata=metadata,
        )

        logger.info(f"Analysis complete for file: {filename}")
        return {
            "metadata": metadata,
            "functions": functions_data,
            "strings": strings_data,
            "decompiled_code": decompiled_codes,
            "function_analyses": function_analysis_results,
            "malware_report": final_malware_report
        }
