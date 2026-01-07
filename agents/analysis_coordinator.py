import logging
import asyncio
from typing import Dict, Any, List
from fastapi import UploadFile

from rizin_client import RizinClient
from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
# 虽然这里可能不直接捕获异常（由上层处理），但导入以便类型注解或特定的 try-catch
from exceptions import RizinBackendError, LLMResponseError

logger = logging.getLogger(__name__)

class AnalysisCoordinator:
    def __init__(self, rizin_client: RizinClient, func_agent: FunctionAnalysisAgent, malware_agent: MalwareAnalysisAgent):
        self.rizin = rizin_client
        self.func_agent = func_agent
        self.malware_agent = malware_agent

    async def analyze_file(self, file: UploadFile) -> Dict[str, Any]:
        filename = file.filename
        logger.info(f"Start analyzing file: {filename}")
        
        # 1. Check Health
        logger.info("Step 1: Checking Rizin backend health...")
        await self.rizin.check_health()

        # 2. Upload
        logger.info(f"Step 2: Uploading file '{filename}' to backend...")
        content = await file.read()
        await self.rizin.upload_file(filename, content, file.content_type)

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
        
        # 提取所有函数地址
        func_addresses = [str(f["offset"]) for f in functions_data if f.get("offset") is not None]
        
        # 调用批量反编译接口
        decompiled_codes_raw = await self.rizin.get_decompiled_codes_batch(func_addresses)
        
        # 建立地址到函数名的映射，用于组装结果
        addr_to_name = {str(f["offset"]): f.get("name", "unknown") for f in functions_data}
        
        decompiled_codes = []
        for item in decompiled_codes_raw:
            # item 结构: {"address": "...", "code": "..."}
            addr = str(item.get("address"))
            code = item.get("code")
            if code and addr in addr_to_name:
                decompiled_codes.append({
                    "name": addr_to_name[addr],
                    "code": code
                })

        # 9. AI Analysis (Parallel)
        logger.info(f"Step 9: Analyzing {len(decompiled_codes)} decompiled functions...")
        
        async def analyze_func(item):
            # 限制发送给 LLM 的代码长度
            MAX_CHAR_LIMIT = 100000
            code = item["code"]
            if len(code) > MAX_CHAR_LIMIT:
                code = code[:MAX_CHAR_LIMIT] + "\n... [Code truncated for AI analysis due to context limits] ..."
            
            try:
                analysis = await self.func_agent.analyze(code)
                return {
                    "name": item["name"],
                    "analysis": analysis
                }
            except Exception as e:
                logger.error(f"Function analysis failed for {item['name']}: {e}")
                # 即使单个函数分析失败，也不要在整个流程中抛出异常，而是记录错误
                return {
                    "name": item["name"],
                    "analysis": {"error": str(e)}
                }

        # 仅分析以 fcn. 开头的自动命名函数 (通常是未识别符号的函数)
        target_funcs = [item for item in decompiled_codes if item["name"].startswith("fcn.")]
        
        if not target_funcs:
            logger.info("No 'fcn.*' functions found for AI analysis, skipping function analysis step.")
            function_analysis_results = []
        else:
            function_analysis_results = await asyncio.gather(*[analyze_func(func) for func in target_funcs])

        # 10. Malware Report
        logger.info("Step 10: Generating final malware analysis report...")
        final_malware_report = await self.malware_agent.analyze(
            analysis_results=function_analysis_results,
            metadata=metadata,
            callgraph=callgraph_data
        )

        logger.info(f"Analysis complete for file: {filename}")
        return {
            "metadata": metadata,
            "functions": functions_data,
            "strings": strings_data,
            "callgraph": callgraph_data,
            "decompiled_code": decompiled_codes,
            "function_analyses": function_analysis_results,
            "malware_report": final_malware_report
        }
