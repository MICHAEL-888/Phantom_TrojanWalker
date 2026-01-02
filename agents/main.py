import os
import httpx
import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from config_loader import load_config
from typing import List, Dict, Any

app = FastAPI()
config = load_config()
RIZIN_BASE_URL = config.plugins["rizin"].base_url
ENDPOINTS = config.plugins["rizin"].endpoints

async def _check_health(client: httpx.AsyncClient):
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['health_check']}"
        resp = await client.get(url)
        if resp.status_code != 200 or resp.json().get("status") != "ok":
            raise HTTPException(status_code=503, detail="Rizin backend is not healthy")
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=503, detail=f"Rizin backend connection failed: {str(e)}")

async def _upload_file(client: httpx.AsyncClient, file: UploadFile):
    content = await file.read()
    files = {"file": (file.filename, content, file.content_type)}
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['upload']}"
        resp = await client.post(url, files=files)
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to upload file to Rizin backend")
        return resp.json()
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

async def _trigger_analysis(client: httpx.AsyncClient):
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['analyze']}"
        resp = await client.get(url)
        if resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to trigger analysis")
        return resp.json()
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=f"Error during analysis: {str(e)}")

async def _get_metadata(client: httpx.AsyncClient) -> Dict[str, Any]:
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['metadata']}"
        resp = await client.get(url)
        return resp.json() if resp.status_code == 200 else {}
    except Exception:
        return {}

async def _get_functions(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['functions']}"
        resp = await client.get(url)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []

async def _get_strings(client: httpx.AsyncClient) -> List[str]:
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['strings']}"
        resp = await client.get(url)
        if resp.status_code == 200:
            return [s.get("string") for s in resp.json() if "string" in s]
    except Exception:
        pass
    return []

async def _get_callgraph(client: httpx.AsyncClient) -> Dict[str, Any]:
    try:
        url = f"{RIZIN_BASE_URL}{ENDPOINTS['callgraph']}"
        resp = await client.get(url)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

async def _get_decompiled_codes(client: httpx.AsyncClient, functions: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    decompiled_results = []
    url = f"{RIZIN_BASE_URL}{ENDPOINTS['decompile']}"
    for f in functions:
        addr = f.get("offset")
        name = f.get("name", "unknown")
        if addr is not None:
            try:
                resp = await client.get(url, params={"addr": str(addr)})
                if resp.status_code == 200:
                    code = resp.json().get("code")
                    if code:
                        decompiled_results.append({
                            "name": name,
                            "code": code
                        })
            except Exception:
                continue
    return decompiled_results

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    """
    接收一个文件，并协调 Rizin 后端进行分析，提取元数据、函数、字符串、调用图和反编译代码。
    """
    async with httpx.AsyncClient(timeout=None) as client:
        # 1. 检查接口是否存活
        await _check_health(client)

        # 2. 上传文件
        await _upload_file(client, file)

        # 3. 触发分析
        await _trigger_analysis(client)

        # 4. 获取元数据
        metadata = await _get_metadata(client)

        # 5. 获取函数并过滤
        raw_funcs = await _get_functions(client)
        functions_data = [
            {
                "name": f.get("name"),
                "size": f.get("size"),
                "signature": f.get("signature")
            }
            for f in raw_funcs
        ]

        # 6. 获取字符串
        strings_data = await _get_strings(client)

        # 7. 获取调用图
        callgraph_data = await _get_callgraph(client)

        # 8. 获取反编译代码
        decompiled_codes = await _get_decompiled_codes(client, raw_funcs)

        return {
            "metadata": metadata,
            "functions": functions_data,
            "strings": strings_data,
            "callgraph": callgraph_data,
            "decompiled_code": decompiled_codes
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)

