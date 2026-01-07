import httpx
import logging
from typing import Dict, Any, List
from config_loader import AppConfig
from exceptions import RizinBackendError

logger = logging.getLogger(__name__)

class RizinClient:
    def __init__(self, config: AppConfig):
        self.config = config
        self.base_url = config.plugins["rizin"].base_url
        self.endpoints = config.plugins["rizin"].endpoints
        # 设置默认超时
        self.timeout = httpx.Timeout(60.0, connect=10.0)
        # 配置 HTTPX 自动重试 Transport
        # 注意: httpx > 0.20 支持 transport, 需确保版本支持. 
        # 这里使用标准 AsyncHTTPTransport (通常内置于新版 httpx)
        self.transport = httpx.AsyncHTTPTransport(retries=3)

    async def _request(self, method: str, endpoint_key: str, **kwargs) -> Any:
        # 如果 endpoint_key 在配置中不存在，且不是绝对 URL，则可能会出错
        # 但我们假设 config.yaml 同步更新，或者我们使用传入的 fallback path
        path = self.endpoints.get(endpoint_key, f"/{endpoint_key}")
        url = f"{self.base_url}{path}"
        
        # 允许调用者覆盖 timeout
        timeout = kwargs.pop("timeout", self.timeout)

        async with httpx.AsyncClient(transport=self.transport, timeout=timeout) as client:
            try:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                # 尝试解析 JSON, 如果有些接口只返回状态码也可以处理
                try:
                    return resp.json()
                except Exception:
                    return resp.text
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code} for {url}")
                raise RizinBackendError(f"Rizin backend returned error: {e.response.status_code}") from e
            except httpx.RequestError as e:
                logger.error(f"Request error for {url}: {e}")
                raise RizinBackendError(f"Failed to connect to Rizin backend: {e}") from e
            except Exception as e:
                logger.error(f"Unexpected error for {url}: {e}")
                raise RizinBackendError(f"Unexpected error: {e}") from e

    async def check_health(self):
        resp = await self._request("GET", "health_check", timeout=10.0)
        if isinstance(resp, dict) and resp.get("status") != "ok":
            raise RizinBackendError("Rizin backend reported unhealthy status")

    async def upload_file(self, filename: str, content: bytes, content_type: str):
        files = {"file": (filename, content, content_type)}
        # 上传可能耗时，给予更多时间
        await self._request("POST", "upload", files=files, timeout=60.0)

    async def trigger_analysis(self):
        # 深度分析特别耗时
        await self._request("GET", "analyze", timeout=120.0)

    async def get_metadata(self) -> Dict[str, Any]:
        res = await self._request("GET", "metadata", timeout=20.0)
        return res if isinstance(res, dict) else {}

    async def get_functions(self) -> List[Dict[str, Any]]:
        res = await self._request("GET", "functions", timeout=30.0)
        return res if isinstance(res, list) else []

    async def get_strings(self) -> List[str]:
        res = await self._request("GET", "strings", timeout=30.0)
        if isinstance(res, list):
            return [s.get("string") for s in res if isinstance(s, dict) and "string" in s]
        return []

    async def get_callgraph(self) -> Dict[str, Any]:
        res = await self._request("GET", "callgraph", timeout=30.0)
        return res if isinstance(res, dict) else {}

    async def get_decompiled_codes_batch(self, addresses: List[str]) -> List[Dict[str, str]]:
        # 使用批量接口，如果配置中没有定义 decompile_batch，则默认尝试 /decompile_batch
        endpoint_key = "decompile_batch"
        if endpoint_key not in self.endpoints:
            # 临时增加 endpoint 防止 Key Error
            self.endpoints[endpoint_key] = "/decompile_batch"

        # 批量反编译非常耗时，根据数量动态调整超时是一个好主意，这里给一个较大的定值
        return await self._request("POST", endpoint_key, json=addresses, timeout=600.0)
