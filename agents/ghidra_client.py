"""
GhidraClient: HTTP client for the Ghidra Pipe service.
Replaces the previous RizinClient with identical interface.
"""
import asyncio
import httpx
import logging
import time
from typing import Dict, Any, List, Optional
from config_loader import AppConfig
from exceptions import GhidraBackendError, GhidraConnectionError, GhidraTimeoutError

logger = logging.getLogger(__name__)


class GhidraClient:
    """HTTP client for communicating with the Ghidra Pipe FastAPI service."""

    # NOTE: Use named constants for easier tuning and to avoid magic numbers.
    DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
    DEFAULT_RETRIES = 3
    HEALTH_CHECK_TIMEOUT_SECONDS = 10.0
    RECOVERY_TIMEOUT_SECONDS = 120.0
    RECOVERY_INITIAL_DELAY_SECONDS = 1.0
    RECOVERY_MAX_DELAY_SECONDS = 10.0

    def __init__(self, config: AppConfig):
        self.config = config
        self.base_url = self._get_base_url(config)
        self.endpoints = self._get_endpoints(config)
        # Default timeout settings
        self.timeout = self.DEFAULT_TIMEOUT
        # Configure retry transport
        self.transport = httpx.AsyncHTTPTransport(retries=self.DEFAULT_RETRIES)

    def _get_base_url(self, config: AppConfig) -> str:
        """Resolve base URL from config with explicit error handling."""
        try:
            return config.plugins["ghidra"].base_url
        except Exception as exc:
            # Refactor note: make configuration errors explicit early.
            raise GhidraBackendError("Missing Ghidra base_url in config") from exc

    def _get_endpoints(self, config: AppConfig) -> Dict[str, str]:
        """Resolve endpoint mappings from config with explicit error handling."""
        try:
            return config.plugins["ghidra"].endpoints
        except Exception as exc:
            # Refactor note: make configuration errors explicit early.
            raise GhidraBackendError("Missing Ghidra endpoints in config") from exc

    async def _request(self, method: str, endpoint_key: str, **kwargs) -> Any:
        """Make an HTTP request to the Ghidra backend."""
        url = self._build_url(endpoint_key)

        # Allow caller to override timeout
        timeout = kwargs.pop("timeout", self.timeout)

        async with httpx.AsyncClient(transport=self.transport, timeout=timeout) as client:
            try:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                return self._safe_json_or_text(resp)
            except httpx.TimeoutException as e:
                logger.error("Request timeout for %s: %s", url, e)
                raise GhidraTimeoutError(
                    f"Ghidra request timed out: {endpoint_key}", endpoint=endpoint_key
                ) from e
            except httpx.HTTPStatusError as e:
                logger.error("HTTP error %s for %s", e.response.status_code, url)
                raise GhidraBackendError(
                    f"Ghidra backend returned error: {e.response.status_code}"
                ) from e
            except httpx.RequestError as e:
                logger.error("Request error for %s: %s", url, e)
                raise GhidraConnectionError(
                    f"Failed to connect to Ghidra backend: {e}"
                ) from e
            except Exception as e:
                logger.error("Unexpected error for %s: %s", url, e)
                raise GhidraBackendError(f"Unexpected error: {e}") from e

    def _build_url(self, endpoint_key: str) -> str:
        """Build a request URL from an endpoint key.

        Refactor note: isolate URL construction to reduce duplication and errors.
        Unknown keys now log a warning instead of silently falling back, so
        config.yaml / config.yaml.example drift is visible.
        """
        path = self.endpoints.get(endpoint_key)
        if path is None:
            logger.warning(
                "Endpoint key '%s' missing from config.yaml; falling back to /%s",
                endpoint_key, endpoint_key,
            )
            path = f"/{endpoint_key}"
        return f"{self.base_url}{path}"

    def _safe_json_or_text(self, response: httpx.Response) -> Any:
        """Return JSON content when possible, otherwise return text.

        Refactor note: centralizes response parsing with safe fallback.
        """
        try:
            return response.json()
        except Exception:
            return response.text

    async def check_health(self):
        """Wait for Ghidra to become healthy after a Pipe process restart."""
        deadline = time.monotonic() + self.RECOVERY_TIMEOUT_SECONDS
        delay = self.RECOVERY_INITIAL_DELAY_SECONDS
        last_error = None

        while True:
            if last_error is not None and time.monotonic() >= deadline:
                break
            try:
                resp = await self._request(
                    "GET", "health_check", timeout=self.HEALTH_CHECK_TIMEOUT_SECONDS,
                )
                if isinstance(resp, dict) and resp.get("status") != "ok":
                    raise GhidraBackendError("Ghidra backend reported unhealthy status")
                return
            except GhidraBackendError as error:
                last_error = error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                sleep_seconds = min(delay, remaining)
                logger.warning(
                    "Ghidra backend is unavailable; retrying health check in %.1fs (%s)",
                    sleep_seconds,
                    error,
                )
                await asyncio.sleep(sleep_seconds)
                delay = min(delay * 2, self.RECOVERY_MAX_DELAY_SECONDS)

        raise GhidraBackendError(
            f"Ghidra backend did not recover within {self.RECOVERY_TIMEOUT_SECONDS:.0f}s"
        ) from last_error

    async def upload_file(self, filename: str, content: bytes, content_type: str):
        """Upload a binary, retrying once if Pipe exits during its restart window."""
        files = {"file": (filename, content, content_type)}
        try:
            await self._request("POST", "upload", files=files, timeout=60.0)
        except GhidraConnectionError as error:
            # The previous task may have closed Pipe after its health check succeeded.
            # Uploads are content-addressed and replacing the current analyzer is safe.
            logger.warning("Ghidra disconnected during upload; waiting to retry: %s", error)
            await self.check_health()
            await self._request("POST", "upload", files=files, timeout=60.0)

    async def trigger_analysis(self):
        """Trigger analysis on the uploaded binary."""
        # Ghidra analysis can take longer than Rizin
        try:
            await self._request("GET", "analyze", timeout=3600.0)
        except GhidraTimeoutError:
            logger.error("Ghidra /analyze timed out; requesting forced stop.")
            try:
                await self.stop_analysis()
            except Exception as stop_error:
                logger.error("Failed to call stop_analysis after timeout: %s", stop_error)
            raise

    async def recover_after_timeout(self, stop: bool = True) -> None:
        """Stop a timed-out request and wait until Pipe is ready again.

        A timed-out HTTP request does not cancel the synchronous work already
        running in the Pipe process.  The process must be terminated before
        the worker releases its single-analysis lock, otherwise the next
        sample can inherit the previous sample's analyzer state.
        """
        if stop:
            try:
                await self.stop_analysis()
            except Exception as stop_error:
                # The process may already be exiting; health recovery below is
                # still useful and provides the definitive readiness check.
                logger.error("Failed to call stop_analysis after timeout: %s", stop_error)
        await self.check_health()

    async def stop_analysis(self) -> Dict[str, Any]:
        """Force-stop the current analysis process in ghidra_pipe service."""
        res = await self._request("POST", "stop_analysis", timeout=5.0)
        return self._coerce_dict(res)

    async def get_metadata(self) -> Dict[str, Any]:
        """Get binary metadata."""
        res = await self._request("GET", "metadata", timeout=60.0)
        return self._coerce_dict(res)

    async def get_functions(self) -> List[Dict[str, Any]]:
        """Get list of functions."""
        res = await self._request("GET", "functions", timeout=60.0)
        return self._coerce_list(res)

    async def get_exports(self) -> List[Dict[str, Any]]:
        """Get export table entries."""
        res = await self._request("GET", "exports", timeout=60.0)
        return self._coerce_list(res)

    async def get_strings(self) -> List[str]:
        """Get strings from the binary."""
        res = await self._request("GET", "strings", timeout=60.0)
        string_entries = self._coerce_list(res)
        return [
            s.get("string")
            for s in string_entries
            if isinstance(s, dict) and "string" in s
        ]

    async def get_callgraph(self) -> Dict[str, Any]:
        """Get global call graph."""
        res = await self._request("GET", "callgraph", timeout=60.0)
        return self._coerce_dict(res)

    async def get_decompiled_codes_batch(self, addresses: List[str]) -> List[Dict[str, str]]:
        """
        Batch decompile functions.
        Returns list of {address, code} dicts.
        """
        # Batch decompilation can be very time-consuming with Ghidra
        res = await self._request("POST", "decompile_batch", json=addresses, timeout=3600.0)
        return self._coerce_list(res)

    async def get_function_xrefs_batch(self, addresses: List[str]) -> List[Dict[str, Any]]:
        """
        Batch get cross-references for multiple functions.
        Input: list of function names or addresses (mixed).
        Returns: list of {name, offset, callers, callees} dicts.
        """
        res = await self._request("POST", "xrefs_batch", json=addresses, timeout=3600.0)
        return self._coerce_list(res)

    async def close_analyzer(self) -> Dict[str, Any]:
        """Close the current Ghidra analyzer, releasing program resources."""
        res = await self._request("POST", "close", timeout=30.0)
        return self._coerce_dict(res)

    def _coerce_dict(self, value: Any) -> Dict[str, Any]:
        """Normalize unknown response payload to dict.

        Refactor note: reduces repeated isinstance checks.
        """
        return value if isinstance(value, dict) else {}

    def _coerce_list(self, value: Any) -> List[Any]:
        """Normalize unknown response payload to list.

        Refactor note: reduces repeated isinstance checks.
        """
        return value if isinstance(value, list) else []
