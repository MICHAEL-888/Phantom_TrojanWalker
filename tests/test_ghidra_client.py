import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents"))

from exceptions import GhidraBackendError, GhidraConnectionError
from ghidra_client import GhidraClient


def _make_client():
    config = SimpleNamespace(
        plugins={
            "ghidra": SimpleNamespace(
                base_url="http://ghidra",
                endpoints={"health_check": "/health_check"},
            )
        }
    )
    return GhidraClient(config)


@pytest.mark.asyncio
async def test_check_health_waits_for_pipe_restart(monkeypatch):
    client = _make_client()
    client._request = AsyncMock(
        side_effect=[
            GhidraBackendError("connection refused"),
            GhidraBackendError("connection refused"),
            {"status": "ok"},
        ]
    )
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await client.check_health()

    assert sleeps == [1.0, 2.0]
    assert client._request.await_count == 3


@pytest.mark.asyncio
async def test_check_health_fails_after_recovery_timeout():
    client = _make_client()
    client.RECOVERY_TIMEOUT_SECONDS = 0
    client._request = AsyncMock(side_effect=GhidraBackendError("connection refused"))

    with pytest.raises(GhidraBackendError, match="did not recover within 0s"):
        await client.check_health()

    client._request.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_health_waits_while_pipe_reports_restarting(monkeypatch):
    client = _make_client()
    client._request = AsyncMock(side_effect=[{"status": "restarting"}, {"status": "ok"}])
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await client.check_health()

    assert sleeps == [1.0]
    assert client._request.await_count == 2


@pytest.mark.asyncio
async def test_upload_retries_after_pipe_disconnect():
    client = _make_client()
    client._request = AsyncMock(
        side_effect=[
            GhidraConnectionError("Server disconnected without sending a response."),
            {"status": "ok"},
            {"status": "ok"},
        ]
    )

    await client.upload_file("sample.bin", b"sample", "application/octet-stream")

    assert client._request.await_count == 3


@pytest.mark.asyncio
async def test_recover_after_timeout_stops_pipe_before_waiting_for_health():
    client = _make_client()
    events = []

    async def stop_analysis():
        events.append("stop")

    async def check_health():
        events.append("health")

    client.stop_analysis = stop_analysis
    client.check_health = check_health

    await client.recover_after_timeout()

    assert events == ["stop", "health"]


def test_timeout_constants_keep_pipe_fallback_window_open():
    from mcp_loader import MCP_HTTP_TIMEOUT_SECONDS

    assert MCP_HTTP_TIMEOUT_SECONDS == 90.0
