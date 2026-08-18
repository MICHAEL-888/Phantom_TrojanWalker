import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents"))

from analysis_coordinator import AnalysisCoordinator
from exceptions import GhidraTimeoutError
from schemas import MalwareReport


SAFE_REPORT = MalwareReport(
    threat_type="clean",
    risk_level="safe",
    malware_name="N/A",
    attack_chain="No malicious ATT&CK behavior was identified during preliminary analysis.",
    reason=(
        "Preliminary function analysis found no ATT&CK technique matches; "
        "final malware review was not required."
    ),
).model_dump()


def _make_coordinator(function_results, key_function_analyses):
    coordinator = AnalysisCoordinator(AsyncMock(), AsyncMock(), AsyncMock())
    metadata = {"bin": {"arch": "x86"}}

    coordinator._step_health_check = AsyncMock()
    coordinator._step_upload = AsyncMock()
    coordinator._step_trigger_analysis = AsyncMock()
    coordinator._step_metadata = AsyncMock(return_value=metadata)
    coordinator._step_functions_and_exports = AsyncMock(return_value=([], set(), set(), set(), {}))
    coordinator._step_strings = AsyncMock(return_value=[])
    coordinator._step_xrefs = AsyncMock(return_value=([], {}, []))
    coordinator._step_decompile = AsyncMock(return_value=[])
    coordinator._step_function_analysis = AsyncMock(
        return_value=(function_results, key_function_analyses)
    )
    coordinator._step_malware_report = AsyncMock(return_value={"risk_level": "high"})
    coordinator._step_close = AsyncMock()

    return coordinator, metadata


@pytest.mark.asyncio
async def test_analysis_ends_when_no_target_functions_pass_screening():
    coordinator, metadata = _make_coordinator([], [])

    result = await coordinator.analyze_content("sample.bin", b"sample")

    assert result == {"metadata": metadata, "malware_report": SAFE_REPORT}
    coordinator._step_malware_report.assert_not_awaited()
    coordinator._step_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_analysis_ends_when_no_function_has_attack_match():
    function_results = [
        {"name": "FUN_001", "analysis": {"attack_matches": []}},
    ]
    coordinator, metadata = _make_coordinator(function_results, [])

    result = await coordinator.analyze_content("sample.bin", b"sample")

    assert result == {"metadata": metadata, "malware_report": SAFE_REPORT}
    coordinator._step_malware_report.assert_not_awaited()
    coordinator._step_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_analysis_runs_final_review_when_screening_has_attack_match():
    key_function_analyses = [
        {"name": "FUN_001", "analysis": {"attack_matches": [{"technique_id": "T1059"}]}},
    ]
    coordinator, metadata = _make_coordinator(key_function_analyses, key_function_analyses)

    result = await coordinator.analyze_content("sample.bin", b"sample")

    assert result == {"metadata": metadata, "malware_report": {"risk_level": "high"}}
    coordinator._step_malware_report.assert_awaited_once_with(key_function_analyses, metadata)
    coordinator._step_close.assert_awaited_once()


@pytest.mark.asyncio
async def test_xrefs_timeout_recovers_pipe_before_analysis_task_finishes():
    ghidra = AsyncMock()
    coordinator = AnalysisCoordinator(ghidra, AsyncMock(), AsyncMock())
    coordinator._step_health_check = AsyncMock()
    coordinator._step_upload = AsyncMock()
    coordinator._step_trigger_analysis = AsyncMock()
    coordinator._step_metadata = AsyncMock(return_value={"bin": {"arch": "x86"}})
    coordinator._step_functions_and_exports = AsyncMock(
        return_value=([{"name": "FUN_001"}], set(), set(), set(), {})
    )
    coordinator._step_strings = AsyncMock(return_value=[])
    timeout = GhidraTimeoutError("Ghidra request timed out: xrefs_batch", endpoint="xrefs_batch")
    coordinator._step_xrefs = AsyncMock(side_effect=timeout)
    coordinator._step_close = AsyncMock()
    recovery_finished = False

    async def recover_after_timeout(*, stop):
        nonlocal recovery_finished
        assert stop is True
        recovery_finished = True

    ghidra.recover_after_timeout.side_effect = recover_after_timeout

    with pytest.raises(GhidraTimeoutError, match="xrefs_batch"):
        await coordinator.analyze_content("complex.bin", b"sample")

    assert recovery_finished is True
    ghidra.recover_after_timeout.assert_awaited_once_with(stop=True)
    coordinator._step_close.assert_not_awaited()
