"""Analysis pipeline orchestrator.

Refactor note: the previous 138-line analyze_content method is decomposed into
named step methods for readability and maintainability. The wasted get_callgraph()
call (result was discarded) is removed. Hardcoded entry-point sets and
function-name prefixes are extracted to module-level constants.
"""
import logging
from typing import Dict, Any, List, Set, Tuple
from fastapi import UploadFile

from ghidra_client import GhidraClient
from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent

logger = logging.getLogger(__name__)

# Refactor note: centralized function-name prefixes and entry-point sets that
# were previously duplicated across _is_ai_target_function and
# _is_entry_point_function.
_GHIDRA_NAME_PREFIXES = ("FUN_", "thunk_FUN_", "LAB_", "DAT_", "PTR_", "s_")
_RIZIN_NAME_PREFIXES = ("sym.", "fcn.", "sub.", "loc.", "imp.", "obj.", "dbg.")

_ENTRY_POINT_FUNCTIONS = frozenset({
    "main", "wmain", "winmain", "wwinmain", "dllmain",
    "_start", "start", "entry",
})

# Superset of entry points including common CRT/loader startup symbols.
_AI_TARGET_FUNCTIONS = _ENTRY_POINT_FUNCTIONS | frozenset({
    "maincrtstartup", "winmaincrtstartup", "dllmaincrtstartup",
    "tmaincrtstartup", "wtmaincrtstartup",
})


class AnalysisCoordinator:
    def __init__(
        self,
        ghidra_client: GhidraClient,
        func_agent: FunctionAnalysisAgent,
        malware_agent: MalwareAnalysisAgent,
    ):
        self.ghidra = ghidra_client
        self.func_agent = func_agent
        self.malware_agent = malware_agent

    # ------------------------------------------------------------------
    # Name normalization & function classification
    # ------------------------------------------------------------------
    def _normalize_func_name(self, name: str) -> str:
        if not name:
            return ""
        base = str(name).strip()
        for prefix in _GHIDRA_NAME_PREFIXES:
            if base.startswith(prefix):
                base = base[len(prefix):]
        for prefix in _RIZIN_NAME_PREFIXES:
            if base.startswith(prefix):
                base = base[len(prefix):]
        if "." in base:
            base = base.split(".")[-1]
        base = base.lstrip("_")
        return base.lower()

    def _is_ai_target_function(self, name: str) -> bool:
        if not name:
            return False
        if str(name).startswith("FUN_") or str(name).startswith("fcn."):
            return True
        return self._normalize_func_name(str(name)) in _AI_TARGET_FUNCTIONS

    def _is_entry_point_function(self, name: str) -> bool:
        if not name:
            return False
        return self._normalize_func_name(str(name)) in _ENTRY_POINT_FUNCTIONS

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------
    def _build_functions_payload(self, raw_funcs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Refactor: isolate mapping logic for readability and reuse.
        return [
            {
                "name": f.get("name"),
                "offset": f.get("offset"),
                "size": f.get("size"),
                "signature": f.get("signature"),
            }
            for f in raw_funcs
        ]

    def _extract_function_names(self, functions_data: List[Dict[str, Any]]) -> List[str]:
        # Refactor: keep filtering rules in one place.
        return [f["name"] for f in functions_data if f.get("name")]

    def _build_export_markers(self, exports_data: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str], Set[int]]:
        """Build exact/normalized export names and exported offsets from export entries."""
        exact_names: Set[str] = set()
        normalized_names: Set[str] = set()
        exported_offsets: Set[int] = set()

        for item in exports_data:
            if not isinstance(item, dict):
                continue
            name_value = item.get("name")
            if name_value:
                name = str(name_value).strip()
                if name:
                    exact_names.add(name)
                    normalized = self._normalize_func_name(name)
                    if normalized:
                        normalized_names.add(normalized)

            offset_value = item.get("offset")
            if isinstance(offset_value, int):
                exported_offsets.add(offset_value)

        return exact_names, normalized_names, exported_offsets

    def _build_function_offset_map(self, functions_data: List[Dict[str, Any]]) -> Dict[str, int]:
        """Build function name -> entry offset lookup."""
        mapping: Dict[str, int] = {}
        for item in functions_data:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            offset = item.get("offset")
            if name and isinstance(offset, int) and name not in mapping:
                mapping[name] = offset
        return mapping

    def _is_exported_function(
        self,
        name: str,
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> bool:
        """Check if a function belongs to export table (name or offset match)."""
        if not name:
            return False
        if name in exported_exact:
            return True
        normalized = self._normalize_func_name(str(name))
        if normalized and normalized in exported_normalized:
            return True
        func_offset = function_offsets.get(name)
        return isinstance(func_offset, int) and func_offset in exported_offsets

    def _merge_function_candidates(self, func_names: List[str]) -> List[str]:
        """Build stable deduplicated function candidates."""
        merged: List[str] = []
        seen: Set[str] = set()
        for name in func_names:
            if name and name not in seen:
                seen.add(name)
                merged.append(name)
        return merged

    def _filter_function_names_for_decompile(
        self,
        func_names: List[str],
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> List[str]:
        """Limit decompile targets to AI targets and export-table functions."""
        return [
            name
            for name in func_names
            if self._is_ai_target_function(name)
            or self._is_exported_function(
                name, exported_exact, exported_normalized, exported_offsets, function_offsets,
            )
        ]

    def _map_decompiled_results(self, decompiled_codes_raw: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        # Refactor: normalize backend results and guard missing fields.
        mapped: List[Dict[str, str]] = []
        for item in decompiled_codes_raw:
            name = item.get("address")  # address field carries the name we sent
            code = item.get("code")
            if code and name:
                mapped.append({"name": name, "code": code})
        return mapped

    def _filter_target_functions(
        self,
        decompiled_codes: List[Dict[str, str]],
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> List[Dict[str, str]]:
        # Refactor: single-responsibility filtering step for AI analysis.
        return [
            item
            for item in decompiled_codes
            if self._is_ai_target_function(item.get("name"))
            or self._is_exported_function(
                item.get("name"), exported_exact, exported_normalized, exported_offsets, function_offsets,
            )
        ]

    def _build_callers_lookup(self, function_xrefs: List[Dict[str, Any]] | None) -> Dict[str, List[Dict[str, Any]]]:
        """Build a lookup from function name to its callers list."""
        if not function_xrefs:
            return {}
        lookup: Dict[str, List[Dict[str, Any]]] = {}
        for xref in function_xrefs:
            name = xref.get("name") if isinstance(xref, dict) else None
            if name:
                callers = xref.get("callers", []) if isinstance(xref, dict) else []
                lookup[name] = callers or []
        return lookup

    def _filter_functions_with_callers(
        self,
        target_funcs: List[Dict[str, str]],
        callers_lookup: Dict[str, List[Dict[str, Any]]],
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> List[Dict[str, str]]:
        """Drop functions with no callers, unless they are entry points or exported."""
        filtered: List[Dict[str, str]] = []
        for item in target_funcs:
            name = item.get("name")
            if not name:
                continue
            if self._is_entry_point_function(name):
                filtered.append(item)
                continue
            if self._is_exported_function(
                name, exported_exact, exported_normalized, exported_offsets, function_offsets,
            ):
                filtered.append(item)
                continue
            if len(callers_lookup.get(name, [])) > 0:
                filtered.append(item)
        return filtered

    def _select_key_function_analyses(self, function_analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Refactor: keep ATT&CK selection logic isolated and testable.
        key_results: List[Dict[str, Any]] = []
        for item in function_analysis_results:
            analysis = item.get("analysis") if isinstance(item, dict) else None
            if not isinstance(analysis, dict):
                continue
            if "error" in analysis:
                continue
            attack_matches = analysis.get("attack_matches")
            if isinstance(attack_matches, list) and len(attack_matches) > 0:
                key_results.append(item)
        return key_results

    # ------------------------------------------------------------------
    # Pipeline steps (Refactor: decomposed from the 138-line analyze_content)
    # ------------------------------------------------------------------
    async def _step_health_check(self) -> None:
        logger.info("Step 1: Checking Ghidra backend health...")
        await self.ghidra.check_health()

    async def _step_upload(self, filename: str, content: bytes, content_type: str) -> None:
        logger.info("Step 2: Uploading file '%s' to backend...", filename)
        await self.ghidra.upload_file(filename, content, content_type)

    async def _step_trigger_analysis(self) -> None:
        logger.info("Step 3: Triggering Ghidra analysis...")
        await self.ghidra.trigger_analysis()

    async def _step_metadata(self) -> Dict[str, Any]:
        logger.info("Step 4: Fetching binary metadata...")
        return await self.ghidra.get_metadata()

    async def _step_functions_and_exports(
        self,
    ) -> Tuple[List[Dict[str, Any]], Set[str], Set[str], Set[int], Dict[str, int]]:
        logger.info("Step 5: Fetching and filtering functions...")
        raw_funcs = await self.ghidra.get_functions() or []
        functions_data = self._build_functions_payload(raw_funcs)

        logger.info("Step 5.5: Fetching export table entries...")
        exports_data = await self.ghidra.get_exports() or []
        exported_exact, exported_normalized, exported_offsets = self._build_export_markers(exports_data)
        function_offsets = self._build_function_offset_map(functions_data)
        logger.info("Export table function candidates: %d", len(exported_exact))

        return functions_data, exported_exact, exported_normalized, exported_offsets, function_offsets

    async def _step_strings(self) -> List[Any]:
        logger.info("Step 6: Fetching strings from binary...")
        return await self.ghidra.get_strings() or []

    async def _step_xrefs(
        self,
        functions_data: List[Dict[str, Any]],
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]], List[str]]:
        logger.info("Step 7: Fetching function cross-references...")
        func_names = self._extract_function_names(functions_data)
        merged = self._merge_function_candidates(func_names)
        decompile_targets = self._filter_function_names_for_decompile(
            merged, exported_exact, exported_normalized, exported_offsets, function_offsets,
        )
        logger.info("Xrefs targets: %d functions", len(decompile_targets))
        function_xrefs = await self.ghidra.get_function_xrefs_batch(decompile_targets) or []
        callers_lookup = self._build_callers_lookup(function_xrefs)
        logger.info("Got xrefs for %d functions", len(function_xrefs))
        return function_xrefs, callers_lookup, decompile_targets

    async def _step_decompile(self, decompile_targets: List[str]) -> List[Dict[str, str]]:
        logger.info("Step 8: Decompiling %d functions (batch mode)...", len(decompile_targets))
        decompiled_codes_raw = await self.ghidra.get_decompiled_codes_batch(decompile_targets) or []
        return self._map_decompiled_results(decompiled_codes_raw)

    async def _step_function_analysis(
        self,
        decompiled_codes: List[Dict[str, str]],
        callers_lookup: Dict[str, List[Dict[str, Any]]],
        exported_exact: Set[str],
        exported_normalized: Set[str],
        exported_offsets: Set[int],
        function_offsets: Dict[str, int],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        logger.info("Step 9: Analyzing %d decompiled functions...", len(decompiled_codes))
        target_funcs = self._filter_target_functions(
            decompiled_codes, exported_exact, exported_normalized, exported_offsets, function_offsets,
        )
        target_funcs = self._filter_functions_with_callers(
            target_funcs, callers_lookup, exported_exact, exported_normalized, exported_offsets, function_offsets,
        )
        logger.info("After caller filter: %d functions to analyze", len(target_funcs))

        if not target_funcs:
            logger.info("No target functions found for AI analysis, skipping function analysis step.")
            return [], []

        function_analysis_results = await self.func_agent.analyze_decompiled_batch(target_funcs)
        key_results = self._select_key_function_analyses(function_analysis_results)
        logger.info("Step 9.5: Selected %d key functions (ATT&CK matched)", len(key_results))
        return function_analysis_results, key_results

    async def _step_malware_report(
        self, key_function_analyses: List[Dict[str, Any]], metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.info("Step 10: Generating final malware analysis report (ATT&CK-focused)...")
        return await self.malware_agent.analyze(
            analysis_results=key_function_analyses, metadata=metadata,
        )

    async def _step_close(self) -> None:
        logger.info("Step 11: Closing Ghidra analyzer to release memory...")
        await self.ghidra.close_analyzer()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    async def analyze_file(self, file: UploadFile) -> Dict[str, Any]:
        content = await file.read()
        # Refactor note: guard against None filename (FastAPI UploadFile.filename is Optional).
        filename = file.filename or "upload.bin"
        return await self.analyze_content(filename, content, file.content_type)

    async def analyze_content(
        self, filename: str, content: bytes, content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """Run the full analysis pipeline.

        Refactor note: previously a 138-line method; now orchestrates named
        step methods. The wasted get_callgraph() call (result was discarded)
        has been removed.
        """
        logger.info("Start analyzing file: %s", filename)

        await self._step_health_check()
        await self._step_upload(filename, content, content_type)
        await self._step_trigger_analysis()

        metadata = await self._step_metadata()
        (
            functions_data,
            exported_exact,
            exported_normalized,
            exported_offsets,
            function_offsets,
        ) = await self._step_functions_and_exports()

        strings_data = await self._step_strings()
        function_xrefs, callers_lookup, decompile_targets = await self._step_xrefs(
            functions_data, exported_exact, exported_normalized, exported_offsets, function_offsets,
        )

        decompiled_codes = await self._step_decompile(decompile_targets)

        function_analysis_results, key_function_analyses = await self._step_function_analysis(
            decompiled_codes, callers_lookup, exported_exact, exported_normalized, exported_offsets, function_offsets,
        )

        final_malware_report = await self._step_malware_report(key_function_analyses, metadata)

        await self._step_close()

        logger.info("Analysis complete for file: %s", filename)
        return {
            "metadata": metadata,
            "malware_report": final_malware_report,
        }
