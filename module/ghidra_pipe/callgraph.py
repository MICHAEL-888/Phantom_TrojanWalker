"""Global call graph builder.

Refactor note: extracted from GhidraAnalyzer. The previous implementation keyed
`func_map` by function NAME, which collided when two functions shared a name
(user-renamed functions or thunks) and silently dropped edges. Now keyed by
entry-address (a unique identifier), so duplicate names no longer collapse nodes.
"""
import logging
from typing import Any, Dict

try:
    from .xrefs import _iter_call_references_from_body
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    from xrefs import _iter_call_references_from_body

logger = logging.getLogger(__name__)


def build_call_graph(program: Any) -> Dict[str, Any]:
    """Build {nodes, edges} for the whole program.

    Nodes are keyed by entry-address to avoid name collisions. Edges reference
    node ids (positional index in the nodes list).
    """
    if program is None:
        return {}

    try:
        func_manager = program.getFunctionManager()
        ref_manager = program.getReferenceManager()

        nodes = []
        # addr_offset -> node index. Entry offset is a unique per-function key.
        addr_to_idx: Dict[int, int] = {}

        for idx, func in enumerate(func_manager.getFunctions(True)):
            entry = func.getEntryPoint()
            offset = entry.getOffset() if entry else 0
            nodes.append({
                "id": idx,
                "name": func.getName(),
                "offset": offset,
            })
            if offset:
                addr_to_idx[offset] = idx

        edges = []
        for func in func_manager.getFunctions(True):
            caller_entry = func.getEntryPoint()
            caller_offset = caller_entry.getOffset() if caller_entry else 0
            caller_idx = addr_to_idx.get(caller_offset)
            if caller_idx is None:
                continue

            body = func.getBody()
            if not body:
                continue

            seen_callee_idx = set()
            for ref in _iter_call_references_from_body(body, ref_manager):
                to_addr = ref.getToAddress()
                callee = func_manager.getFunctionAt(to_addr)
                if callee:
                    callee_entry = callee.getEntryPoint()
                    callee_offset = callee_entry.getOffset() if callee_entry else 0
                    callee_idx = addr_to_idx.get(callee_offset)
                    if callee_idx is not None and callee_idx not in seen_callee_idx:
                        seen_callee_idx.add(callee_idx)
                        edges.append({"from": caller_idx, "to": callee_idx})

        logger.info(f"Call graph: {len(nodes)} nodes, {len(edges)} edges")
        return {"nodes": nodes, "edges": edges}

    except Exception as e:
        logger.error(f"Error generating call graph: {e}")
        return {}
