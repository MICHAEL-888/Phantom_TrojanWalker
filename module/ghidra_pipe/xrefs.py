"""Cross-reference (callers/callees) service.

Refactor note: extracted from GhidraAnalyzer. The inconsistent return type of
`_iter_call_references_from_body` (list on early exit, generator otherwise) is
fixed to always return a generator via a wrapper that yields nothing.
"""
import logging
from typing import Any, Dict, List, Optional

try:
    from .addressing import find_function
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    from addressing import find_function

logger = logging.getLogger(__name__)


def _iter_call_references_from_body(body: Any, ref_manager: Any):
    """Yield call-type references originating from a function body.

    Note: ReferenceManager.getReferenceSourceIterator may yield Address objects,
    so References are resolved via getReferencesFrom(address). Refactor note:
    always return a generator (yield nothing on early exit) so the type
    contract is consistent for callers.
    """
    if not body:
        return
    try:
        ref_iter = ref_manager.getReferenceSourceIterator(body, True)
    except Exception:
        return

    for from_addr in ref_iter:
        try:
            refs_from = ref_manager.getReferencesFrom(from_addr)
        except Exception:
            continue
        for ref in refs_from:
            try:
                if ref.getReferenceType().isCall():
                    yield ref
            except Exception:
                continue


def get_callees(func: Any, func_manager: Any, ref_manager: Any) -> List[Dict[str, Any]]:
    """Get functions called by the given function, deduped by (name, offset)."""
    callees: List[Dict[str, Any]] = []
    seen = set()

    body = func.getBody()
    if not body:
        return callees

    for ref in _iter_call_references_from_body(body, ref_manager):
        to_addr = ref.getToAddress()
        callee = func_manager.getFunctionAt(to_addr)
        if callee:
            callee_name = callee.getName()
            callee_entry = callee.getEntryPoint()
            callee_offset = callee_entry.getOffset() if callee_entry else 0
            key = (callee_name, callee_offset)
            if key not in seen:
                seen.add(key)
                callees.append({"name": callee_name, "offset": callee_offset})

    return callees


def get_callers(func: Any, func_manager: Any, ref_manager: Any) -> List[Dict[str, Any]]:
    """Get functions that call the given function, deduped by (name, offset)."""
    callers: List[Dict[str, Any]] = []
    seen = set()

    func_entry = func.getEntryPoint()
    if not func_entry:
        return callers

    refs_to = ref_manager.getReferencesTo(func_entry)
    for ref in refs_to:
        # Some bindings may yield Address objects; handle both Reference and Address.
        if hasattr(ref, "getReferenceType"):
            if not ref.getReferenceType().isCall():
                continue
            from_addr = ref.getFromAddress()
        else:
            # Address fallback: resolve back to a call Reference targeting func_entry.
            from_addr = ref
            found = False
            try:
                refs_from = ref_manager.getReferencesFrom(from_addr)
            except Exception:
                refs_from = []
            for ref_from in refs_from:
                try:
                    if ref_from.getReferenceType().isCall() and ref_from.getToAddress() == func_entry:
                        from_addr = ref_from.getFromAddress()
                        found = True
                        break
                except Exception:
                    continue
            if not found:
                continue

        caller = func_manager.getFunctionContaining(from_addr)
        if caller:
            caller_name = caller.getName()
            caller_entry = caller.getEntryPoint()
            caller_offset = caller_entry.getOffset() if caller_entry else 0
            key = (caller_name, caller_offset)
            if key not in seen:
                seen.add(key)
                callers.append({"name": caller_name, "offset": caller_offset})

    return callers


def get_xrefs(program: Any, address_or_name: str) -> Optional[Dict[str, Any]]:
    """Get callers+callees for one function. Returns {name, offset, callers, callees}."""
    if program is None:
        return None
    try:
        func = find_function(program, address_or_name)
        if not func:
            return None
        func_manager = program.getFunctionManager()
        ref_manager = program.getReferenceManager()

        func_name = func.getName()
        func_entry = func.getEntryPoint()
        func_offset = func_entry.getOffset() if func_entry else 0

        return {
            "name": func_name,
            "offset": func_offset,
            "callers": get_callers(func, func_manager, ref_manager),
            "callees": get_callees(func, func_manager, ref_manager),
        }
    except Exception as e:
        logger.error(f"Error getting xrefs for {address_or_name}: {e}")
        return None


def get_xrefs_batch(program: Any, addresses: List[str]) -> List[Dict[str, Any]]:
    """Batch get xrefs; failed items are skipped."""
    if program is None:
        return []
    results: List[Dict[str, Any]] = []
    for addr in addresses:
        try:
            xref = get_xrefs(program, addr)
            if xref:
                results.append(xref)
        except Exception as e:
            logger.warning(f"Error getting xrefs for {addr}: {e}")
            continue
    logger.info(f"Got xrefs for {len(results)}/{len(addresses)} functions")
    return results
