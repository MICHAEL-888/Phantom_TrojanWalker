"""Decompilation service.

Refactor note: extracted from GhidraAnalyzer and the duplicated decompile logic
between single and batch is unified into `_decompile_one`. The single-endpoint
return shape now includes `address` for consistency with the batch endpoint.
"""
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from . import _jvm
    from .addressing import find_function
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    import _jvm
    from addressing import find_function

logger = logging.getLogger(__name__)

_DECOMPILE_TIMEOUT_SECONDS = 60
_FALLBACK_CONTEXT_BEFORE = 6
_FALLBACK_CONTEXT_AFTER = 4
_FALLBACK_MAX_STRINGS = 80
_FALLBACK_MAX_CALLS = 120
_FALLBACK_MAX_CHARS = 120_000


def _address_key(address: Any) -> int:
    """Return a stable sortable key for a Ghidra address."""
    try:
        return int(address.getOffset())
    except Exception:
        return 0


def _address_text(address: Any) -> str:
    """Render an address without depending on a particular Java binding."""
    if address is None:
        return "?"
    try:
        return str(address)
    except Exception:
        return "?"


def _instruction_at(listing: Any, address: Any) -> Optional[Any]:
    try:
        instruction = listing.getInstructionAt(address)
        return instruction or listing.getInstructionContaining(address)
    except Exception:
        return None


def _instruction_text(instruction: Any) -> str:
    """Render an instruction using stable Ghidra instruction accessors."""
    try:
        mnemonic = str(instruction.getMnemonicString())
        operands = [
            str(instruction.getDefaultOperandRepresentation(index))
            for index in range(instruction.getNumOperands())
        ]
        return " ".join(part for part in (mnemonic, ", ".join(operands)) if part)
    except Exception:
        try:
            return str(instruction)
        except Exception:
            return "<unprintable instruction>"


def _instruction_line(instruction: Any) -> str:
    try:
        address = instruction.getAddress()
    except Exception:
        address = None
    return f"{_address_text(address)}: {_instruction_text(instruction)}"


def _context(instruction: Any, body: Any, listing: Any) -> List[str]:
    """Return a bounded instruction window that stays inside the function."""
    previous: List[Any] = []
    try:
        current = instruction
        item = current.getPrevious()
        while item is not None and len(previous) < _FALLBACK_CONTEXT_BEFORE:
            if not body.contains(item.getAddress()):
                break
            previous.append(item)
            item = item.getPrevious()
    except Exception:
        previous = []

    lines = [_instruction_line(item) for item in reversed(previous)]
    lines.append("--> " + _instruction_line(instruction))

    try:
        item = instruction.getNext()
        count = 0
        while item is not None and count < _FALLBACK_CONTEXT_AFTER:
            if not body.contains(item.getAddress()):
                break
            lines.append("    " + _instruction_line(item))
            item = item.getNext()
            count += 1
    except Exception:
        pass
    return lines


def _safe_data_value(data: Any) -> Optional[str]:
    try:
        if not data.hasStringValue():
            return None
        value = data.getValue()
        if value is None or not str(value):
            return None
        return str(value)
    except Exception:
        return None


def _string_data(listing: Any, address: Any) -> Optional[Tuple[Any, str]]:
    """Resolve a referenced data item, including one pointer indirection."""
    if address is None:
        return None
    try:
        data = listing.getDataContaining(address)
    except Exception:
        return None
    if data is None:
        return None

    value = _safe_data_value(data)
    if value is not None:
        return data.getAddress(), value

    # Rust and PE import/data layouts sometimes reference a pointer to a string.
    try:
        pointed_address = data.getValue()
        pointed_data = listing.getDataContaining(pointed_address)
    except Exception:
        pointed_data = None
    if pointed_data is None:
        return None
    value = _safe_data_value(pointed_data)
    if value is None:
        return None
    return pointed_data.getAddress(), value


def _reference_sources(body: Any, ref_manager: Any) -> Iterable[Any]:
    """Yield unique source addresses carrying references in a function body."""
    seen = set()
    try:
        sources = ref_manager.getReferenceSourceIterator(body, True)
    except Exception:
        return
    for source in sources:
        key = _address_key(source)
        if key in seen:
            continue
        seen.add(key)
        yield source


def _external_target_text(reference: Any) -> Optional[str]:
    """Best-effort rendering of a Ghidra ExternalReference."""
    try:
        if not reference.isExternalReference():
            return None
    except Exception:
        return None

    location = None
    try:
        location = reference.getExternalLocation()
    except Exception:
        pass

    def get_value(name: str) -> Optional[str]:
        for item in (location, reference):
            if item is None:
                continue
            try:
                value = getattr(item, name)()
                if value:
                    return str(value)
            except Exception:
                continue
        return None

    library = get_value("getLibraryName")
    label = get_value("getLabel")
    if library and label:
        return f"{library}!{label}"
    return label or library


def _external_location_text(program: Any, address: Any) -> Optional[str]:
    try:
        external_manager = program.getExternalManager()
        location = external_manager.getExternalLocation(address)
    except Exception:
        location = None
    if location is None:
        return None
    try:
        library = str(location.getLibraryName() or "")
        label = str(location.getLabel() or "")
    except Exception:
        return None
    if library and label:
        return f"{library}!{label}"
    return label or library or None


def _symbol_target_text(program: Any, address: Any) -> Optional[str]:
    """Resolve an import/data reference through Ghidra's symbol managers."""
    direct = _external_location_text(program, address)
    if direct:
        return direct

    try:
        symbol = program.getSymbolTable().getPrimarySymbol(address)
    except Exception:
        symbol = None
    if symbol is not None:
        try:
            return str(symbol.getName())
        except Exception:
            pass

    # An indirect call commonly references an IAT slot rather than the
    # external address itself. Follow one data pointer to the external symbol.
    try:
        data = program.getListing().getDataContaining(address)
        pointed_address = data.getValue() if data is not None else None
    except Exception:
        pointed_address = None
    return _external_location_text(program, pointed_address)


def _function_target_text(reference: Any, function_manager: Any) -> Optional[str]:
    try:
        target_address = reference.getToAddress()
        target = function_manager.getFunctionAt(target_address)
    except Exception:
        return None
    if target is None:
        return None

    try:
        real = target.getThunkedFunction(True) if target.isThunk() else target
    except Exception:
        real = target
    try:
        name = str(real.getName())
        if real.isExternal():
            return name
        return name
    except Exception:
        return None


def _call_target_text(program: Any, reference: Any, function_manager: Any) -> str:
    external = _external_target_text(reference)
    if external:
        return external

    function_name = _function_target_text(reference, function_manager)
    if function_name:
        try:
            ref_type = reference.getReferenceType()
            if ref_type.isIndirect() or ref_type.isComputed():
                return f"{function_name} (indirect)"
        except Exception:
            pass
        return function_name

    try:
        target_address = reference.getToAddress()
        symbol_name = _symbol_target_text(program, target_address)
        if symbol_name:
            return symbol_name
        target_text = _address_text(target_address)
    except Exception:
        target_text = "?"
    try:
        ref_type = reference.getReferenceType()
        if ref_type.isIndirect() or ref_type.isComputed():
            return f"indirect/unresolved ({target_text})"
    except Exception:
        pass
    return f"unresolved ({target_text})"


def _named_call_target_text(program: Any, reference: Any, function_manager: Any) -> Optional[str]:
    """Return a call target only when Ghidra can attach a symbol name to it."""
    external = _external_target_text(reference)
    if external:
        return external

    function_name = _function_target_text(reference, function_manager)
    if function_name and not _is_anonymous_function_name(function_name):
        return function_name

    try:
        symbol_name = _symbol_target_text(program, reference.getToAddress())
        if symbol_name and not _is_anonymous_function_name(symbol_name):
            return symbol_name
        return None
    except Exception:
        return None


def _is_anonymous_function_name(name: str) -> bool:
    """Identify Ghidra's autogenerated function names."""
    normalized = str(name).lower()
    return normalized.startswith(("fun_", "thunk_fun_", "sub_", "thunk_sub_"))


def _instruction_is_call(instruction: Any) -> bool:
    try:
        return bool(instruction.getFlowType().isCall())
    except Exception:
        return False


def _body_instructions(body: Any, listing: Any) -> Iterable[Any]:
    """Yield each defined instruction in a function body once."""
    seen = set()
    try:
        addresses = body.getAddresses(True)
    except Exception:
        return
    for address in addresses:
        instruction = _instruction_at(listing, address)
        if instruction is None:
            continue
        key = _address_key(instruction.getAddress())
        if key in seen:
            continue
        seen.add(key)
        yield instruction


def _append_bounded(lines: List[str], line: str, total: List[int]) -> bool:
    """Append one line unless the fallback character budget is exhausted."""
    remaining = _FALLBACK_MAX_CHARS - total[0]
    if remaining <= 0:
        return False
    if len(line) + 1 > remaining:
        lines.append(line[: max(0, remaining - 1)] + "...")
        total[0] = _FALLBACK_MAX_CHARS
        return False
    lines.append(line)
    total[0] += len(line) + 1
    return True


def _decompilation_timed_out(decompiler: Any, results: Any) -> bool:
    """Use the explicit result flag, with a compatibility diagnostic fallback."""
    if results is not None:
        try:
            if results.decompileCompleted():
                return False
        except Exception:
            return False

        try:
            timed_out = getattr(results, "isTimedOut")
        except Exception:
            timed_out = None
        if callable(timed_out):
            try:
                return bool(timed_out())
            except Exception:
                pass
        else:
            try:
                result_message = str(results.getErrorMessage() or "").lower()
            except Exception:
                result_message = ""
            return "timeout" in result_message or "timed out" in result_message

    try:
        message = str(decompiler.getLastMessage() or "").lower()
    except Exception:
        return False
    return "timeout" in message or "timed out" in message


def _timeout_fallback(program: Any, func: Any) -> str:
    """Build an ordered mixed evidence stream after a decompilation timeout."""
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()
    body = func.getBody()

    # Keep one event per source instruction. This is important when Ghidra
    # exposes multiple Reference objects for one instruction or one string.
    events: Dict[int, Dict[str, Any]] = {}
    seen_strings = set()
    sources = list(_reference_sources(body, ref_manager))
    sources.sort(key=_address_key)
    for source in sources:
        try:
            references = ref_manager.getReferencesFrom(source)
        except Exception:
            continue
        source_key = _address_key(source)
        event = events.setdefault(source_key, {"source": source, "strings": [], "calls": []})
        for reference in references:
            try:
                reference_type = reference.getReferenceType()
                is_call = reference_type.isCall()
            except Exception:
                continue
            if is_call:
                target = _named_call_target_text(program, reference, function_manager)
                if target and target not in event["calls"]:
                    event["calls"].append(target)
                continue
            try:
                resolved = _string_data(listing, reference.getToAddress())
            except Exception:
                resolved = None
            if resolved is None:
                continue
            data_address, value = resolved
            string_key = (_address_key(data_address), value)
            if string_key in seen_strings:
                continue
            seen_strings.add(string_key)
            event["strings"].append((data_address, value))

    # Calls through an IAT or a register can have only DATA references. The
    # instruction flow type still identifies the operation as a call, so do
    # not rely solely on ReferenceType.isCall().
    for instruction in _body_instructions(body, listing):
        if not _instruction_is_call(instruction):
            continue
        source = instruction.getAddress()
        source_key = _address_key(source)
        event = events.setdefault(source_key, {"source": source, "strings": [], "calls": []})
        try:
            references = ref_manager.getReferencesFrom(source)
        except Exception:
            references = []
        for reference in references:
            target = _named_call_target_text(program, reference, function_manager)
            if target and target not in event["calls"]:
                event["calls"].append(target)

    lines: List[str] = []
    total = [0]
    try:
        function_name = str(func.getName())
    except Exception:
        function_name = "?"
    try:
        entry = _address_text(func.getEntryPoint())
    except Exception:
        entry = "?"
    try:
        body_size = body.getNumAddresses()
    except Exception:
        body_size = "?"

    for line in (
        "[GHIDRA FALLBACK: decompilation timed out]",
        f"function: {function_name} @ {entry}",
        f"body_addresses: {body_size}",
        "",
        "Ordered evidence (by instruction address):",
    ):
        if not _append_bounded(lines, line, total):
            return "\n".join(lines)

    string_count = 0
    call_count = 0
    context_count = 0
    for source_key in sorted(events):
        event = events[source_key]
        if not event["strings"] and not event["calls"]:
            continue
        source = event["source"]
        if string_count >= _FALLBACK_MAX_STRINGS and event["strings"]:
            event["strings"] = []
        if call_count >= _FALLBACK_MAX_CALLS and event["calls"]:
            event["calls"] = []
        if not event["strings"] and not event["calls"]:
            break
        instruction = _instruction_at(listing, source)
        if instruction is None:
            continue
        if not _append_bounded(lines, f"\n--- evidence @ {_address_text(source)} ---", total):
            break
        for address, value in event["strings"]:
            if string_count >= _FALLBACK_MAX_STRINGS:
                break
            if not _append_bounded(
                lines, f"  STRING {_address_text(address)}: {value!r}", total
            ):
                break
            string_count += 1
        if event["calls"] and call_count < _FALLBACK_MAX_CALLS:
            if not _append_bounded(lines, f"  FUNCTION: {', '.join(event['calls'])}", total):
                break
            call_count += len(event["calls"])
        if not _append_bounded(lines, "  assembly:", total):
            break
        for context_line in _context(instruction, body, listing):
            if not _append_bounded(lines, "    " + context_line, total):
                break
        context_count += 1

    if string_count >= _FALLBACK_MAX_STRINGS:
        _append_bounded(lines, "... remaining strings omitted", total)
    if call_count >= _FALLBACK_MAX_CALLS:
        _append_bounded(lines, "... remaining named function calls omitted", total)
    if context_count >= _FALLBACK_MAX_CALLS:
        _append_bounded(lines, "... remaining contexts omitted", total)

    return "\n".join(lines)


def _decompile_one(program: Any, decompiler: Any, func: Any, monitor: Any) -> Optional[str]:
    """Decompile a single function; return C source or None."""
    try:
        results = decompiler.decompileFunction(func, _DECOMPILE_TIMEOUT_SECONDS, monitor)
        if results and results.decompileCompleted():
            decomp_func = results.getDecompiledFunction()
            if decomp_func:
                code = decomp_func.getC()
                if code:
                    return code
        if _decompilation_timed_out(decompiler, results):
            return _timeout_fallback(program, func)
    except Exception as e:
        logger.warning(f"Error decompiling function: {e}")
    return None


def decompile_one(program: Any, decompiler: Any, address_or_name: str) -> Optional[Dict[str, str]]:
    """Decompile a single function by name or address.

    Returns {"address": ..., "code": ...} or None. Refactor note: include
    `address` to align the shape with the batch endpoint.
    """
    if program is None or decompiler is None:
        return None
    try:
        func = find_function(program, address_or_name)
        if not func:
            return None
        monitor = _jvm.get_console_task_monitor_cls()()
        code = _decompile_one(program, decompiler, func, monitor)
        if code is None:
            return None
        return {"address": address_or_name, "code": code}
    except Exception as e:
        logger.error(f"Error decompiling {address_or_name}: {e}")
        return None


def decompile_batch(program: Any, decompiler: Any, addresses: List[str]) -> List[Dict[str, str]]:
    """Batch decompile; failed items are skipped (missing-item semantics)."""
    if program is None or decompiler is None:
        return []

    results: List[Dict[str, str]] = []
    monitor = _jvm.get_console_task_monitor_cls()()

    for addr in addresses:
        try:
            func = find_function(program, addr)
            if not func:
                continue
            code = _decompile_one(program, decompiler, func, monitor)
            if code:
                results.append({"address": addr, "code": code})
        except Exception as e:
            logger.warning(f"Error decompiling {addr}: {e}")
            continue

    logger.info(f"Decompiled {len(results)}/{len(addresses)} functions")
    return results
