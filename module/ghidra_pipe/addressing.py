"""Function name/address resolution.

Refactor note: extracted from GhidraAnalyzer so the parsing and lookup logic is
reusable and testable without a live analyzer. The redundant `(ValueError,
Exception)` clause was collapsed to `Exception`.
"""
from typing import Any, Optional

# Prefixes that carry a hex address suffix.
_HEX_PREFIXED = ("0x", "FUN_", "thunk_FUN_", "fcn.")


def parse_address_value(address_or_name: str) -> Optional[int]:
    """Parse a string into a numeric address value if it looks like one.

    Refactor note: keep parsing errors local and return None to fall back to
    name-based lookup.
    """
    if not address_or_name:
        return None
    try:
        if address_or_name.startswith("0x"):
            return int(address_or_name, 16)
        if address_or_name.startswith("FUN_"):
            return int(address_or_name[4:], 16)
        if address_or_name.startswith("thunk_FUN_"):
            return int(address_or_name[10:], 16)
        if address_or_name.startswith("fcn."):
            # Rizin-style auto-named function (fcn.00401000)
            return int(address_or_name[4:], 16)
    except Exception:
        return None
    return None


def find_function(program: Any, address_or_name: str) -> Optional[Any]:
    """Find a Ghidra function by hex address or case-insensitive name."""
    if program is None:
        return None

    func_manager = program.getFunctionManager()

    addr_val = parse_address_value(address_or_name)
    if addr_val is not None:
        addr_factory = program.getAddressFactory()
        addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)
        func = func_manager.getFunctionAt(addr)
        if func:
            return func
        func = func_manager.getFunctionContaining(addr)
        if func:
            return func

    target_lower = str(address_or_name).lower()
    for func in func_manager.getFunctions(True):
        func_name = func.getName()
        if func_name == address_or_name:
            return func
        if func_name and func_name.lower() == target_lower:
            return func

    return None
