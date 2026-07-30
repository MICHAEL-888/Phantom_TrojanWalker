"""GhidraAnalyzer: lifecycle + listing operations for binary analysis.

Refactor note: previously a ~818-line god class handling lifecycle, listing,
PE parsing, formatting, decompilation, xrefs, and call-graph building. The
single-responsibility sub-services now live in sibling modules; this module
keeps program lifecycle, listing (functions/exports/strings), metadata assembly,
and delegation to the sub-services.

Bug fixes folded into this refactor:
- open(): wrap self._ctx.__enter__() in try/finally so a partial failure calls
  __exit__ instead of leaking the pyghidra context.
- close(): per-resource try/finally so a closeProgram() failure still runs
  __exit__ and temp-project cleanup.
- bin.os: previously identical to bin.compiler (both returned the compiler spec
  ID); now derived from the executable format (PE->Windows, ELF->Linux, ...).
- analyze(): dropped the dead `level` parameter (Ghidra always does full analysis).
"""
import os
import shutil
import tempfile
import logging
from typing import Any, Dict, List, Optional

try:
    from . import _jvm
    from .formatting import get_sizes
    from .pe_metadata import parse_pe_metadata
    from . import decompile as _decompile_svc
    from . import xrefs as _xref_svc
    from . import callgraph as _callgraph_svc
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    import _jvm
    from formatting import get_sizes
    from pe_metadata import parse_pe_metadata
    import decompile as _decompile_svc
    import xrefs as _xref_svc
    import callgraph as _callgraph_svc

logger = logging.getLogger(__name__)


# Executable format -> OS label. Refactor note: centralized so the metadata
# builder does not duplicate platform heuristics.
_FORMAT_OS_MAP = (
    ("PE", "Windows"),
    ("ELF", "Linux"),
    ("Mach-O", "macOS"),
    ("COFF", "Windows"),
)


def _derive_os(exe_format: Any) -> str:
    if not exe_format:
        return "unknown"
    fmt = str(exe_format).upper()
    for token, os_label in _FORMAT_OS_MAP:
        if token in fmt:
            return os_label
    return "unknown"


class GhidraAnalyzer:
    """Analyzer for binary files using Ghidra/pyghidra.

    Holds program lifecycle and listing operations; decompilation, xrefs, and
    call-graph building are delegated to sibling service modules.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._ctx = None
        self._flat_api = None
        self._program = None
        self._decompiler = None
        self._project_dir = None

    def open(self) -> bool:
        """Initialize Ghidra and open the binary. Returns True on success.

        Refactor note: the pyghidra context manager is now wrapped in try/except
        so a failure after __enter__ still calls __exit__ and releases the JVM
        program handle instead of leaking it.
        """
        try:
            _jvm.ensure_ghidra_started()

            import pyghidra

            self._project_dir = tempfile.mkdtemp(prefix="ghidra_project_")
            project_name = "TempProject"

            self._ctx = pyghidra.open_program(
                self.file_path,
                analyze=False,
                project_location=self._project_dir,
                project_name=project_name,
            )
            try:
                self._flat_api = self._ctx.__enter__()
                self._program = self._flat_api.getCurrentProgram()

                DecompInterface = _jvm.get_decomp_interface_cls()
                DecompileOptions = _jvm.get_decompile_options_cls()
                self._decompiler = DecompInterface()
                options = DecompileOptions()
                options.setWARNCommentIncluded(False)
                options.setHeadCommentIncluded(False)
                options.setPLATECommentIncluded(False)
                options.setPRECommentIncluded(False)
                options.setPOSTCommentIncluded(False)
                options.setEOLCommentIncluded(False)
                self._decompiler.setOptions(options)
                self._decompiler.openProgram(self._program)
            except Exception:
                # Refactor note: ensure the context manager is exited if anything
                # after __enter__ fails, then re-raise to the caller.
                try:
                    self._ctx.__exit__(None, None, None)
                except Exception:
                    pass
                self._ctx = None
                raise

            logger.info(f"Opened binary: {self.file_path}")
            return True

        except Exception as e:
            logger.error(f"Error opening binary with Ghidra: {e}")
            return False

    def analyze(self) -> Dict[str, str]:
        """Execute Ghidra auto-analysis on the opened binary."""
        if not self._program:
            return {"status": "error", "message": "Program not opened"}
        try:
            self._flat_api.analyzeAll(self._program)
            logger.info("Ghidra analysis completed")
            return {"status": "done"}
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {"status": "error", "message": str(e)}

    # ------------------------------------------------------------------
    # Listing operations
    # ------------------------------------------------------------------
    def get_functions(self) -> List[Dict[str, Any]]:
        """List functions: {name, offset, size, signature}."""
        if not self._program:
            return []
        try:
            func_manager = self._program.getFunctionManager()
            functions = []
            for func in func_manager.getFunctions(True):
                entry = func.getEntryPoint()
                body = func.getBody()
                functions.append({
                    "name": func.getName(),
                    "offset": entry.getOffset() if entry else 0,
                    "size": body.getNumAddresses() if body else 0,
                    "signature": func.getSignature().getPrototypeString() if func.getSignature() else "",
                })
            logger.info(f"Found {len(functions)} functions")
            return functions
        except Exception as e:
            logger.error(f"Error getting functions: {e}")
            return []

    def get_exports(self) -> List[Dict[str, Any]]:
        """List export table entries: {name, offset}."""
        if not self._program:
            return []
        try:
            symbol_table = self._program.getSymbolTable()
            func_manager = self._program.getFunctionManager()
            entry_iter = symbol_table.getExternalEntryPointIterator()

            exports = []
            seen = set()
            for addr in entry_iter:
                if not addr:
                    continue
                offset = addr.getOffset()
                export_name = _get_symbol_name_at(symbol_table, addr)
                func = func_manager.getFunctionAt(addr) or func_manager.getFunctionContaining(addr)
                function_name = func.getName() if func else None
                dedupe_key = (offset, export_name, function_name)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                exports.append({"name": export_name, "offset": offset})

            logger.info(f"Found {len(exports)} export entries")
            return exports
        except Exception as e:
            logger.error(f"Error getting exports: {e}")
            return []

    def get_strings(self) -> List[Dict[str, Any]]:
        """List strings: {string, vaddr, section, type, length}."""
        if not self._program:
            return []
        try:
            listing = self._program.getListing()
            strings = []
            for data in listing.getDefinedData(True):
                type_name = _get_data_type_name(data)
                if not _is_string_type(type_name):
                    continue
                str_value = _safe_string_value(data)
                if not str_value:
                    continue
                addr = data.getAddress()
                strings.append({
                    "string": str_value,
                    "vaddr": addr.getOffset() if addr else 0,
                    "section": "",  # Ghidra does not expose section info here
                    "type": type_name,
                    "length": len(str_value),
                })
            logger.info(f"Found {len(strings)} strings")
            return strings
        except Exception as e:
            logger.error(f"Error getting strings: {e}")
            return []

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    def get_info(self) -> Dict[str, Any]:
        """Assemble frontend-compatible metadata (core + bin)."""
        if not self._program:
            return {}
        try:
            lang = self._program.getLanguage()
            compiler_spec = self._program.getCompilerSpec()
            exe_format = self._program.getExecutableFormat()

            file_size, human_size = get_sizes(self.file_path)
            subsys, signed, compiled = parse_pe_metadata(exe_format, self.file_path)

            return _build_info_payload(
                file_path=self.file_path,
                lang=lang,
                compiler_spec=compiler_spec,
                exe_format=exe_format,
                file_size=file_size,
                human_size=human_size,
                subsys=subsys,
                signed=signed,
                compiled=compiled,
            )
        except Exception as e:
            logger.error(f"Error getting info: {e}")
            return {}

    # ------------------------------------------------------------------
    # Delegated services
    # ------------------------------------------------------------------
    def get_decompiled_code(self, address_or_name: str) -> Optional[Dict[str, str]]:
        """Decompile one function. Returns {address, code} or None."""
        return _decompile_svc.decompile_one(self._program, self._decompiler, address_or_name)

    def get_decompiled_code_batch(self, addresses: List[str]) -> List[Dict[str, str]]:
        """Batch decompile; failed items skipped. Returns [{address, code}, ...]."""
        return _decompile_svc.decompile_batch(self._program, self._decompiler, addresses)

    def get_global_call_graph(self) -> Dict[str, Any]:
        """Build {nodes, edges} for the whole program."""
        return _callgraph_svc.build_call_graph(self._program)

    def get_function_xrefs(self, address_or_name: str) -> Optional[Dict[str, Any]]:
        """Get {name, offset, callers, callees} for one function."""
        return _xref_svc.get_xrefs(self._program, address_or_name)

    def get_function_xrefs_batch(self, addresses: List[str]) -> List[Dict[str, Any]]:
        """Batch get xrefs; failed items skipped."""
        return _xref_svc.get_xrefs_batch(self._program, addresses)

    # ------------------------------------------------------------------
    # Lifecycle cleanup
    # ------------------------------------------------------------------
    def close(self):
        """Release all resources.

        Refactor note: each resource is released in its own try/finally so a
        failure in one step does not skip the others. Previously a single try
        wrapped everything, so a closeProgram() exception leaked the pyghidra
        context and the temp project directory.
        """
        if self._decompiler is not None:
            try:
                self._decompiler.closeProgram()
            except Exception as e:
                logger.warning(f"Error closing decompiler: {e}")
            try:
                self._decompiler.dispose()
            except Exception as e:
                logger.warning(f"Error disposing decompiler: {e}")
            self._decompiler = None

        if self._ctx is not None:
            try:
                self._ctx.__exit__(None, None, None)
            except Exception as e:
                logger.warning(f"Error exiting pyghidra context: {e}")
            self._ctx = None
            self._flat_api = None

        self._program = None

        if self._project_dir and os.path.exists(self._project_dir):
            try:
                shutil.rmtree(self._project_dir)
            except Exception as e:
                logger.warning(f"Error removing temp project dir: {e}")
            self._project_dir = None

        logger.info("GhidraAnalyzer closed")

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ------------------------------------------------------------------
# Module-level listing helpers (pure functions on Ghidra Java objects)
# Refactor note: kept at module scope so they are not recreated per instance.
# ------------------------------------------------------------------
def _get_symbol_name_at(symbol_table: Any, addr: Any) -> str:
    """Best-effort symbol name at an address (primary -> any -> str(addr))."""
    try:
        primary = symbol_table.getPrimarySymbol(addr)
        if primary:
            primary_name = primary.getName()
            if primary_name:
                return str(primary_name)
    except Exception:
        pass

    try:
        symbols = symbol_table.getSymbols(addr)
        for sym in symbols:
            name = sym.getName()
            if name:
                return str(name)
    except Exception:
        pass

    try:
        return str(addr)
    except Exception:
        return ""


def _get_data_type_name(data: Any) -> str:
    """Safely get data type name in lowercase."""
    data_type = data.getDataType()
    return data_type.getName().lower() if data_type else ""


def _is_string_type(type_name: str) -> bool:
    return "string" in type_name or "unicode" in type_name


def _safe_string_value(data: Any) -> str:
    """Safely extract a string value from defined data.

    Refactor note: isolates error handling to reduce nesting in callers.
    """
    try:
        value = data.getValue()
        if value is None:
            return ""
        return str(value) or ""
    except Exception:
        return ""


def _build_info_payload(
    *,
    file_path: str,
    lang: Any,
    compiler_spec: Any,
    exe_format: Any,
    file_size: Optional[int],
    human_size: Optional[str],
    subsys: Optional[str],
    signed: Optional[bool],
    compiled: Optional[str],
) -> Dict[str, Any]:
    """Build the frontend-compatible metadata payload."""
    return {
        "core": {
            "file": os.path.basename(file_path),
            "format": exe_format or "unknown",
            "mode": str(lang.getLanguageDescription().getSize()) if lang else "unknown",
            "type": "executable",
            "size": file_size,
            "humansz": human_size,
        },
        "bin": {
            "arch": str(lang.getProcessor()) if lang else "unknown",
            "bits": lang.getLanguageDescription().getSize() if lang else 0,
            "machine": str(lang.getLanguageDescription().getProcessor()) if lang else "unknown",
            "os": _derive_os(exe_format),
            "endian": "little" if (lang and not lang.isBigEndian()) else ("big" if lang else "unknown"),
            "compiler": compiler_spec.getCompilerSpecID().getIdAsString() if compiler_spec else "unknown",
            "subsys": subsys,
            "signed": signed,
            "compiled": compiled,
        },
    }
