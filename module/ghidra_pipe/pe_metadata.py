"""PE-specific metadata extraction.

Refactor note: extracted from GhidraAnalyzer as a self-contained parser so the
analyzer does not carry PE/Java format knowledge. The IMAGE_DIRECTORY_ENTRY_SECURITY
index (4) is now documented inline.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# PE optional header data directory index for the security/certificate table.
# See IMAGE_DIRECTORY_ENTRY_SECURITY in winnt.h.
_IMAGE_DIRECTORY_ENTRY_SECURITY = 4

_SUBSYSTEM_MAP = {
    1: "Native", 2: "Windows GUI", 3: "Windows CUI",
    5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
    10: "EFI App", 11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver", 13: "EFI ROM",
    14: "XBOX", 16: "Windows Boot App",
}


def parse_pe_metadata(exe_format: Any, file_path: str) -> tuple[Optional[str], Optional[bool], Optional[str]]:
    """Extract (subsystem, signed, compiled_timestamp) if the binary is PE.

    Returns (None, None, None) for non-PE binaries. Failures are logged and
    treated as "no PE metadata" rather than propagated.
    """
    subsys = None
    signed = None
    compiled = None

    if not exe_format or "PE" not in str(exe_format).upper():
        return subsys, signed, compiled

    try:
        from java.io import File
        from ghidra.app.util.bin import RandomAccessByteProvider
        from ghidra.app.util.bin.format.pe import PortableExecutable

        provider = RandomAccessByteProvider(File(file_path), "r")
        try:
            pe = PortableExecutable(provider, PortableExecutable.SectionLayout.FILE)
            nt = pe.getNTHeader()
            if nt is None:
                return subsys, signed, compiled

            file_header = nt.getFileHeader()
            optional_header = nt.getOptionalHeader()

            if file_header is not None:
                ts = file_header.getTimeDateStamp()
                if ts:
                    compiled = datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()

            if optional_header is None:
                return subsys, signed, compiled

            subsys = _map_subsystem(optional_header.getSubsystem())
            signed = _is_pe_signed(optional_header)
            return subsys, signed, compiled
        finally:
            try:
                provider.close()
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Error parsing PE headers: {e}")
        return subsys, signed, compiled


def _map_subsystem(subsys_val: Any) -> str:
    return _SUBSYSTEM_MAP.get(subsys_val, str(subsys_val))


def _is_pe_signed(optional_header: Any) -> Optional[bool]:
    data_dirs = optional_header.getDataDirectories()
    if not data_dirs or len(data_dirs) <= _IMAGE_DIRECTORY_ENTRY_SECURITY:
        return False
    sec_dir = data_dirs[_IMAGE_DIRECTORY_ENTRY_SECURITY]
    try:
        return (sec_dir.getSize() or 0) > 0
    except Exception:
        return False
