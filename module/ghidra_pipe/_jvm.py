"""JVM/pyghidra bootstrap.

Refactor note: isolate one-time JVM startup and Java class resolution so the
analyzer and its sub-services share a single initialization path. The dead
`_StringDataInstance` cache was removed (string extraction uses data.getValue()
directly, never the StringDataInstance class).
"""
import logging

logger = logging.getLogger(__name__)

_ghidra_started = False
_DecompInterface = None
_DecompileOptions = None
_ConsoleTaskMonitor = None


def ensure_ghidra_started() -> None:
    """Initialize pyghidra/JVM exactly once; cache Java class references."""
    global _ghidra_started, _DecompInterface, _DecompileOptions, _ConsoleTaskMonitor
    if _ghidra_started:
        return

    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx1g", "-Xms512m", "-XX:+UseG1GC")
    launcher.start()

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    _DecompInterface = DecompInterface
    _DecompileOptions = DecompileOptions
    _ConsoleTaskMonitor = ConsoleTaskMonitor
    _ghidra_started = True
    logger.info("Ghidra/pyghidra initialized successfully")


def get_decomp_interface_cls():
    return _DecompInterface


def get_decompile_options_cls():
    return _DecompileOptions


def get_console_task_monitor_cls():
    return _ConsoleTaskMonitor
