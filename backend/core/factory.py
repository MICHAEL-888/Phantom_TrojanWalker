import sys
import os


def _ensure_agents_on_path() -> None:
    """Ensure agents module can be found when imported from backend.

    Refactor note: keep path setup in one place for maintainability. root_dir
    enables `from agents.x import ...` (package mode); agents_dir enables bare
    imports used inside agents/ modules (e.g. `from config_loader import ...`).
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    if root_dir not in sys.path:
        sys.path.append(root_dir)
    agents_dir = os.path.join(root_dir, "agents")
    if agents_dir not in sys.path:
        sys.path.append(agents_dir)


_ensure_agents_on_path()

from agents.config_loader import load_config
from agents.agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
from agents.ghidra_client import GhidraClient
from agents.analysis_coordinator import AnalysisCoordinator


def create_coordinator() -> AnalysisCoordinator:
    """Build the AnalysisCoordinator with dependency-injected agents.

    Refactor note: agents now receive AppConfig via DI (consistent with
    GhidraClient) instead of calling load_config() internally, so config.yaml
    is loaded exactly once here.
    """
    config = load_config("agents/config.yaml")

    ghidra_client = GhidraClient(config=config)
    func_agent = FunctionAnalysisAgent(config=config)
    malware_agent = MalwareAnalysisAgent(config=config)

    return AnalysisCoordinator(ghidra_client, func_agent, malware_agent)
