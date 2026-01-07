import sys
import os

# Ensure agents module can be found
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)
AGENTS_DIR = os.path.join(ROOT_DIR, "agents")
if AGENTS_DIR not in sys.path:
    sys.path.append(AGENTS_DIR)

from agents.config_loader import load_config
from agents.agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
from agents.rizin_client import RizinClient
from agents.analysis_coordinator import AnalysisCoordinator

def create_coordinator() -> AnalysisCoordinator:
    config = load_config("agents/config.yaml")

    rizin_client = RizinClient(config=config)
    
    # Initialize agents (they load config internally in current implementation)
    func_agent = FunctionAnalysisAgent()
    malware_agent = MalwareAnalysisAgent()
    
    return AnalysisCoordinator(rizin_client, func_agent, malware_agent)
