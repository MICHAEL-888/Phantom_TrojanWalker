import sys
import os
from agents.config_loader import load_config
from agents.agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
from agents.rizin_client import RizinClient
from agents.analysis_coordinator import AnalysisCoordinator

# Ensure agents module can be found if running from subfolder
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.append(ROOT_DIR)
sys.path.append(os.path.join(ROOT_DIR, "agents"))


def create_coordinator() -> AnalysisCoordinator:
    config = load_config("agents/config.yaml")

    rizin_client = RizinClient(base_url=config.rizin_backend.url)
    
    # Initialize agents
    func_agent = FunctionAnalysisAgent(config)
    malware_agent = MalwareAnalysisAgent(config)
    
    return AnalysisCoordinator(rizin_client, func_agent, malware_agent)
