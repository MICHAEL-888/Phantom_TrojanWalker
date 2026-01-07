import os
import sys

# Add root and agents directory to path BEFORE other imports
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)
AGENTS_DIR = os.path.join(ROOT_DIR, "agents")
if AGENTS_DIR not in sys.path:
    sys.path.append(AGENTS_DIR)

import uvicorn
import logging

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8001, reload=True)
