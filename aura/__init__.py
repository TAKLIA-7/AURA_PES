"""
AURA — AI Agent Security, Authorization, Execution Enforcement, and Audit Platform.

Multi-agent security enforcement system built with LangChain + LangGraph.
"""

from pathlib import Path

try:
    from dotenv import load_dotenv

    # Load .env from project root or current working directory
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    load_dotenv()
except ImportError:
    pass

__version__ = "0.1.0"

