"""AURA — AI-agent security and execution-enforcement layer."""

from __future__ import annotations

# Automatically load environment variables from .env if python-dotenv is installed
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

__version__ = "0.1.0"

