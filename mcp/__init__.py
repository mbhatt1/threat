"""
MCP (Model Context Protocol) SDK
Simple implementation for AI security scanning integration
"""

from .server import Server
from .tools import Tool
from .resources import Resource

__version__ = "0.1.0"
__all__ = ["Server", "Tool", "Resource"]