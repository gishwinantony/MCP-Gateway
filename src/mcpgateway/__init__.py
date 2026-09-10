"""mcp-gateway: a security and context-control layer in front of MCP servers."""

from .config import GatewayConfig
from .gateway import Gateway, Session
from .policy import PolicyEngine, Principal
from .registry import ToolRegistry
from .retrieval import ToolIndex
from .scanner import ToolScanner, Verdict

__version__ = "0.1.0"
__all__ = [
    "Gateway",
    "GatewayConfig",
    "PolicyEngine",
    "Principal",
    "Session",
    "ToolIndex",
    "ToolRegistry",
    "ToolScanner",
    "Verdict",
]
