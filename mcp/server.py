"""
MCP Server implementation
"""
import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Configuration for MCP Server"""
    name: str
    version: str = "1.0.0"
    description: str = ""
    max_connections: int = 100
    timeout: int = 300


class Server:
    """
    MCP Server for handling tool and resource requests
    """
    
    def __init__(self, config: Optional[ServerConfig] = None):
        self.config = config or ServerConfig(name="MCP Server")
        self.tools: Dict[str, 'Tool'] = {}
        self.resources: Dict[str, 'Resource'] = {}
        self._handlers: Dict[str, Callable] = {}
        self._running = False
        
    def register_tool(self, tool: 'Tool') -> None:
        """Register a tool with the server"""
        self.tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name}")
        
    def register_resource(self, resource: 'Resource') -> None:
        """Register a resource with the server"""
        self.resources[resource.uri] = resource
        logger.info(f"Registered resource: {resource.uri}")
        
    def add_handler(self, event: str, handler: Callable) -> None:
        """Add an event handler"""
        self._handlers[event] = handler
        
    async def start(self, host: str = "localhost", port: int = 8080) -> None:
        """Start the MCP server"""
        self._running = True
        logger.info(f"Starting MCP server on {host}:{port}")
        
        # In a real implementation, this would start an actual server
        # For now, it's a placeholder that runs until stopped
        while self._running:
            await asyncio.sleep(1)
            
    async def stop(self) -> None:
        """Stop the MCP server"""
        self._running = False
        logger.info("Stopping MCP server")
        
    async def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a tool call request"""
        if tool_name not in self.tools:
            return {
                "error": f"Tool '{tool_name}' not found",
                "available_tools": list(self.tools.keys())
            }
            
        tool = self.tools[tool_name]
        try:
            result = await tool.handler(**arguments)
            return {
                "success": True,
                "result": result
            }
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
            
    async def handle_resource_request(self, uri: str) -> Dict[str, Any]:
        """Handle a resource request"""
        if uri not in self.resources:
            return {
                "error": f"Resource '{uri}' not found",
                "available_resources": list(self.resources.keys())
            }
            
        resource = self.resources[uri]
        try:
            content = await resource.handler()
            return {
                "success": True,
                "content": content
            }
        except Exception as e:
            logger.error(f"Error accessing resource {uri}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
            
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools"""
        return [tool.to_dict() for tool in self.tools.values()]
        
    def list_resources(self) -> List[Dict[str, Any]]:
        """List all registered resources"""
        return [resource.to_dict() for resource in self.resources.values()]