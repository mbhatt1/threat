"""
MCP Resource implementation
"""
from typing import Dict, Any, Callable, Optional
from dataclasses import dataclass, asdict


@dataclass
class Resource:
    """
    Represents a data resource in the MCP framework
    """
    uri: str
    name: str
    description: str
    handler: Callable
    mime_type: str = "application/json"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary representation"""
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mime_type": self.mime_type
        }
        
    async def __call__(self) -> Any:
        """Make resource callable"""
        import inspect
        if inspect.iscoroutinefunction(self.handler):
            return await self.handler()
        else:
            return self.handler()