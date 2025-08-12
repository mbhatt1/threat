"""
MCP Tool implementation
"""
from typing import Dict, Any, Callable, Optional, List
from dataclasses import dataclass, asdict
import inspect


@dataclass
class ToolParameter:
    """Parameter definition for a tool"""
    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None


@dataclass 
class Tool:
    """
    Represents a callable tool in the MCP framework
    """
    name: str
    description: str
    handler: Callable
    parameters: List[ToolParameter] = None
    
    def __post_init__(self):
        """Initialize parameters from handler if not provided"""
        if self.parameters is None:
            self.parameters = self._extract_parameters()
            
    def _extract_parameters(self) -> List[ToolParameter]:
        """Extract parameters from handler function signature"""
        params = []
        sig = inspect.signature(self.handler)
        
        for name, param in sig.parameters.items():
            if name == 'self':
                continue
                
            param_type = 'any'
            if param.annotation != inspect.Parameter.empty:
                param_type = param.annotation.__name__ if hasattr(param.annotation, '__name__') else str(param.annotation)
                
            required = param.default == inspect.Parameter.empty
            default = None if required else param.default
            
            params.append(ToolParameter(
                name=name,
                type=param_type,
                description=f"Parameter {name}",
                required=required,
                default=default
            ))
            
        return params
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert tool to dictionary representation"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": [asdict(p) for p in self.parameters]
        }
        
    async def __call__(self, **kwargs) -> Any:
        """Make tool callable"""
        # If handler is async, await it
        if inspect.iscoroutinefunction(self.handler):
            return await self.handler(**kwargs)
        else:
            return self.handler(**kwargs)


class ToolCall:
    """Represents a request to call a tool"""
    
    def __init__(self, tool_name: str, arguments: Dict[str, Any]):
        self.tool_name = tool_name
        self.arguments = arguments
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments
        }


class ToolResponse:
    """Represents a response from a tool call"""
    
    def __init__(self, success: bool, result: Any = None, error: Optional[str] = None):
        self.success = success
        self.result = result
        self.error = error
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {"success": self.success}
        if self.result is not None:
            data["result"] = self.result
        if self.error is not None:
            data["error"] = self.error
        return data