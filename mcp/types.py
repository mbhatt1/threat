"""
MCP Types for content representation
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class Content:
    """Base class for content types"""
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TextContent(Content):
    """Text content representation"""
    text: str
    mime_type: str = "text/plain"
    
    def __str__(self) -> str:
        return self.text


@dataclass
class ImageContent(Content):
    """Image content representation"""
    data: str  # Base64 encoded image data
    mime_type: str = "image/png"
    alt_text: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {"data": self.data, "mime_type": self.mime_type}
        if self.alt_text:
            data["alt_text"] = self.alt_text
        return data


@dataclass
class JSONContent(Content):
    """JSON content representation"""
    data: Dict[str, Any]
    mime_type: str = "application/json"
    
    def to_dict(self) -> Dict[str, Any]:
        return {"data": self.data, "mime_type": self.mime_type}