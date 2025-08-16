"""
AI Security Models Package
Specialized deep learning models for security vulnerability detection
"""

# Import the Hephaestus Cognitive AI module (Bedrock version)
from .hephaestus_ai_cognitive_bedrock import (
    HephaestusCognitiveAI,
    CognitiveBedrockAnalyzer,
    VulnerabilityChain,
    InnovationPhase
)

__all__ = [
    'HephaestusCognitiveAI',
    'CognitiveBedrockAnalyzer',
    'VulnerabilityChain',
    'InnovationPhase'
]