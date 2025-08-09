"""
AI Explainability and Evidence Engine
Provides detailed reasoning, confidence calibration, and audit trails for AI findings
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import numpy as np
from pathlib import Path
import boto3
from decimal import Decimal
import os

logger = logging.getLogger(__name__)

# DynamoDB client
dynamodb = boto3.resource('dynamodb')

class ConfidenceLevel(Enum):
    """AI confidence levels with calibrated thresholds"""
    VERY_HIGH = "very_high"    # >0.95 - Almost certain
    HIGH = "high"               # 0.85-0.95 - Confident
    MEDIUM = "medium"           # 0.70-0.85 - Probable
    LOW = "low"                 # 0.50-0.70 - Possible
    VERY_LOW = "very_low"       # <0.50 - Uncertain
    
    @classmethod
    def from_score(cls, score: float) -> 'ConfidenceLevel':
        """Get confidence level from numerical score"""
        if score > 0.95:
            return cls.VERY_HIGH
        elif score > 0.85:
            return cls.HIGH
        elif score > 0.70:
            return cls.MEDIUM
        elif score > 0.50:
            return cls.LOW
        else:
            return cls.VERY_LOW

@dataclass
class Evidence:
    """Evidence supporting an AI finding"""
    type: str  # pattern_match, semantic_analysis, context_clue, statistical
    description: str
    confidence_contribution: float  # How much this evidence contributes to confidence
    source_lines: List[int] = None
    related_code: str = None
    reasoning: str = None
    
    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB-compatible format"""
        item = {
            'type': self.type,
            'description': self.description,
            'confidence_contribution': Decimal(str(self.confidence_contribution))
        }
        if self.source_lines:
            item['source_lines'] = self.source_lines
        if self.related_code:
            item['related_code'] = self.related_code
        if self.reasoning:
            item['reasoning'] = self.reasoning
        return item

@dataclass
class AIFindingExplanation:
    """Complete explanation for an AI-generated finding"""
    finding_id: str
    ai_model: str
    confidence_score: float
    confidence_level: ConfidenceLevel
    evidence_list: List[Evidence]
    reasoning_chain: List[str]  # Step-by-step reasoning
    similar_patterns: List[Dict[str, Any]]  # Similar issues found elsewhere
    false_positive_indicators: List[str]
    human_readable_explanation: str
    tokens_analyzed: int
    processing_time_ms: int
    comparison_with_tools: Optional[Dict[str, Any]] = None

class AIExplainabilityEngine:
    """
    Provides explainability, evidence tracking, and confidence calibration for AI findings
    """
    
    def __init__(self):
        # Initialize DynamoDB tables
        self.ai_decisions_table = dynamodb.Table(
            os.environ.get('AI_DECISIONS_TABLE', 'SecurityAuditAIDecisions')
        )
        self.confidence_calibration_table = dynamodb.Table(
            os.environ.get('CONFIDENCE_CALIBRATION_TABLE', 'SecurityAuditConfidenceCalibration')
        )
        self.tool_comparisons_table = dynamodb.Table(
            os.environ.get('TOOL_COMPARISONS_TABLE', 'SecurityAuditToolComparisons')
        )
        
        # Cache for confidence calibration data
        self._calibration_cache = {}
        self._cache_ttl = 3600  # 1 hour
        self._last_cache_update = datetime.utcnow()
    
    def generate_explanation(self, 
                           finding: Dict[str, Any],
                           ai_response: str,
                           model_id: str,
                           processing_time_ms: int,
                           tokens_used: int) -> AIFindingExplanation:
        """
        Generate detailed explanation for an AI finding
        """
        finding_id = self._generate_finding_id(finding)
        
        # Extract evidence from AI response
        evidence_list = self._extract_evidence(finding, ai_response)
        
        # Calculate calibrated confidence
        raw_confidence = finding.get('confidence', 0.85)
        calibrated_confidence = self._calibrate_confidence(raw_confidence, model_id)
        confidence_level = ConfidenceLevel.from_score(calibrated_confidence)
        
        # Extract reasoning chain
        reasoning_chain = self._extract_reasoning_chain(ai_response)
        
        # Identify similar patterns
        similar_patterns = self._find_similar_patterns(finding)
        
        # Check for false positive indicators
        false_positive_indicators = self._identify_false_positive_indicators(finding, evidence_list)
        
        # Generate human-readable explanation
        human_explanation = self._generate_human_explanation(
            finding, evidence_list, reasoning_chain, confidence_level
        )
        
        # Create explanation object
        explanation = AIFindingExplanation(
            finding_id=finding_id,
            ai_model=model_id,
            confidence_score=calibrated_confidence,
            confidence_level=confidence_level,
            evidence_list=evidence_list,
            reasoning_chain=reasoning_chain,
            similar_patterns=similar_patterns,
            false_positive_indicators=false_positive_indicators,
            human_readable_explanation=human_explanation,
            tokens_analyzed=tokens_used,
            processing_time_ms=processing_time_ms
        )
        
        # Store in audit trail
        self._store_ai_decision(explanation, finding)
        
        return explanation
    
    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique ID for finding"""
        key_parts = [
            finding.get('file', ''),
            str(finding.get('line', 0)),
            finding.get('type', ''),
            finding.get('message', '')[:50]
        ]
        return hashlib.sha256('|'.join(key_parts).encode()).hexdigest()[:16]
    
    def _extract_evidence(self, finding: Dict[str, Any], ai_response: str) -> List[Evidence]:
        """Extract evidence from AI response"""
        evidence_list = []
        
        # Pattern matching evidence
        if 'pattern' in finding or 'code_snippet' in finding:
            evidence_list.append(Evidence(
                type='pattern_match',
                description='Direct pattern match found in code',
                confidence_contribution=0.4,
                related_code=finding.get('code_snippet', ''),
                source_lines=[finding.get('line', 0)]
            ))
        
        # Semantic analysis evidence
        if 'semantic' in ai_response.lower() or 'understand' in ai_response.lower():
            evidence_list.append(Evidence(
                type='semantic_analysis',
                description='AI semantic understanding of code logic',
                confidence_contribution=0.3,
                reasoning='AI analyzed the code semantics and data flow'
            ))
        
        # Context clues
        if 'context' in ai_response.lower() or finding.get('file', '').endswith(('.py', '.js', '.java')):
            evidence_list.append(Evidence(
                type='context_clue',
                description='Contextual indicators from file type and structure',
                confidence_contribution=0.2,
                reasoning=f"File type {Path(finding.get('file', '')).suffix} suggests vulnerability pattern"
            ))
        
        # Statistical evidence
        if 'common' in ai_response.lower() or 'frequently' in ai_response.lower():
            evidence_list.append(Evidence(
                type='statistical',
                description='Statistical correlation with known vulnerabilities',
                confidence_contribution=0.1,
                reasoning='Pattern statistically correlated with security issues'
            ))
        
        return evidence_list
    
    def _calibrate_confidence(self, raw_confidence: float, model_id: str) -> float:
        """
        Calibrate confidence score based on historical accuracy
        """
        # Check cache
        if self._should_refresh_cache():
            self._refresh_calibration_cache(model_id)
        
        # Find calibration data for this confidence range
        confidence_range = int(raw_confidence * 10) / 10  # Round to nearest 0.1
        calibration_key = f"{model_id}_{confidence_range}"
        
        if calibration_key in self._calibration_cache:
            calibration_data = self._calibration_cache[calibration_key]
            actual_accuracy = calibration_data.get('actual_accuracy', raw_confidence)
            
            # Apply calibration
            # If model is overconfident, reduce confidence
            # If model is underconfident, increase confidence
            calibration_factor = actual_accuracy / raw_confidence if raw_confidence > 0 else 1.0
            calibrated = raw_confidence * calibration_factor
            
            return max(0.0, min(1.0, calibrated))
        
        return raw_confidence
    
    def _should_refresh_cache(self) -> bool:
        """Check if calibration cache should be refreshed"""
        return (datetime.utcnow() - self._last_cache_update).seconds > self._cache_ttl
    
    def _refresh_calibration_cache(self, model_id: str):
        """Refresh calibration cache from DynamoDB"""
        try:
            response = self.confidence_calibration_table.query(
                KeyConditionExpression='model = :model',
                ExpressionAttributeValues={':model': model_id}
            )
            
            self._calibration_cache.clear()
            for item in response.get('Items', []):
                cache_key = f"{item['model']}_{item['confidence_range_start']}"
                self._calibration_cache[cache_key] = {
                    'actual_accuracy': float(item.get('actual_accuracy', 0.8)),
                    'sample_count': item.get('sample_count', 0)
                }
            
            self._last_cache_update = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Failed to refresh calibration cache: {e}")
    
    def _extract_reasoning_chain(self, ai_response: str) -> List[str]:
        """Extract step-by-step reasoning from AI response"""
        reasoning_steps = []
        
        # Look for numbered steps or bullet points
        import re
        
        # Pattern for numbered steps
        numbered_pattern = r'(\d+[\.\)]\s*[^\n]+)'
        numbered_matches = re.findall(numbered_pattern, ai_response)
        if numbered_matches:
            reasoning_steps.extend(numbered_matches)
        
        # Pattern for bullet points
        bullet_pattern = r'[\*\-]\s*([^\n]+)'
        bullet_matches = re.findall(bullet_pattern, ai_response)
        if bullet_matches and not numbered_matches:
            reasoning_steps.extend(bullet_matches)
        
        # If no structured reasoning found, extract key sentences
        if not reasoning_steps:
            sentences = ai_response.split('.')
            key_sentences = [s.strip() for s in sentences if any(
                keyword in s.lower() for keyword in 
                ['found', 'detected', 'identified', 'vulnerable', 'risk', 'issue']
            )]
            reasoning_steps = key_sentences[:5]  # Limit to 5 steps
        
        return reasoning_steps
    
    def _find_similar_patterns(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar patterns in historical findings"""
        similar_patterns = []
        
        try:
            # Query recent findings of same type
            response = self.ai_decisions_table.query(
                IndexName='FindingTypeIndex',  # Assuming this GSI exists
                KeyConditionExpression='finding_type = :type',
                ExpressionAttributeValues={
                    ':type': finding.get('type', 'unknown')
                },
                Limit=10,
                ScanIndexForward=False  # Most recent first
            )
            
            for item in response.get('Items', []):
                if item.get('finding_id') != finding.get('finding_id'):
                    similar_patterns.append({
                        'finding_id': item.get('finding_id'),
                        'file': item.get('file_path'),
                        'confidence': float(item.get('confidence_score', 0)),
                        'timestamp': item.get('timestamp')
                    })
            
        except Exception as e:
            logger.error(f"Failed to find similar patterns: {e}")
        
        return similar_patterns[:5]  # Return top 5
    
    def _identify_false_positive_indicators(self, 
                                          finding: Dict[str, Any], 
                                          evidence_list: List[Evidence]) -> List[str]:
        """Identify potential false positive indicators"""
        indicators = []
        
        # Low confidence
        if finding.get('confidence', 1.0) < 0.7:
            indicators.append("Low AI confidence score")
        
        # Test file
        file_path = finding.get('file', '').lower()
        if any(test_indicator in file_path for test_indicator in ['test', 'spec', 'mock']):
            indicators.append("Finding in test file")
        
        # Comment or documentation
        if finding.get('in_comment', False):
            indicators.append("Code in comment block")
        
        # Low evidence
        total_evidence_weight = sum(e.confidence_contribution for e in evidence_list)
        if total_evidence_weight < 0.5:
            indicators.append("Insufficient supporting evidence")
        
        # Known false positive patterns
        known_fp_patterns = [
            'example', 'sample', 'demo', 'tutorial', 'template'
        ]
        if any(pattern in file_path for pattern in known_fp_patterns):
            indicators.append("File appears to be example/demo code")
        
        return indicators
    
    def _generate_human_explanation(self, 
                                  finding: Dict[str, Any],
                                  evidence_list: List[Evidence],
                                  reasoning_chain: List[str],
                                  confidence_level: ConfidenceLevel) -> str:
        """Generate human-readable explanation"""
        explanation_parts = []
        
        # Start with what was found
        explanation_parts.append(
            f"I detected a {finding.get('severity', 'potential')} "
            f"{finding.get('type', 'security issue')} in {finding.get('file', 'the code')} "
            f"at line {finding.get('line', 'unknown')}."
        )
        
        # Explain confidence
        confidence_explanations = {
            ConfidenceLevel.VERY_HIGH: "I am very confident about this finding",
            ConfidenceLevel.HIGH: "I am confident about this finding",
            ConfidenceLevel.MEDIUM: "I believe this is likely a real issue",
            ConfidenceLevel.LOW: "This is a possible issue that needs verification",
            ConfidenceLevel.VERY_LOW: "This is uncertain and requires manual review"
        }
        explanation_parts.append(confidence_explanations.get(confidence_level, ""))
        
        # Explain evidence
        explanation_parts.append("\nMy analysis is based on:")
        for i, evidence in enumerate(evidence_list[:3], 1):
            explanation_parts.append(f"{i}. {evidence.description}")
        
        # Add reasoning summary
        if reasoning_chain:
            explanation_parts.append("\nReasoning process:")
            explanation_parts.append(reasoning_chain[0])
        
        # Add recommendation
        explanation_parts.append(
            f"\nRecommendation: {finding.get('remediation', 'Review and fix this security issue')}"
        )
        
        return "\n".join(explanation_parts)
    
    def _store_ai_decision(self, explanation: AIFindingExplanation, finding: Dict[str, Any]):
        """Store AI decision in DynamoDB audit trail"""
        try:
            item = {
                'finding_id': explanation.finding_id,
                'timestamp': datetime.utcnow().isoformat(),
                'ai_model': explanation.ai_model,
                'confidence_score': Decimal(str(explanation.confidence_score)),
                'confidence_level': explanation.confidence_level.value,
                'evidence_json': json.dumps([asdict(e) for e in explanation.evidence_list]),
                'reasoning_json': json.dumps(explanation.reasoning_chain),
                'tokens_used': explanation.tokens_analyzed,
                'processing_time_ms': explanation.processing_time_ms,
                'finding_type': finding.get('type', 'unknown'),
                'finding_severity': finding.get('severity', 'MEDIUM'),
                'file_path': finding.get('file', ''),
                'false_positive_indicators': explanation.false_positive_indicators,
                'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())  # 90 day retention
            }
            
            self.ai_decisions_table.put_item(Item=item)
            
        except Exception as e:
            logger.error(f"Failed to store AI decision: {e}")
    
    def update_confidence_calibration(self, 
                                    model_id: str,
                                    confidence_range: float,
                                    was_correct: bool):
        """Update confidence calibration based on feedback"""
        try:
            # Get current calibration data
            response = self.confidence_calibration_table.get_item(
                Key={
                    'model': model_id,
                    'confidence_range_start': Decimal(str(int(confidence_range * 10) / 10))
                }
            )
            
            current_data = response.get('Item', {
                'model': model_id,
                'confidence_range_start': Decimal(str(int(confidence_range * 10) / 10)),
                'confidence_range_end': Decimal(str((int(confidence_range * 10) + 1) / 10)),
                'actual_accuracy': Decimal('0.8'),
                'sample_count': 0,
                'correct_count': 0
            })
            
            # Update counts
            sample_count = current_data.get('sample_count', 0) + 1
            correct_count = current_data.get('correct_count', 0) + (1 if was_correct else 0)
            
            # Calculate new accuracy
            new_accuracy = correct_count / sample_count if sample_count > 0 else 0.8
            
            # Update item
            self.confidence_calibration_table.put_item(
                Item={
                    'model': model_id,
                    'confidence_range_start': current_data['confidence_range_start'],
                    'confidence_range_end': current_data['confidence_range_end'],
                    'actual_accuracy': Decimal(str(new_accuracy)),
                    'sample_count': sample_count,
                    'correct_count': correct_count,
                    'last_updated': datetime.utcnow().isoformat()
                }
            )
            
            # Invalidate cache
            self._last_cache_update = datetime.utcnow() - timedelta(hours=2)
            
        except Exception as e:
            logger.error(f"Failed to update confidence calibration: {e}")
    
    def compare_with_traditional_tools(self, 
                                     finding_id: str,
                                     ai_found: bool,
                                     tool_results: Dict[str, bool]):
        """Compare AI findings with traditional tool results"""
        try:
            for tool_name, tool_found in tool_results.items():
                match_type = 'exact' if ai_found == tool_found else 'different'
                
                self.tool_comparisons_table.put_item(
                    Item={
                        'finding_id': finding_id,
                        'tool_name': tool_name,
                        'ai_found': ai_found,
                        'tool_found': tool_found,
                        'match_type': match_type,
                        'comparison_timestamp': datetime.utcnow().isoformat(),
                        'ttl': int((datetime.utcnow() + timedelta(days=30)).timestamp())
                    }
                )
        except Exception as e:
            logger.error(f"Failed to store tool comparison: {e}")
    
    def get_explanation_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve explanation for a finding"""
        try:
            response = self.ai_decisions_table.get_item(
                Key={'finding_id': finding_id}
            )
            
            if 'Item' in response:
                item = response['Item']
                return {
                    'finding_id': item['finding_id'],
                    'ai_model': item['ai_model'],
                    'confidence_score': float(item['confidence_score']),
                    'confidence_level': item['confidence_level'],
                    'evidence': json.loads(item.get('evidence_json', '[]')),
                    'reasoning': json.loads(item.get('reasoning_json', '[]')),
                    'timestamp': item['timestamp'],
                    'false_positive_indicators': item.get('false_positive_indicators', [])
                }
                
        except Exception as e:
            logger.error(f"Failed to retrieve explanation: {e}")
        
        return None
    
    def get_model_performance_stats(self, model_id: str) -> Dict[str, Any]:
        """Get performance statistics for a model"""
        try:
            # Query all calibration data for model
            response = self.confidence_calibration_table.query(
                KeyConditionExpression='model = :model',
                ExpressionAttributeValues={':model': model_id}
            )
            
            total_samples = 0
            total_correct = 0
            confidence_accuracy_pairs = []
            
            for item in response.get('Items', []):
                samples = item.get('sample_count', 0)
                correct = item.get('correct_count', 0)
                conf_start = float(item.get('confidence_range_start', 0))
                accuracy = float(item.get('actual_accuracy', 0))
                
                total_samples += samples
                total_correct += correct
                confidence_accuracy_pairs.append((conf_start, accuracy, samples))
            
            overall_accuracy = total_correct / total_samples if total_samples > 0 else 0
            
            # Calculate calibration error
            calibration_error = 0
            for conf, acc, samples in confidence_accuracy_pairs:
                if samples > 0:
                    calibration_error += abs(conf - acc) * samples
            
            calibration_error = calibration_error / total_samples if total_samples > 0 else 0
            
            return {
                'model_id': model_id,
                'total_samples': total_samples,
                'overall_accuracy': round(overall_accuracy, 3),
                'calibration_error': round(calibration_error, 3),
                'confidence_accuracy_data': confidence_accuracy_pairs,
                'is_well_calibrated': calibration_error < 0.1  # Less than 10% error
            }
            
        except Exception as e:
            logger.error(f"Failed to get model performance stats: {e}")
            return {}