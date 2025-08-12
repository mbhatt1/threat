"""
AI Explainability Engine - Provides explanations for AI security findings
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import boto3
from collections import defaultdict


class AIExplainabilityEngine:
    """
    Provides explanations and transparency for AI security findings
    Tracks model performance and confidence metrics
    """
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.s3_client = boto3.client('s3')
        self.explanations_table = os.environ.get('EXPLANATIONS_TABLE', 'security-explanations')
        self.metrics_bucket = os.environ.get('METRICS_BUCKET', 'security-audit-metrics')
        
    def explain_finding(self, finding: Dict[str, Any], model_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate explanation for a security finding
        
        Args:
            finding: The security finding to explain
            model_output: Raw output from AI model
            
        Returns:
            Explanation with reasoning steps and confidence
        """
        explanation = {
            'finding_id': finding.get('id', 'unknown'),
            'finding_type': finding.get('type', 'unknown'),
            'ai_model': model_output.get('model_id', 'unknown'),
            'confidence_score': model_output.get('confidence', 0.0),
            'confidence_level': self._categorize_confidence(model_output.get('confidence', 0.0)),
            'reasoning': [],
            'evidence': [],
            'false_positive_indicators': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Extract reasoning steps
        if 'reasoning_steps' in model_output:
            explanation['reasoning'] = model_output['reasoning_steps']
        elif 'analysis' in model_output:
            # Parse analysis text into steps
            analysis = model_output['analysis']
            steps = [s.strip() for s in analysis.split('.') if s.strip()]
            explanation['reasoning'] = steps[:5]  # Limit to 5 steps
        
        # Extract evidence
        if 'evidence' in model_output:
            explanation['evidence'] = model_output['evidence']
        elif 'code_context' in finding:
            explanation['evidence'].append({
                'type': 'code_context',
                'description': 'Vulnerable code pattern detected',
                'snippet': finding['code_context']
            })
        
        # Check for false positive indicators
        explanation['false_positive_indicators'] = self._check_false_positive_indicators(
            finding, model_output
        )
        
        # Store explanation
        self._store_explanation(explanation)
        
        return explanation
    
    def get_explanation_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve explanation for a specific finding"""
        try:
            table = self.dynamodb.Table(self.explanations_table)
            response = table.get_item(Key={'finding_id': finding_id})
            return response.get('Item')
        except Exception as e:
            print(f"Error retrieving explanation: {e}")
            return None
    
    def get_model_performance_stats(self, model_id: str) -> Dict[str, Any]:
        """
        Get performance statistics for an AI model
        
        Args:
            model_id: ID of the AI model
            
        Returns:
            Performance statistics including accuracy and calibration
        """
        try:
            # In production, this would query actual metrics
            # For now, return mock data
            return {
                'model_id': model_id,
                'total_samples': 10234,
                'overall_accuracy': 0.924,
                'precision': 0.891,
                'recall': 0.956,
                'f1_score': 0.922,
                'calibration_error': 0.032,
                'is_well_calibrated': True,
                'confidence_distribution': {
                    'very_low': 0.02,
                    'low': 0.05,
                    'medium': 0.23,
                    'high': 0.45,
                    'very_high': 0.25
                },
                'last_updated': datetime.utcnow().isoformat()
            }
        except Exception as e:
            print(f"Error getting model stats: {e}")
            return {}
    
    def track_feedback(self, finding_id: str, feedback: Dict[str, Any]):
        """Track user feedback on findings for model improvement"""
        try:
            table = self.dynamodb.Table(self.explanations_table)
            table.update_item(
                Key={'finding_id': finding_id},
                UpdateExpression='SET feedback = :feedback, feedback_timestamp = :ts',
                ExpressionAttributeValues={
                    ':feedback': feedback,
                    ':ts': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            print(f"Error tracking feedback: {e}")
    
    def _categorize_confidence(self, confidence: float) -> str:
        """Categorize confidence score into levels"""
        if confidence >= 0.9:
            return 'very_high'
        elif confidence >= 0.75:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        elif confidence >= 0.25:
            return 'low'
        else:
            return 'very_low'
    
    def _check_false_positive_indicators(self, finding: Dict[str, Any], 
                                       model_output: Dict[str, Any]) -> List[str]:
        """Check for indicators that finding might be false positive"""
        indicators = []
        
        # Low confidence
        if model_output.get('confidence', 1.0) < 0.6:
            indicators.append('Low model confidence score')
        
        # Test file
        if 'test' in finding.get('file_path', '').lower():
            indicators.append('Finding in test file')
        
        # Common false positive patterns
        if finding.get('type') == 'hardcoded_secret':
            if finding.get('value', '').startswith('example_'):
                indicators.append('Appears to be example/placeholder value')
        
        # Model uncertainty
        if model_output.get('uncertainty', 0) > 0.3:
            indicators.append('High model uncertainty')
        
        return indicators
    
    def _store_explanation(self, explanation: Dict[str, Any]):
        """Store explanation in DynamoDB"""
        try:
            table = self.dynamodb.Table(self.explanations_table)
            table.put_item(Item=explanation)
        except Exception as e:
            print(f"Error storing explanation: {e}")
    
    def generate_audit_trail(self, scan_id: str) -> Dict[str, Any]:
        """Generate complete audit trail for a scan"""
        audit_trail = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'model_decisions': [],
            'confidence_metrics': {},
            'reasoning_summary': []
        }
        
        # In production, this would aggregate all explanations for the scan
        # For now, return mock audit trail
        audit_trail['model_decisions'] = [
            {
                'finding_id': 'f1',
                'decision': 'vulnerability_detected',
                'confidence': 0.92,
                'model': 'claude-3-sonnet'
            }
        ]
        
        audit_trail['confidence_metrics'] = {
            'average_confidence': 0.87,
            'min_confidence': 0.65,
            'max_confidence': 0.98
        }
        
        return audit_trail