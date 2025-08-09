"""
Machine Learning Feedback Lambda - Handles model training and improvement based on scan results
"""
import os
import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
from collections import defaultdict

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sagemaker_client = boto3.client('sagemaker')
bedrock_runtime = boto3.client('bedrock-runtime')

# Environment variables
FINDINGS_TABLE = os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
FEEDBACK_TABLE = os.environ.get('FEEDBACK_TABLE', 'SecurityFeedback')
MODEL_METADATA_TABLE = os.environ.get('MODEL_METADATA_TABLE', 'SecurityModelMetadata')
TRAINING_BUCKET = os.environ.get('TRAINING_BUCKET')
MODEL_BUCKET = os.environ.get('MODEL_BUCKET')
MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')


class MLFeedbackHandler:
    """Handles machine learning feedback and model improvement"""
    
    def __init__(self):
        self.findings_table = dynamodb.Table(FINDINGS_TABLE)
        self.feedback_table = dynamodb.Table(FEEDBACK_TABLE)
        self.model_metadata_table = dynamodb.Table(MODEL_METADATA_TABLE)
        
    def process_feedback(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process feedback for ML model improvement
        
        Feedback types:
        1. False positive/negative marking
        2. Severity adjustment
        3. Pattern validation
        4. Model performance metrics
        """
        
        feedback_type = event.get('feedback_type', 'finding_validation')
        
        if feedback_type == 'finding_validation':
            return self._process_finding_validation(event)
        elif feedback_type == 'batch_feedback':
            return self._process_batch_feedback(event)
        elif feedback_type == 'model_evaluation':
            return self._evaluate_model_performance(event)
        elif feedback_type == 'pattern_learning':
            return self._learn_new_patterns(event)
        elif feedback_type == 'threshold_adjustment':
            return self._adjust_detection_thresholds(event)
        elif feedback_type == 'trigger_training':
            return self._trigger_model_training(event)
        else:
            return {'statusCode': 400, 'message': f'Unknown feedback type: {feedback_type}'}
    
    def _process_finding_validation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process validation feedback for individual findings"""
        
        finding_id = event.get('finding_id')
        validation = event.get('validation')  # true_positive, false_positive, etc.
        user_id = event.get('user_id', 'system')
        reason = event.get('reason', '')
        
        if not finding_id or not validation:
            return {'statusCode': 400, 'message': 'finding_id and validation required'}
        
        # Store feedback
        feedback_record = {
            'feedback_id': f"{finding_id}-{datetime.utcnow().timestamp()}",
            'finding_id': finding_id,
            'validation': validation,
            'user_id': user_id,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat(),
            'processed': False
        }
        
        try:
            self.feedback_table.put_item(Item=feedback_record)
        except Exception as e:
            logger.error(f"Failed to store feedback: {e}")
            return {'statusCode': 500, 'error': str(e)}
        
        # Update finding with feedback
        self._update_finding_with_feedback(finding_id, validation)
        
        # If false positive, analyze why
        if validation == 'false_positive':
            analysis = self._analyze_false_positive(finding_id, reason)
            feedback_record['false_positive_analysis'] = analysis
        
        # Check if we have enough feedback to trigger learning
        feedback_count = self._get_recent_feedback_count()
        if feedback_count >= 100:  # Configurable threshold
            self._trigger_learning_job()
        
        return {
            'statusCode': 200,
            'feedback_id': feedback_record['feedback_id'],
            'finding_id': finding_id,
            'validation': validation,
            'feedback_count': feedback_count,
            'learning_triggered': feedback_count >= 100
        }
    
    def _process_batch_feedback(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process feedback for multiple findings at once"""
        
        feedback_items = event.get('feedback_items', [])
        user_id = event.get('user_id', 'system')
        
        processed = []
        failed = []
        
        for item in feedback_items:
            try:
                result = self._process_finding_validation({
                    'finding_id': item.get('finding_id'),
                    'validation': item.get('validation'),
                    'user_id': user_id,
                    'reason': item.get('reason', '')
                })
                processed.append(item.get('finding_id'))
            except Exception as e:
                failed.append({
                    'finding_id': item.get('finding_id'),
                    'error': str(e)
                })
        
        return {
            'statusCode': 200,
            'processed_count': len(processed),
            'failed_count': len(failed),
            'processed': processed,
            'failed': failed
        }
    
    def _evaluate_model_performance(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate model performance based on feedback"""
        
        time_range = event.get('time_range', 'last_7_days')
        model_version = event.get('model_version', 'current')
        
        # Get feedback data
        feedback_data = self._get_feedback_data(time_range)
        
        # Calculate metrics
        metrics = self._calculate_performance_metrics(feedback_data)
        
        # Analyze patterns in false positives/negatives
        error_analysis = self._analyze_error_patterns(feedback_data)
        
        # Generate improvement recommendations
        recommendations = self._generate_improvement_recommendations(metrics, error_analysis)
        
        # Store evaluation results
        evaluation = {
            'evaluation_id': f"eval-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.utcnow().isoformat(),
            'model_version': model_version,
            'time_range': time_range,
            'metrics': metrics,
            'error_analysis': error_analysis,
            'recommendations': recommendations
        }
        
        # Save evaluation
        if MODEL_BUCKET:
            self._save_evaluation(evaluation)
        
        return {
            'statusCode': 200,
            'evaluation_id': evaluation['evaluation_id'],
            'metrics': metrics,
            'recommendations': recommendations
        }
    
    def _learn_new_patterns(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Learn new vulnerability patterns from validated findings"""
        
        pattern_type = event.get('pattern_type', 'vulnerability')
        min_occurrences = event.get('min_occurrences', 5)
        
        # Get validated findings
        validated_findings = self._get_validated_findings()
        
        # Extract patterns
        patterns = self._extract_patterns(validated_findings, pattern_type)
        
        # Filter patterns by occurrence
        significant_patterns = [
            p for p in patterns 
            if p['occurrences'] >= min_occurrences
        ]
        
        # Generate pattern rules
        new_rules = []
        for pattern in significant_patterns:
            rule = self._generate_pattern_rule(pattern)
            new_rules.append(rule)
        
        # Store new patterns
        stored_patterns = self._store_patterns(new_rules)
        
        # Update detection engine
        if new_rules:
            self._update_detection_rules(new_rules)
        
        return {
            'statusCode': 200,
            'patterns_found': len(patterns),
            'significant_patterns': len(significant_patterns),
            'new_rules_created': len(new_rules),
            'stored_patterns': stored_patterns
        }
    
    def _adjust_detection_thresholds(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Adjust detection thresholds based on feedback"""
        
        threshold_type = event.get('threshold_type', 'confidence')
        adjustment_factor = event.get('adjustment_factor', 'auto')
        
        # Get current thresholds
        current_thresholds = self._get_current_thresholds()
        
        # Calculate optimal thresholds based on feedback
        if adjustment_factor == 'auto':
            optimal_thresholds = self._calculate_optimal_thresholds()
        else:
            optimal_thresholds = self._apply_manual_adjustment(
                current_thresholds, adjustment_factor
            )
        
        # Validate threshold changes
        validation = self._validate_threshold_changes(
            current_thresholds, optimal_thresholds
        )
        
        if validation['safe_to_apply']:
            # Apply new thresholds
            self._apply_thresholds(optimal_thresholds)
            status = 'applied'
        else:
            status = 'requires_review'
        
        return {
            'statusCode': 200,
            'status': status,
            'current_thresholds': current_thresholds,
            'recommended_thresholds': optimal_thresholds,
            'validation': validation,
            'expected_impact': self._estimate_threshold_impact(
                current_thresholds, optimal_thresholds
            )
        }
    
    def _trigger_model_training(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger model training job"""
        
        training_type = event.get('training_type', 'incremental')
        dataset_config = event.get('dataset_config', {})
        
        # Prepare training data
        training_data = self._prepare_training_data(dataset_config)
        
        # Create training job configuration
        job_config = {
            'job_name': f"security-model-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'training_type': training_type,
            'dataset': training_data['dataset_location'],
            'hyperparameters': self._get_hyperparameters(training_type),
            'evaluation_metrics': ['precision', 'recall', 'f1_score', 'false_positive_rate']
        }
        
        # For Bedrock models, we would fine-tune if supported
        # For now, we'll simulate training process
        if training_type == 'fine_tuning':
            # In production, trigger Bedrock fine-tuning if available
            training_job = self._simulate_fine_tuning(job_config)
        else:
            # Incremental learning through prompt engineering
            training_job = self._incremental_learning(job_config)
        
        return {
            'statusCode': 200,
            'job_name': job_config['job_name'],
            'training_type': training_type,
            'dataset_size': training_data['sample_count'],
            'status': training_job['status'],
            'estimated_completion': training_job.get('estimated_completion')
        }
    
    def _update_finding_with_feedback(self, finding_id: str, validation: str):
        """Update finding record with feedback"""
        try:
            self.findings_table.update_item(
                Key={'finding_id': finding_id},
                UpdateExpression='SET validation_status = :status, validation_timestamp = :ts',
                ExpressionAttributeValues={
                    ':status': validation,
                    ':ts': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Failed to update finding: {e}")
    
    def _analyze_false_positive(self, finding_id: str, reason: str) -> Dict[str, Any]:
        """Analyze why a finding was marked as false positive"""
        
        # Get finding details
        try:
            response = self.findings_table.get_item(Key={'finding_id': finding_id})
            finding = response.get('Item', {})
        except:
            return {}
        
        analysis = {
            'finding_type': finding.get('finding_type'),
            'confidence_level': finding.get('confidence_level'),
            'confidence_score': float(finding.get('confidence', 0)),
            'severity': finding.get('severity'),
            'user_reason': reason
        }
        
        # Common false positive patterns
        if 'test' in finding.get('file_path', '').lower():
            analysis['likely_cause'] = 'test_file'
        elif finding.get('confidence', 0) < 0.7:
            analysis['likely_cause'] = 'low_confidence'
        elif 'example' in finding.get('description', '').lower():
            analysis['likely_cause'] = 'example_code'
        else:
            analysis['likely_cause'] = 'context_misunderstanding'
        
        # Generate learning points
        analysis['learning_points'] = self._generate_learning_points(finding, reason)
        
        return analysis
    
    def _get_recent_feedback_count(self) -> int:
        """Get count of recent feedback items"""
        # In production, query DynamoDB with time filter
        # Simplified for demo
        try:
            response = self.feedback_table.scan(
                FilterExpression='attribute_not_exists(processed)'
            )
            return len(response.get('Items', []))
        except:
            return 0
    
    def _trigger_learning_job(self):
        """Trigger asynchronous learning job"""
        # In production, trigger Step Functions or SageMaker job
        logger.info("Learning job triggered")
    
    def _get_feedback_data(self, time_range: str) -> List[Dict]:
        """Get feedback data for specified time range"""
        # Calculate time boundaries
        end_time = datetime.utcnow()
        if time_range == 'last_24_hours':
            start_time = end_time - timedelta(hours=24)
        elif time_range == 'last_7_days':
            start_time = end_time - timedelta(days=7)
        elif time_range == 'last_30_days':
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(days=7)
        
        # In production, query with time filter
        # Simplified version
        feedback_items = []
        try:
            response = self.feedback_table.scan()
            feedback_items = response.get('Items', [])
        except Exception as e:
            logger.error(f"Failed to get feedback: {e}")
        
        return feedback_items
    
    def _calculate_performance_metrics(self, feedback_data: List[Dict]) -> Dict[str, Any]:
        """Calculate model performance metrics"""
        
        total = len(feedback_data)
        if total == 0:
            return {
                'total_feedback': 0,
                'accuracy': 0,
                'precision': 0,
                'recall': 0,
                'f1_score': 0
            }
        
        # Count validations
        true_positives = len([f for f in feedback_data if f.get('validation') == 'true_positive'])
        false_positives = len([f for f in feedback_data if f.get('validation') == 'false_positive'])
        true_negatives = len([f for f in feedback_data if f.get('validation') == 'true_negative'])
        false_negatives = len([f for f in feedback_data if f.get('validation') == 'false_negative'])
        
        # Calculate metrics
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'total_feedback': total,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'accuracy': round(accuracy, 3),
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'false_positive_rate': round(false_positives / total if total > 0 else 0, 3)
        }
    
    def _analyze_error_patterns(self, feedback_data: List[Dict]) -> Dict[str, Any]:
        """Analyze patterns in false positives and negatives"""
        
        false_positives = [f for f in feedback_data if f.get('validation') == 'false_positive']
        false_negatives = [f for f in feedback_data if f.get('validation') == 'false_negative']
        
        # Analyze false positive patterns
        fp_patterns = defaultdict(int)
        for fp in false_positives:
            # Get finding details
            finding_id = fp.get('finding_id')
            # In production, retrieve finding details
            fp_patterns['total'] += 1
            
            # Categorize by reason
            reason = fp.get('reason', 'unknown')
            if 'test' in reason.lower():
                fp_patterns['test_code'] += 1
            elif 'example' in reason.lower():
                fp_patterns['example_code'] += 1
            elif 'comment' in reason.lower():
                fp_patterns['commented_code'] += 1
            else:
                fp_patterns['other'] += 1
        
        # Analyze false negative patterns
        fn_patterns = defaultdict(int)
        for fn in false_negatives:
            fn_patterns['total'] += 1
            # Would analyze missed vulnerability types
        
        return {
            'false_positive_patterns': dict(fp_patterns),
            'false_negative_patterns': dict(fn_patterns),
            'top_fp_reasons': self._get_top_reasons(false_positives),
            'top_fn_types': []  # Would be populated with missed vuln types
        }
    
    def _generate_improvement_recommendations(self, metrics: Dict, error_analysis: Dict) -> List[Dict]:
        """Generate recommendations for model improvement"""
        
        recommendations = []
        
        # Check accuracy
        if metrics['accuracy'] < 0.8:
            recommendations.append({
                'priority': 'high',
                'type': 'accuracy_improvement',
                'recommendation': 'Consider retraining with more diverse dataset',
                'expected_impact': 'Improve overall accuracy by 10-15%'
            })
        
        # Check false positive rate
        if metrics['false_positive_rate'] > 0.2:
            recommendations.append({
                'priority': 'high',
                'type': 'false_positive_reduction',
                'recommendation': 'Adjust confidence thresholds and add context filters',
                'expected_impact': 'Reduce false positives by 30-40%'
            })
        
        # Check for specific patterns
        fp_patterns = error_analysis.get('false_positive_patterns', {})
        if fp_patterns.get('test_code', 0) > fp_patterns.get('total', 1) * 0.3:
            recommendations.append({
                'priority': 'medium',
                'type': 'pattern_filter',
                'recommendation': 'Add test file detection and exclusion',
                'expected_impact': 'Eliminate test file false positives'
            })
        
        # Check recall
        if metrics['recall'] < 0.7:
            recommendations.append({
                'priority': 'high',
                'type': 'sensitivity_improvement',
                'recommendation': 'Lower detection thresholds for critical vulnerabilities',
                'expected_impact': 'Catch 20-30% more real vulnerabilities'
            })
        
        return recommendations
    
    def _get_validated_findings(self) -> List[Dict]:
        """Get findings that have been validated"""
        validated = []
        
        try:
            # Get feedback with true_positive validation
            response = self.feedback_table.scan(
                FilterExpression='validation = :val',
                ExpressionAttributeValues={':val': 'true_positive'}
            )
            
            for feedback in response.get('Items', []):
                # Get corresponding finding
                finding_id = feedback.get('finding_id')
                finding_response = self.findings_table.get_item(
                    Key={'finding_id': finding_id}
                )
                if 'Item' in finding_response:
                    validated.append(finding_response['Item'])
                    
        except Exception as e:
            logger.error(f"Failed to get validated findings: {e}")
        
        return validated
    
    def _extract_patterns(self, findings: List[Dict], pattern_type: str) -> List[Dict]:
        """Extract patterns from validated findings"""
        
        patterns = defaultdict(lambda: {
            'occurrences': 0,
            'examples': [],
            'characteristics': {}
        })
        
        for finding in findings:
            if pattern_type == 'vulnerability':
                # Extract vulnerability patterns
                pattern_key = f"{finding.get('finding_type')}:{finding.get('severity')}"
                patterns[pattern_key]['occurrences'] += 1
                patterns[pattern_key]['examples'].append(finding.get('finding_id'))
                
                # Extract characteristics
                if 'confidence' in finding:
                    if 'avg_confidence' not in patterns[pattern_key]['characteristics']:
                        patterns[pattern_key]['characteristics']['avg_confidence'] = []
                    patterns[pattern_key]['characteristics']['avg_confidence'].append(
                        float(finding.get('confidence', 0))
                    )
        
        # Convert to list and calculate averages
        pattern_list = []
        for key, data in patterns.items():
            pattern = {
                'pattern': key,
                'occurrences': data['occurrences'],
                'examples': data['examples'][:5],  # Limit examples
                'characteristics': {}
            }
            
            # Calculate averages
            for char, values in data['characteristics'].items():
                if 'avg_' in char and isinstance(values, list):
                    pattern['characteristics'][char] = sum(values) / len(values)
            
            pattern_list.append(pattern)
        
        return pattern_list
    
    def _generate_pattern_rule(self, pattern: Dict) -> Dict[str, Any]:
        """Generate detection rule from pattern"""
        
        pattern_parts = pattern['pattern'].split(':')
        finding_type = pattern_parts[0] if pattern_parts else 'unknown'
        severity = pattern_parts[1] if len(pattern_parts) > 1 else 'MEDIUM'
        
        rule = {
            'rule_id': hashlib.md5(pattern['pattern'].encode()).hexdigest()[:12],
            'pattern': pattern['pattern'],
            'finding_type': finding_type,
            'severity': severity,
            'confidence_threshold': pattern['characteristics'].get('avg_confidence', 0.7),
            'min_occurrences': 1,
            'created_from_learning': True,
            'created_at': datetime.utcnow().isoformat(),
            'validation_count': pattern['occurrences']
        }
        
        return rule
    
    def _store_patterns(self, patterns: List[Dict]) -> List[str]:
        """Store learned patterns"""
        stored = []
        
        if MODEL_BUCKET:
            # Store patterns in S3
            patterns_key = f"learned-patterns/patterns-{datetime.utcnow().strftime('%Y%m%d')}.json"
            try:
                s3_client.put_object(
                    Bucket=MODEL_BUCKET,
                    Key=patterns_key,
                    Body=json.dumps(patterns, indent=2),
                    ContentType='application/json'
                )
                stored.append(patterns_key)
            except Exception as e:
                logger.error(f"Failed to store patterns: {e}")
        
        return stored
    
    def _update_detection_rules(self, rules: List[Dict]):
        """Update detection engine with new rules"""
        # In production, update the detection engine configuration
        logger.info(f"Updated detection engine with {len(rules)} new rules")
    
    def _get_current_thresholds(self) -> Dict[str, float]:
        """Get current detection thresholds"""
        # In production, retrieve from configuration
        return {
            'confidence': 0.7,
            'severity_weight': 0.8,
            'business_risk': 0.6,
            'false_positive_tolerance': 0.15
        }
    
    def _calculate_optimal_thresholds(self) -> Dict[str, float]:
        """Calculate optimal thresholds based on feedback"""
        
        # Get recent performance metrics
        feedback_data = self._get_feedback_data('last_30_days')
        metrics = self._calculate_performance_metrics(feedback_data)
        
        current = self._get_current_thresholds()
        optimal = current.copy()
        
        # Adjust based on false positive rate
        if metrics['false_positive_rate'] > 0.2:
            # Increase confidence threshold
            optimal['confidence'] = min(0.9, current['confidence'] + 0.1)
        elif metrics['false_positive_rate'] < 0.05 and metrics['recall'] < 0.8:
            # Decrease confidence threshold to catch more
            optimal['confidence'] = max(0.5, current['confidence'] - 0.1)
        
        # Adjust based on accuracy
        if metrics['accuracy'] < 0.8:
            optimal['severity_weight'] = min(0.9, current['severity_weight'] + 0.05)
        
        return optimal
    
    def _validate_threshold_changes(self, current: Dict, new: Dict) -> Dict[str, Any]:
        """Validate threshold changes are safe"""
        
        validation = {
            'safe_to_apply': True,
            'warnings': [],
            'changes': {}
        }
        
        # Check magnitude of changes
        for key, current_val in current.items():
            if key in new:
                change = abs(new[key] - current_val)
                validation['changes'][key] = {
                    'current': current_val,
                    'new': new[key],
                    'change': change
                }
                
                # Warn on large changes
                if change > 0.2:
                    validation['warnings'].append(
                        f"Large change in {key}: {change:.2f}"
                    )
                    validation['safe_to_apply'] = False
        
        return validation
    
    def _apply_thresholds(self, thresholds: Dict[str, float]):
        """Apply new detection thresholds"""
        # In production, update configuration
        logger.info(f"Applied new thresholds: {thresholds}")
    
    def _estimate_threshold_impact(self, current: Dict, new: Dict) -> Dict[str, Any]:
        """Estimate impact of threshold changes"""
        
        impact = {
            'estimated_fp_change': 0,
            'estimated_fn_change': 0,
            'confidence_impact': 'neutral'
        }
        
        # Estimate based on threshold differences
        confidence_change = new.get('confidence', 0.7) - current.get('confidence', 0.7)
        
        if confidence_change > 0:
            impact['estimated_fp_change'] = -10  # Fewer false positives
            impact['estimated_fn_change'] = 5   # More false negatives
            impact['confidence_impact'] = 'stricter'
        elif confidence_change < 0:
            impact['estimated_fp_change'] = 10   # More false positives
            impact['estimated_fn_change'] = -5   # Fewer false negatives
            impact['confidence_impact'] = 'looser'
        
        return impact
    
    def _prepare_training_data(self, config: Dict) -> Dict[str, Any]:
        """Prepare training dataset"""
        
        # Get validated findings
        validated_findings = self._get_validated_findings()
        
        # Get feedback data
        feedback_data = self._get_feedback_data('last_90_days')
        
        # Combine and format for training
        training_samples = []
        for feedback in feedback_data:
            finding_id = feedback.get('finding_id')
            # Get finding details
            # Format as training sample
            sample = {
                'finding_id': finding_id,
                'label': feedback.get('validation'),
                'features': {}  # Would extract features
            }
            training_samples.append(sample)
        
        # Save training data
        if TRAINING_BUCKET:
            dataset_key = f"datasets/security-{datetime.utcnow().strftime('%Y%m%d')}.json"
            try:
                s3_client.put_object(
                    Bucket=TRAINING_BUCKET,
                    Key=dataset_key,
                    Body=json.dumps(training_samples),
                    ContentType='application/json'
                )
                dataset_location = f"s3://{TRAINING_BUCKET}/{dataset_key}"
            except:
                dataset_location = 'local'
        else:
            dataset_location = 'local'
        
        return {
            'dataset_location': dataset_location,
            'sample_count': len(training_samples),
            'positive_samples': len([s for s in training_samples if s['label'] == 'true_positive']),
            'negative_samples': len([s for s in training_samples if s['label'] == 'false_positive'])
        }
    
    def _get_hyperparameters(self, training_type: str) -> Dict[str, Any]:
        """Get hyperparameters for training"""
        
        if training_type == 'fine_tuning':
            return {
                'learning_rate': 0.0001,
                'batch_size': 16,
                'epochs': 5,
                'warmup_steps': 100
            }
        else:
            return {
                'prompt_optimization': True,
                'context_window': 4096,
                'temperature': 0.1
            }
    
    def _simulate_fine_tuning(self, config: Dict) -> Dict[str, Any]:
        """Simulate fine-tuning process"""
        # In production, would trigger actual fine-tuning
        return {
            'status': 'simulated',
            'job_id': config['job_name'],
            'estimated_completion': (datetime.utcnow() + timedelta(hours=2)).isoformat()
        }
    
    def _incremental_learning(self, config: Dict) -> Dict[str, Any]:
        """Perform incremental learning through prompt optimization"""
        
        # Generate optimized prompts based on feedback
        optimized_prompts = self._generate_optimized_prompts()
        
        # Store prompts
        if MODEL_BUCKET:
            prompts_key = f"prompts/optimized-{datetime.utcnow().strftime('%Y%m%d')}.json"
            try:
                s3_client.put_object(
                    Bucket=MODEL_BUCKET,
                    Key=prompts_key,
                    Body=json.dumps(optimized_prompts),
                    ContentType='application/json'
                )
            except Exception as e:
                logger.error(f"Failed to store prompts: {e}")
        
        return {
            'status': 'completed',
            'job_id': config['job_name'],
            'prompts_updated': len(optimized_prompts)
        }
    
    def _generate_optimized_prompts(self) -> List[Dict[str, str]]:
        """Generate optimized prompts based on learning"""
        
        # Get common false positive patterns
        feedback_data = self._get_feedback_data('last_30_days')
        error_analysis = self._analyze_error_patterns(feedback_data)
        
        prompts = []
        
        # Add context for common false positives
        if error_analysis['false_positive_patterns'].get('test_code', 0) > 10:
            prompts.append({
                'type': 'context_filter',
                'prompt': "Ignore vulnerabilities in test files or example code unless they demonstrate unsafe patterns that could be copied to production."
            })
        
        if error_analysis['false_positive_patterns'].get('commented_code', 0) > 5:
            prompts.append({
                'type': 'context_filter',
                'prompt': "Do not flag vulnerabilities in commented-out code unless the comments indicate future implementation plans."
            })
        
        return prompts
    
    def _save_evaluation(self, evaluation: Dict):
        """Save model evaluation results"""
        if MODEL_BUCKET:
            eval_key = f"evaluations/{evaluation['evaluation_id']}.json"
            try:
                s3_client.put_object(
                    Bucket=MODEL_BUCKET,
                    Key=eval_key,
                    Body=json.dumps(evaluation, indent=2),
                    ContentType='application/json'
                )
            except Exception as e:
                logger.error(f"Failed to save evaluation: {e}")
    
    def _get_top_reasons(self, feedback_items: List[Dict]) -> List[Tuple[str, int]]:
        """Get top reasons for feedback"""
        reason_counts = defaultdict(int)
        
        for item in feedback_items:
            reason = item.get('reason', 'unspecified')
            reason_counts[reason] += 1
        
        # Sort by count
        sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_reasons[:5]
    
    def _generate_learning_points(self, finding: Dict, reason: str) -> List[str]:
        """Generate specific learning points from false positive"""
        
        learning_points = []
        
        # Analyze file path
        file_path = finding.get('file_path', '')
        if 'test' in file_path.lower():
            learning_points.append("Consider file path context - test files have different security requirements")
        
        # Analyze confidence
        if finding.get('confidence', 0) < 0.7:
            learning_points.append("Low confidence findings need additional validation")
        
        # Analyze user reason
        if reason:
            if 'example' in reason.lower():
                learning_points.append("Distinguish between example/documentation code and production code")
            elif 'false' in reason.lower():
                learning_points.append("Improve pattern matching to reduce false pattern matches")
        
        return learning_points


def lambda_handler(event, context):
    """Lambda handler for ML feedback processing"""
    
    handler = MLFeedbackHandler()
    
    try:
        # Handle different event sources
        if 'Records' in event:
            # Process batch feedback from SQS/SNS
            results = []
            for record in event['Records']:
                if 'body' in record:
                    message = json.loads(record['body'])
                    result = handler.process_feedback(message)
                    results.append(result)
            
            return {
                'statusCode': 200,
                'processed': len(results),
                'results': results
            }
        else:
            # Direct invocation
            return handler.process_feedback(event)
            
    except Exception as e:
        logger.error(f"ML feedback processing failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }