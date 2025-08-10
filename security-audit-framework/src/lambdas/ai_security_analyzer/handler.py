"""
AI Security Analyzer Lambda
Exposes advanced AI security capabilities including threat intelligence,
root cause analysis, and sandbox testing
"""
import os
import sys
import json
import boto3
from pathlib import Path
import asyncio
from typing import Dict, Any, List

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from ai_models.sql_injection_detector import SQLInjectionDetector
from ai_models.threat_intelligence import AISecurityIntelligence
from ai_models.root_cause_analyzer import AIRootCauseAnalyzer
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.ai_security_sandbox import AISecuritySandbox
from ai_models.security_test_generator import AISecurityTestGenerator

# Initialize components
sql_detector = SQLInjectionDetector()
threat_intel = AISecurityIntelligence()
root_cause = AIRootCauseAnalyzer()
pure_ai = PureAIVulnerabilityDetector()
sandbox = AISecuritySandbox()
test_generator = AISecurityTestGenerator()


def handler(event, context):
    """
    Lambda handler for AI security analysis
    
    Event structure:
    {
        "action": "analyze_sql|threat_intel|root_cause|pure_ai|sandbox",
        "payload": {
            # For analyze_sql:
            "code": "SQL query or code containing SQL",
            "context": {"language": "python", "framework": "django"}
            
            # For threat_intel:
            "findings": [list of security findings],
            "repository_path": "path/to/repo"
            
            # For root_cause:
            "incident_id": "incident-123",
            "incident_data": {incident details}
            
            # For pure_ai:
            "code": "source code to analyze",
            "context": {"file_path": "path/to/file", "language": "python"}
            
            # For sandbox:
            "vulnerability": {vulnerability details},
            "test_cases": [list of test cases]
        }
    }
    """
    action = event.get('action')
    payload = event.get('payload', {})
    
    try:
        if action == 'analyze_sql':
            return handle_sql_analysis(payload)
        elif action == 'threat_intel':
            return handle_threat_intelligence(payload)
        elif action == 'root_cause':
            return handle_root_cause_analysis(payload)
        elif action == 'pure_ai':
            return handle_pure_ai_detection(payload)
        elif action == 'sandbox':
            return handle_sandbox_testing(payload)
        elif action == 'test_generator':
            return handle_test_generation(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}',
                    'available_actions': [
                        'analyze_sql', 'threat_intel', 'root_cause',
                        'pure_ai', 'sandbox', 'test_generator'
                    ]
                })
            }
            
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'action': action
            })
        }


def handle_sql_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle SQL injection analysis"""
    code = payload.get('code', '')
    context = payload.get('context', {})
    deep_analysis = payload.get('deep_analysis', True)
    
    if not code:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Code is required'})
        }
    
    # Detect SQL injection
    result = sql_detector.detect(code, context, deep_analysis)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'is_vulnerable': result.is_vulnerable,
            'confidence': result.confidence,
            'injection_type': result.injection_type,
            'severity': result.severity,
            'exploitation_scenario': result.exploitation_scenario,
            'fix_recommendation': result.fix_recommendation,
            'proof_of_concept': result.proof_of_concept,
            'attention_weights': result.attention_weights
        })
    }


def handle_threat_intelligence(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle threat intelligence analysis"""
    code_patterns = payload.get('code_patterns', [])
    technology_stack = payload.get('technology_stack', [])
    action_type = payload.get('action_type', 'analyze_threats')
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        if action_type == 'analyze_threats':
            threats = loop.run_until_complete(
                threat_intel.analyze_global_threats(code_patterns, technology_stack)
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'threats': [
                        {
                            'threat_id': t.threat_id,
                            'threat_type': t.threat_type,
                            'threat_name': t.threat_name,
                            'severity': t.severity,
                            'likelihood': t.likelihood,
                            'mitigation_strategies': t.mitigation_strategies
                        }
                        for t in threats
                    ]
                })
            }
            
        elif action_type == 'predict_vulnerabilities':
            codebase_analysis = payload.get('codebase_analysis', {})
            historical_vulns = payload.get('historical_vulnerabilities', [])
            
            predictions = loop.run_until_complete(
                threat_intel.predict_vulnerabilities(codebase_analysis, historical_vulns)
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'predictions': [
                        {
                            'prediction_id': p.prediction_id,
                            'vulnerability_type': p.vulnerability_type,
                            'predicted_severity': p.predicted_severity,
                            'likelihood_of_discovery': p.likelihood_of_discovery,
                            'preventive_measures': p.preventive_measures
                        }
                        for p in predictions
                    ]
                })
            }
            
        elif action_type == 'threat_hunting':
            repository = payload.get('repository', '')
            hunt_parameters = payload.get('hunt_parameters', {})
            
            findings = loop.run_until_complete(
                threat_intel.threat_hunting(repository, hunt_parameters)
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({'findings': findings})
            }
            
    finally:
        loop.close()


def handle_root_cause_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle root cause analysis for incidents"""
    incident_id = payload.get('incident_id')
    incident_data = payload.get('incident_data', {})
    action_type = payload.get('action_type', 'analyze_incident')
    
    if not incident_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'incident_id is required'})
        }
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        if action_type == 'analyze_incident':
            # Get mock data for demo (in production, would fetch from DB)
            logs = payload.get('logs', [])
            alerts = payload.get('related_alerts', [])
            
            analysis = loop.run_until_complete(
                root_cause.analyze_incident(incident_data, logs, alerts)
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'incident_id': analysis.incident_id,
                    'root_causes': analysis.root_causes,
                    'contributing_factors': analysis.contributing_factors,
                    'timeline': analysis.timeline,
                    'remediation_steps': analysis.remediation_steps,
                    'confidence_score': analysis.confidence_score
                })
            }
            
        elif action_type == 'prioritize_alerts':
            alerts = payload.get('alerts', [])
            context = payload.get('context', {})
            
            prioritized = loop.run_until_complete(
                root_cause.alert_prioritization(alerts, context)
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({'prioritized_alerts': prioritized})
            }
            
    finally:
        loop.close()


def handle_pure_ai_detection(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle pure AI vulnerability detection"""
    code = payload.get('code', '')
    context = payload.get('context', {})
    
    if not code:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Code is required'})
        }
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        vulnerabilities = loop.run_until_complete(
            pure_ai.detect_vulnerabilities(code, context)
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'vulnerabilities': [
                    {
                        'vuln_id': v.vuln_id,
                        'vulnerability_type': v.vulnerability_type,
                        'description': v.description,
                        'severity': v.severity,
                        'confidence': v.confidence,
                        'file_path': v.file_path,
                        'line_numbers': v.line_numbers,
                        'exploitation_scenario': v.exploitation_scenario,
                        'fix_recommendation': v.fix_recommendation,
                        'detection_method': v.detection_method
                    }
                    for v in vulnerabilities
                ]
            })
        }
        
    finally:
        loop.close()


def handle_sandbox_testing(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle sandbox vulnerability testing"""
    vulnerability = payload.get('vulnerability', {})
    code_context = payload.get('code_context', '')
    proposed_fix = payload.get('proposed_fix')
    
    if not vulnerability or not code_context:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'vulnerability and code_context are required'})
        }
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        report = loop.run_until_complete(
            sandbox.test_vulnerability(vulnerability, code_context, proposed_fix)
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'sandbox_id': report.sandbox_id,
                'vulnerability_confirmed': any(test.success for test in report.exploit_results),
                'exploit_tests_run': len(report.exploit_results),
                'successful_exploits': sum(1 for test in report.exploit_results if test.success),
                'fix_effective': all(
                    fix.fix_effective for fix in report.fix_validations
                ) if report.fix_validations else None,
                'risk_reduction': report.risk_reduction,
                'recommendations': report.recommendations,
                'overall_assessment': report.overall_assessment
            })
        }
        
    finally:
        loop.close()


def handle_test_generation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle AI security test generation"""
    vulnerabilities = payload.get('vulnerabilities', [])
    code_context = payload.get('code_context', {})
    test_types = payload.get('test_types', ['unit', 'integration', 'penetration', 'fuzzing'])
    
    if not vulnerabilities:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Vulnerabilities list is required'})
        }
    
    # Create event loop for async operations
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(
            test_generator.generate_tests(vulnerabilities, code_context, test_types)
        )
        
        response_data = {
            'test_suite_id': result.test_suite_metadata.get('suite_id'),
            'total_test_cases': len(result.test_cases),
            'total_penetration_scenarios': len(result.penetration_scenarios),
            'test_distribution': result.coverage_analysis.get('test_distribution', {}),
            'coverage_percentage': result.coverage_analysis['vulnerability_coverage']['coverage_percentage'],
            'estimated_execution_time': result.test_suite_metadata.get('estimated_execution_time'),
            'required_tools': result.test_suite_metadata.get('required_tools', []),
            'ai_confidence': result.ai_confidence,
            'test_cases': [
                {
                    'test_id': tc.test_id,
                    'test_name': tc.test_name,
                    'test_type': tc.test_type,
                    'vulnerability_type': tc.vulnerability_type,
                    'severity': tc.severity,
                    'confidence': tc.confidence
                }
                for tc in result.test_cases[:10]  # Return first 10 for response size
            ],
            'penetration_scenarios': [
                {
                    'scenario_id': ps.scenario_id,
                    'scenario_name': ps.scenario_name,
                    'attack_vector': ps.attack_vector,
                    'target_vulnerability': ps.target_vulnerability,
                    'risk_score': ps.risk_score
                }
                for ps in result.penetration_scenarios[:5]  # Return first 5
            ]
        }
        
        return {
            'statusCode': 200,
            'body': json.dumps(response_data)
        }
        
    finally:
        loop.close()
        loop.close()