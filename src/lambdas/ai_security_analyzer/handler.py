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
from datetime import datetime
import logging
import subprocess
import tempfile

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add parent directories to path
# When deployed via CDK bundling, ai_models/ will be at the same level as handler.py
# For local development, we need to go up to src/
current_dir = Path(__file__).parent
if (current_dir / 'ai_models').exists():
    # Deployed scenario - ai_models is in the same directory
    sys.path.append(str(current_dir))
else:
    # Local development - ai_models is at src/ai_models
    sys.path.append(str(current_dir.parent.parent))

# Import AI components
from ai_models.sql_injection_detector import SQLInjectionDetector
from ai_models.threat_intelligence import AISecurityIntelligence
from ai_models.root_cause_analyzer import AIRootCauseAnalyzer
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.ai_security_sandbox import AISecuritySandbox
from ai_models.security_test_generator import AISecurityTestGenerator
from ai_models.hephaestus_ai_cognitive_bedrock import HephaestusCognitiveAI

# Initialize components
sql_detector = SQLInjectionDetector()
threat_intel = AISecurityIntelligence()
root_cause = AIRootCauseAnalyzer()
pure_ai = PureAIVulnerabilityDetector()
sandbox = AISecuritySandbox()
test_generator = AISecurityTestGenerator()

# Initialize Hephaestus (will use AWS credentials from Lambda environment)
hephaestus_ai = HephaestusCognitiveAI()


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
            
            # For hephaestus_cognitive:
            "repository_s3_bucket": "bucket-name",
            "repository_s3_key": "path/to/repo.zip",
            "max_iterations": 2,
            "severity_filter": "critical"  # optional: critical, high, medium, low
        }
    }
    """
    action = event.get('action')
    payload = event.get('payload', {})
    
    try:
        logger.info(f"Received action: {action}")
        logger.info(f"Payload: {json.dumps(payload)[:500]}")  # Log first 500 chars
        
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
        elif action == 'hephaestus_cognitive':
            return handle_hephaestus_cognitive(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}',
                    'available_actions': [
                        'analyze_sql', 'threat_intel', 'root_cause',
                        'pure_ai', 'sandbox', 'test_generator',
                        'hephaestus_cognitive'
                    ]
                })
            }
            
    except Exception as e:
        logger.error(f"Error handling action {action}: {str(e)}", exc_info=True)
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


def handle_hephaestus_cognitive(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle Hephaestus Cognitive AI analysis
    This advanced system uses 6-phase cognitive flow for deep vulnerability discovery
    """
    # Handle different payload formats (from SNS, EventBridge, API)
    repository_url = payload.get('repository_url')
    s3_bucket = payload.get('repository_s3_bucket')
    s3_key = payload.get('repository_s3_key')
    repository_path = payload.get('repository_path')
    
    # Map parameters
    max_iterations = payload.get('max_iterations', payload.get('max_vulnerabilities', 2))
    severity_filter = payload.get('severity_filter')
    branch = payload.get('branch', 'main')
    
    # Check if we have repository location
    if not repository_url and not s3_bucket and not repository_path:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Either repository_url, repository_s3_bucket/key, or repository_path is required'
            })
        }
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        logger.info(f"[HEPHAESTUS] Starting analysis - URL: {repository_url}, S3: {s3_bucket}/{s3_key}")
        
        # Handle repository URL (clone from git)
        if repository_url and not s3_bucket:
            # Clone repository to /tmp
            repo_dir = tempfile.mkdtemp(dir='/tmp')
            clone_cmd = ['git', 'clone', '--depth', '1', '--branch', branch, repository_url, repo_dir]
            
            try:
                logger.info(f"[HEPHAESTUS] Cloning repository: {repository_url}")
                result = subprocess.run(clone_cmd, check=True, capture_output=True, text=True)
                repo_path = repo_dir
                logger.info(f"[HEPHAESTUS] Repository cloned successfully to {repo_path}")
            except subprocess.CalledProcessError as e:
                logger.error(f"[HEPHAESTUS] Failed to clone repository: {e.stderr}")
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': f'Failed to clone repository: {e.stderr}'
                    })
                }
                
        # If S3 location provided, download the repository
        elif s3_bucket and s3_key:
            s3_client = boto3.client('s3')
            # Download to /tmp in Lambda
            local_path = f"/tmp/{s3_key.split('/')[-1]}"
            s3_client.download_file(s3_bucket, s3_key, local_path)
            
            # Extract if it's a zip file
            if local_path.endswith('.zip'):
                import zipfile
                extract_path = '/tmp/repo'
                with zipfile.ZipFile(local_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                repo_path = extract_path
            else:
                repo_path = local_path
        else:
            repo_path = payload.get('repository_path')
        
        # Run Hephaestus analysis
        logger.info(f"[HEPHAESTUS] Starting cognitive analysis on {repo_path}")
        results = loop.run_until_complete(
            hephaestus_ai.analyze(repo_path, max_iterations)
        )
        logger.info(f"[HEPHAESTUS] Analysis complete - found {results['total_chains']} vulnerability chains")
        
        # Filter by severity if requested
        chains = results['chains']
        if severity_filter:
            severity_order = ['critical', 'high', 'medium', 'low']
            filter_index = severity_order.index(severity_filter)
            chains = [c for c in chains
                     if severity_order.index(c.severity) <= filter_index]
        
        # Prepare response (limit size for Lambda response)
        response_chains = []
        for chain in chains[:50]:  # Limit to first 50 chains
            response_chains.append({
                'id': chain.id,
                'title': chain.title,
                'description': chain.description,
                'severity': chain.severity,
                'confidence': chain.confidence,
                'phase': chain.innovation_phase,
                'iteration': chain.discovery_iteration,
                'impact': chain.impact,
                'steps': chain.steps[:5],  # Limit steps for response size
                'functions_count': len(chain.functions_involved),
                'entry_points_count': len(chain.entry_points),
                'exploitation_techniques': chain.exploitation_techniques[:5],
                'has_poc': bool(chain.poc_code)
            })
        
        # Store full results in S3 if needed
        result_s3_key = None
        if len(chains) > 50 or any(chain.poc_code for chain in chains):
            # Store full results including POCs in S3
            result_bucket = os.environ.get('RESULTS_BUCKET', s3_bucket)
            # Generate unique key for results
            request_id = datetime.utcnow().strftime('%Y%m%d%H%M%S') + '-' + os.urandom(4).hex()
            result_key = f"hephaestus-results/{request_id}.json"
            
            # Convert chains to serializable format
            full_results = {
                'repository': repo_path,
                'analysis_time': datetime.utcnow().isoformat(),
                'total_chains': len(chains),
                'iterations_completed': results['iterations_completed'],
                'by_severity': results['report']['by_severity'],
                'by_phase': results['report']['by_phase'],
                'chains': [
                    {
                        'id': c.id,
                        'title': c.title,
                        'description': c.description,
                        'severity': c.severity,
                        'confidence': c.confidence,
                        'steps': c.steps,
                        'impact': c.impact,
                        'exploit_scenario': c.exploit_scenario,
                        'mitigations': c.mitigations,
                        'code_locations': c.code_locations,
                        'attack_path': c.attack_path,
                        'functions_involved': c.functions_involved,
                        'entry_points': c.entry_points,
                        'exploitation_techniques': c.exploitation_techniques,
                        'innovation_phase': c.innovation_phase,
                        'discovery_iteration': c.discovery_iteration,
                        'poc_code': c.poc_code
                    }
                    for c in chains
                ]
            }
            
            s3_client.put_object(
                Bucket=result_bucket,
                Key=result_key,
                Body=json.dumps(full_results, indent=2),
                ContentType='application/json'
            )
            result_s3_key = f"s3://{result_bucket}/{result_key}"
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'analysis_complete': True,
                'total_vulnerability_chains': results['total_chains'],
                'iterations_completed': results['iterations_completed'],
                'by_severity': results['report']['by_severity'],
                'by_phase': dict(results['report']['by_phase']),
                'critical_chains_count': len([c for c in chains if c.severity == 'critical']),
                'chains': response_chains,
                'full_results_s3': result_s3_key,
                'message': f"Hephaestus discovered {results['total_chains']} vulnerability chains using {results['iterations_completed']} cognitive iterations"
            })
        }
        
    except Exception as e:
        logger.error(f"[HEPHAESTUS] Analysis failed: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Hephaestus analysis failed: {str(e)}',
                'error_type': type(e).__name__
            })
        }
        
    finally:
        loop.close()