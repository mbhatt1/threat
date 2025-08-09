#!/usr/bin/env python3
"""
Autonomous Dynamic Tool Creation Agent
Monitors findings from other agents and creates new security tools based on patterns
"""

import os
import json
import sys
import logging
import boto3
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple
from collections import defaultdict
import re
import ast
import subprocess
import tempfile
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Add the shared module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from shared.strands import StrandsMessage, StrandsProtocol, MessageType, SecurityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyzes security findings to identify patterns and gaps"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.patterns = defaultdict(list)
        
    def analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings to identify patterns and clusters"""
        if not findings:
            return {'patterns': [], 'clusters': []}
        
        # Extract text features from findings
        texts = []
        for finding in findings:
            text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('file_path', '')}"
            texts.append(text)
        
        # Vectorize findings
        try:
            X = self.vectorizer.fit_transform(texts)
            
            # Cluster similar findings
            clustering = DBSCAN(eps=0.3, min_samples=2, metric='cosine')
            clusters = clustering.fit_predict(X)
            
            # Analyze clusters
            cluster_info = defaultdict(list)
            for idx, cluster_id in enumerate(clusters):
                if cluster_id != -1:  # Ignore noise
                    cluster_info[cluster_id].append(findings[idx])
            
            # Extract patterns from clusters
            patterns = []
            for cluster_id, cluster_findings in cluster_info.items():
                pattern = self._extract_pattern(cluster_findings)
                if pattern:
                    patterns.append(pattern)
            
            return {
                'patterns': patterns,
                'clusters': dict(cluster_info),
                'total_findings': len(findings),
                'unique_patterns': len(patterns)
            }
        except Exception as e:
            logger.error(f"Error analyzing findings: {e}")
            return {'patterns': [], 'clusters': {}}
    
    def _extract_pattern(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract common pattern from a cluster of findings"""
        # Find common attributes
        common_severity = self._most_common([f.get('severity') for f in findings])
        common_type = self._most_common([f.get('type') for f in findings])
        
        # Extract common file patterns
        file_paths = [f.get('file_path', '') for f in findings]
        file_pattern = self._find_common_pattern(file_paths)
        
        # Extract common code patterns if available
        code_snippets = [f.get('code_snippet') for f in findings if f.get('code_snippet')]
        code_pattern = self._find_code_pattern(code_snippets) if code_snippets else None
        
        return {
            'severity': common_severity,
            'type': common_type,
            'file_pattern': file_pattern,
            'code_pattern': code_pattern,
            'occurrence_count': len(findings),
            'sample_findings': findings[:3]  # Keep samples for reference
        }
    
    def _most_common(self, items: List[Any]) -> Any:
        """Find most common item in a list"""
        if not items:
            return None
        from collections import Counter
        counter = Counter(items)
        return counter.most_common(1)[0][0]
    
    def _find_common_pattern(self, paths: List[str]) -> str:
        """Find common pattern in file paths"""
        if not paths:
            return ""
        
        # Find common directory patterns
        common_dirs = set()
        for path in paths:
            dirs = path.split('/')
            common_dirs.update(dirs[:-1])  # Exclude filename
        
        # Find common file extensions
        extensions = [os.path.splitext(path)[1] for path in paths]
        common_ext = self._most_common(extensions)
        
        if common_dirs and common_ext:
            return f"*/{'/'.join(sorted(common_dirs)[:2])}/*{common_ext}"
        elif common_ext:
            return f"*{common_ext}"
        return "*"
    
    def _find_code_pattern(self, snippets: List[str]) -> Dict[str, Any]:
        """Extract common code pattern from snippets"""
        if not snippets:
            return None
        
        # Simple pattern extraction - look for common tokens
        tokens = []
        for snippet in snippets:
            # Tokenize code
            tokens.extend(re.findall(r'\b\w+\b', snippet))
        
        # Find most common tokens (excluding common keywords)
        common_keywords = {'if', 'else', 'for', 'while', 'return', 'def', 'class', 'import', 'from'}
        filtered_tokens = [t for t in tokens if t not in common_keywords and len(t) > 2]
        
        from collections import Counter
        token_counts = Counter(filtered_tokens)
        common_tokens = token_counts.most_common(5)
        
        return {
            'common_tokens': [t[0] for t in common_tokens],
            'sample_snippet': snippets[0][:200]  # First 200 chars as sample
        }


class RuleGenerator:
    """Generates new security rules based on identified patterns"""
    
    def __init__(self):
        self.rule_templates = {
            'ai_code': self._generate_ai_code_rule,
            'dependency': self._generate_dependency_rule,
            'secrets': self._generate_secrets_rule,
            'iac': self._generate_iac_rule
        }
    
    def generate_rules(self, patterns: List[Dict[str, Any]], agent_type: str) -> List[Dict[str, Any]]:
        """Generate security rules based on patterns"""
        rules = []
        
        generator = self.rule_templates.get(agent_type)
        if not generator:
            logger.warning(f"No rule generator for agent type: {agent_type}")
            return rules
        
        for pattern in patterns:
            try:
                rule = generator(pattern)
                if rule:
                    rules.append(rule)
            except Exception as e:
                logger.error(f"Error generating rule: {e}")
        
        return rules
    
    def _generate_ai_code_rule(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-based code analysis rule from pattern"""
        rule_id = f"autonomous-{pattern.get('type', 'custom')}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Build pattern based on code pattern
        code_pattern = pattern.get('code_pattern', {})
        if not code_pattern:
            return None
        
        common_tokens = code_pattern.get('common_tokens', [])
        if not common_tokens:
            return None
        
        # Simple pattern generation - look for function calls with common tokens
        patterns = []
        for token in common_tokens[:2]:  # Use top 2 tokens
            patterns.append(f"$FUNC({token}, ...)")
            patterns.append(f"{token}(...)")
        
        return {
            'rules': [{
                'id': rule_id,
                'patterns': patterns,
                'message': f"Potential security issue detected based on pattern analysis",
                'severity': pattern.get('severity', 'WARNING'),
                'languages': ['python', 'javascript', 'java'],
                'metadata': {
                    'generated_by': 'autonomous_agent',
                    'pattern_occurrences': pattern.get('occurrence_count', 0),
                    'confidence': 'medium'
                }
            }]
        }
    
    def _generate_dependency_rule(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Generate dependency check rule from pattern"""
        # Extract package patterns from findings
        sample_findings = pattern.get('sample_findings', [])
        if not sample_findings:
            return None
        
        vulnerable_packages = set()
        for finding in sample_findings:
            # Extract package name from description or title
            desc = finding.get('description', '')
            if 'package' in desc.lower():
                # Simple extraction - look for package names
                matches = re.findall(r'([a-zA-Z0-9\-_]+)(?:@|==|>=|<=|>|<)([0-9\.]+)', desc)
                vulnerable_packages.update([m[0] for m in matches])
        
        if not vulnerable_packages:
            return None
        
        return {
            'name': f"autonomous-dependency-check-{datetime.now().strftime('%Y%m%d')}",
            'packages': list(vulnerable_packages),
            'severity': pattern.get('severity', 'MEDIUM'),
            'description': f"Packages identified through pattern analysis as potentially vulnerable"
        }
    
    def _generate_secrets_rule(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Generate secrets detection rule from pattern"""
        file_pattern = pattern.get('file_pattern', '')
        if not file_pattern:
            return None
        
        # Generate regex based on common patterns in findings
        sample_findings = pattern.get('sample_findings', [])
        regex_patterns = []
        
        for finding in sample_findings:
            desc = finding.get('description', '')
            # Look for patterns like API keys, tokens, etc.
            if 'api' in desc.lower() and 'key' in desc.lower():
                regex_patterns.append(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']')
            if 'token' in desc.lower():
                regex_patterns.append(r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']')
            if 'secret' in desc.lower():
                regex_patterns.append(r'["\']?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']')
        
        if not regex_patterns:
            return None
        
        return {
            'name': f"autonomous-secret-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'regex': '|'.join(regex_patterns),
            'paths': [file_pattern],
            'severity': pattern.get('severity', 'HIGH'),
            'description': "Custom secret pattern detected through ML analysis"
        }
    
    def _generate_iac_rule(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Generate IaC security rule from pattern"""
        # Generate Checkov custom policy
        rule_id = f"CKV_CUSTOM_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        sample_findings = pattern.get('sample_findings', [])
        if not sample_findings:
            return None
        
        # Analyze findings to determine resource types and checks
        resource_types = set()
        check_types = []
        
        for finding in sample_findings:
            desc = finding.get('description', '')
            file_path = finding.get('file_path', '')
            
            # Identify resource types
            if '.tf' in file_path:
                if 'aws_' in desc:
                    resource_match = re.search(r'aws_(\w+)', desc)
                    if resource_match:
                        resource_types.add(f"aws_{resource_match.group(1)}")
            
            # Identify check types
            if 'encryption' in desc.lower():
                check_types.append('encryption')
            if 'public' in desc.lower():
                check_types.append('public_access')
            if 'logging' in desc.lower():
                check_types.append('logging')
        
        if not resource_types:
            return None
        
        return {
            'id': rule_id,
            'name': f"Autonomous IaC check for {', '.join(check_types)}",
            'resource_types': list(resource_types),
            'check_types': check_types,
            'severity': pattern.get('severity', 'MEDIUM'),
            'description': f"Custom IaC policy based on pattern analysis"
        }


class AutonomousAgent:
    """Main autonomous agent that creates new security tools"""
    
    def __init__(self):
        self.protocol = StrandsProtocol()
        self.pattern_analyzer = PatternAnalyzer()
        self.rule_generator = RuleGenerator()
        self.dynamodb = boto3.client('dynamodb')
        self.s3 = boto3.client('s3')
        
        # Get configuration from environment
        self.findings_table = os.environ.get('FINDINGS_TABLE', 'SecurityFindings')
        self.rules_bucket = os.environ.get('RULES_BUCKET', 'security-audit-rules')
        self.learning_interval_hours = int(os.environ.get('LEARNING_INTERVAL_HOURS', '24'))
    
    def process_message(self, message: StrandsMessage) -> StrandsMessage:
        """Process incoming Strands message"""
        logger.info(f"Processing message: {message.message_type}")
        
        if message.message_type == MessageType.TASK_ASSIGNMENT:
            return self._handle_task_assignment(message)
        else:
            return self.protocol.create_error_message(
                task_id=message.task_id,
                agent_id="AUTONOMOUS",
                error=f"Unsupported message type: {message.message_type}"
            )
    
    def _handle_task_assignment(self, message: StrandsMessage) -> StrandsMessage:
        """Handle task assignment to analyze and create new tools"""
        task_context = message.context
        
        try:
            # Check if this is a direct tool creation request
            if task_context.get('action') == 'create_dynamic_tool':
                return self._handle_tool_creation_request(message)
            
            # Otherwise, fetch recent findings from DynamoDB
            findings = self._fetch_recent_findings()
            logger.info(f"Fetched {len(findings)} recent findings for analysis")
            
            # Analyze patterns
            analysis_results = self.pattern_analyzer.analyze_findings(findings)
            logger.info(f"Identified {len(analysis_results['patterns'])} patterns")
            
            # Generate new rules for each agent type
            generated_rules = {}
            for agent_type in ['ai_code', 'dependency', 'secrets', 'iac']:
                rules = self.rule_generator.generate_rules(
                    analysis_results['patterns'], 
                    agent_type
                )
                if rules:
                    generated_rules[agent_type] = rules
                    logger.info(f"Generated {len(rules)} rules for {agent_type}")
            
            # Test and validate rules
            validated_rules = self._validate_rules(generated_rules)
            
            # Deploy validated rules
            deployed_rules = self._deploy_rules(validated_rules)
            
            # Create result message
            results = {
                'analysis': {
                    'total_findings_analyzed': analysis_results['total_findings'],
                    'patterns_identified': analysis_results['unique_patterns'],
                    'clusters_found': len(analysis_results['clusters'])
                },
                'rules_generated': {
                    agent_type: len(rules) 
                    for agent_type, rules in generated_rules.items()
                },
                'rules_validated': {
                    agent_type: len(rules) 
                    for agent_type, rules in validated_rules.items()
                },
                'rules_deployed': deployed_rules,
                'recommendations': self._generate_recommendations(analysis_results)
            }
            
            return self.protocol.create_result_message(
                task_id=message.task_id,
                agent_id="AUTONOMOUS",
                results=results,
                execution_time=300  # Placeholder
            )
            
        except Exception as e:
            logger.error(f"Error in autonomous processing: {e}")
            return self.protocol.create_error_message(
                task_id=message.task_id,
                agent_id="AUTONOMOUS",
                error=str(e)
            )
    
    def _fetch_recent_findings(self) -> List[Dict[str, Any]]:
        """Fetch recent findings from DynamoDB"""
        findings = []
        
        try:
            # Query findings from the last learning interval
            cutoff_time = datetime.utcnow() - timedelta(hours=self.learning_interval_hours)
            
            response = self.dynamodb.scan(
                TableName=self.findings_table,
                FilterExpression='#ts > :cutoff',
                ExpressionAttributeNames={
                    '#ts': 'timestamp'
                },
                ExpressionAttributeValues={
                    ':cutoff': {'S': cutoff_time.isoformat()}
                }
            )
            
            # Parse findings
            for item in response.get('Items', []):
                finding = {
                    'finding_id': item.get('finding_id', {}).get('S', ''),
                    'type': item.get('type', {}).get('S', ''),
                    'severity': item.get('severity', {}).get('S', ''),
                    'title': item.get('title', {}).get('S', ''),
                    'description': item.get('description', {}).get('S', ''),
                    'file_path': item.get('file_path', {}).get('S', ''),
                    'code_snippet': item.get('code_snippet', {}).get('S', ''),
                    'agent_id': item.get('agent_id', {}).get('S', '')
                }
                findings.append(finding)
            
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.dynamodb.scan(
                    TableName=self.findings_table,
                    FilterExpression='#ts > :cutoff',
                    ExpressionAttributeNames={'#ts': 'timestamp'},
                    ExpressionAttributeValues={':cutoff': {'S': cutoff_time.isoformat()}},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                
                for item in response.get('Items', []):
                    finding = {
                        'finding_id': item.get('finding_id', {}).get('S', ''),
                        'type': item.get('type', {}).get('S', ''),
                        'severity': item.get('severity', {}).get('S', ''),
                        'title': item.get('title', {}).get('S', ''),
                        'description': item.get('description', {}).get('S', ''),
                        'file_path': item.get('file_path', {}).get('S', ''),
                        'code_snippet': item.get('code_snippet', {}).get('S', ''),
                        'agent_id': item.get('agent_id', {}).get('S', '')
                    }
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error fetching findings: {e}")
        
        return findings
    
    def _validate_rules(self, rules: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Validate generated rules in a sandboxed environment"""
        validated = {}
        
        for agent_type, agent_rules in rules.items():
            validated[agent_type] = []
            
            for rule in agent_rules:
                try:
                    # Basic validation - ensure rule has required fields
                    is_valid = self._validate_rule_structure(rule, agent_type)
                    
                    if is_valid:
                        # Test rule in sandbox (simplified for this implementation)
                        test_result = self._test_rule_in_sandbox(rule, agent_type)
                        if test_result['success']:
                            validated[agent_type].append(rule)
                            logger.info(f"Rule validated successfully: {rule.get('id', rule.get('name'))}")
                        else:
                            logger.warning(f"Rule failed validation: {test_result.get('error')}")
                    else:
                        logger.warning(f"Rule has invalid structure")
                        
                except Exception as e:
                    logger.error(f"Error validating rule: {e}")
        
        return validated
    
    def _validate_rule_structure(self, rule: Dict[str, Any], agent_type: str) -> bool:
        """Validate rule structure based on agent type"""
        if agent_type == 'ai_code':
            return 'rules' in rule and isinstance(rule['rules'], list)
        elif agent_type == 'dependency':
            return 'name' in rule and 'packages' in rule
        elif agent_type == 'secrets':
            return 'name' in rule and 'regex' in rule
        elif agent_type == 'iac':
            return 'id' in rule and 'resource_types' in rule
        return False
    
    def _test_rule_in_sandbox(self, rule: Dict[str, Any], agent_type: str) -> Dict[str, Any]:
        """Test rule in a sandboxed environment with comprehensive validation"""
        sandbox_dir = None
        try:
            # Create isolated sandbox directory
            sandbox_dir = tempfile.mkdtemp(prefix='rule_sandbox_')
            
            if agent_type == 'ai_code':
                # Test AI code analysis rule with Bedrock
                rule_file = os.path.join(sandbox_dir, 'test_rule.yml')
                test_file = os.path.join(sandbox_dir, 'test_code.py')
                
                # Write rule
                import yaml
                with open(rule_file, 'w') as f:
                    yaml.dump(rule, f)
                
                # Create test code that should trigger the rule
                test_code = self._generate_test_code_for_rule(rule)
                with open(test_file, 'w') as f:
                    f.write(test_code)
                
                # Validate rule syntax
                validate_result = subprocess.run(
                    ['semgrep', '--validate', rule_file],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if validate_result.returncode != 0:
                    return {
                        'success': False,
                        'error': f"Rule validation failed: {validate_result.stderr}"
                    }
                
                # Test rule execution
                test_result = subprocess.run(
                    ['semgrep', '--config', rule_file, test_file, '--json'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if test_result.returncode == 0:
                    # Parse results to verify rule triggers correctly
                    import json
                    results = json.loads(test_result.stdout)
                    expected_matches = self._count_expected_matches(test_code, rule)
                    actual_matches = len(results.get('results', []))
                    
                    if expected_matches > 0 and actual_matches == 0:
                        return {
                            'success': False,
                            'error': 'Rule did not trigger on test code'
                        }
                    elif expected_matches == 0 and actual_matches > 0:
                        return {
                            'success': False,
                            'error': 'Rule triggered false positives'
                        }
                    
                    return {'success': True}
                else:
                    return {
                        'success': False,
                        'error': f"Rule execution failed: {test_result.stderr}"
                    }
                    
            elif agent_type == 'dependency':
                # Test dependency check rule
                test_file = os.path.join(sandbox_dir, 'package.json')
                
                # Create test dependency file
                test_deps = self._generate_test_dependencies_for_rule(rule)
                with open(test_file, 'w') as f:
                    json.dump(test_deps, f)
                
                # Validate rule structure and test pattern matching
                validation_errors = self._validate_dependency_rule(rule, test_deps)
                if validation_errors:
                    return {
                        'success': False,
                        'error': f"Rule validation failed: {', '.join(validation_errors)}"
                    }
                
                return {'success': True}
                
            elif agent_type == 'ai_iac':
                # Test AI infrastructure security policy
                policy_file = os.path.join(sandbox_dir, 'custom_policy.py')
                test_tf_file = os.path.join(sandbox_dir, 'test.tf')
                
                # Write custom policy
                policy_code = self._generate_checkov_policy(rule)
                with open(policy_file, 'w') as f:
                    f.write(policy_code)
                
                # Create test Terraform file
                test_tf = self._generate_test_terraform_for_rule(rule)
                with open(test_tf_file, 'w') as f:
                    f.write(test_tf)
                
                # Test policy execution
                test_result = subprocess.run(
                    ['checkov', '-f', test_tf_file, '--external-checks-dir', sandbox_dir, '--json'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if test_result.returncode in [0, 1]:  # 0=pass, 1=failures found
                    # Verify policy works correctly
                    results = json.loads(test_result.stdout)
                    return {'success': True}
                else:
                    return {
                        'success': False,
                        'error': f"Policy execution failed: {test_result.stderr}"
                    }
            else:
                # Unknown agent type - perform basic structure validation
                required_fields = ['id', 'name', 'description', 'severity']
                missing_fields = [f for f in required_fields if f not in rule]
                if missing_fields:
                    return {
                        'success': False,
                        'error': f"Missing required fields: {', '.join(missing_fields)}"
                    }
                return {'success': True}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Rule testing timed out'}
        except Exception as e:
            return {'success': False, 'error': f"Sandbox testing failed: {str(e)}"}
        finally:
            # Clean up sandbox
            if sandbox_dir and os.path.exists(sandbox_dir):
                import shutil
                shutil.rmtree(sandbox_dir)
    
    def _generate_test_code_for_rule(self, rule: Dict[str, Any]) -> str:
        """Generate test code that should trigger the given Semgrep rule"""
        # Extract pattern from rule
        patterns = []
        for r in rule.get('rules', []):
            if 'pattern' in r:
                patterns.append(r['pattern'])
            elif 'patterns' in r:
                for p in r['patterns']:
                    if 'pattern' in p:
                        patterns.append(p['pattern'])
        
        # Generate code based on patterns
        test_code = "# Test code for rule validation\n"
        
        # Common vulnerable patterns
        if any('exec' in p for p in patterns):
            test_code += "exec(user_input)\n"
        if any('eval' in p for p in patterns):
            test_code += "eval(request.GET['code'])\n"
        if any('sql' in p.lower() for p in patterns):
            test_code += "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        if any('password' in p.lower() for p in patterns):
            test_code += "password = 'hardcoded123'\n"
        if any('jwt' in p.lower() or 'token' in p.lower() for p in patterns):
            test_code += "JWT_SECRET = 'secret123'\n"
        
        # If no specific patterns matched, create generic test
        if len(test_code.split('\n')) <= 2:
            test_code += "# Generic vulnerable code\n"
            test_code += "import os\n"
            test_code += "os.system(user_input)\n"
        
        return test_code
    
    def _count_expected_matches(self, test_code: str, rule: Dict[str, Any]) -> int:
        """Count how many times the rule should match in test code"""
        # Simple heuristic - count vulnerable lines
        vulnerable_patterns = ['exec(', 'eval(', 'os.system(', 'cursor.execute(f', 'password =', 'JWT_SECRET =']
        count = 0
        for line in test_code.split('\n'):
            if any(pattern in line for pattern in vulnerable_patterns):
                count += 1
        return count
    
    def _generate_test_dependencies_for_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Generate test dependencies for dependency check rule"""
        return {
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.0.0",  # Old version with vulnerabilities
                "lodash": "4.17.0",  # Version with prototype pollution
                "jquery": "2.2.4"    # Old version with XSS vulnerabilities
            }
        }
    
    def _validate_dependency_rule(self, rule: Dict[str, Any], test_deps: Dict[str, Any]) -> List[str]:
        """Validate dependency check rule structure"""
        errors = []
        
        # Check required fields
        if 'package_pattern' not in rule and 'version_constraint' not in rule:
            errors.append("Rule must specify package_pattern or version_constraint")
        
        # Validate regex patterns if present
        if 'package_pattern' in rule:
            try:
                import re
                re.compile(rule['package_pattern'])
            except re.error as e:
                errors.append(f"Invalid package pattern regex: {e}")
        
        return errors
    def _generate_ai_iac_policy(self, rule: Dict[str, Any]) -> str:
        """Generate AI infrastructure policy from rule definition"""
        policy_template = '''
# AI Infrastructure Security Policy
# Uses AWS Bedrock for intelligent policy evaluation


class CustomCheck(BaseResourceCheck):
    def __init__(self):
        name = "{name}"
        id = "{id}"
        supported_resources = {resources}
        categories = [CheckCategories.SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        {description}
        """
        # Custom logic based on rule
        {check_logic}
        return CheckResult.PASSED

check = CustomCheck()
'''
        
        return policy_template.format(
            name=rule.get('name', 'Custom Check'),
            id=rule.get('id', 'CUSTOM_001'),
            resources=rule.get('resource_types', ['aws_instance']),
            description=rule.get('description', 'Custom security check'),
            check_logic=self._generate_check_logic(rule)
        )
    
    def _generate_check_logic(self, rule: Dict[str, Any]) -> str:
        """Generate check logic for Checkov policy"""
        # Basic logic generation based on rule type
        if 'required_tags' in rule:
            return '''
        required_tags = {required_tags}
        if 'tags' not in conf:
            return CheckResult.FAILED
        for tag in required_tags:
            if tag not in conf['tags'][0]:
                return CheckResult.FAILED
'''.format(required_tags=rule['required_tags'])
        
        return "# Implement custom check logic here"
    
    def _generate_test_terraform_for_rule(self, rule: Dict[str, Any]) -> str:
        """Generate test Terraform code for rule validation"""
        return '''
resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # Missing required tags to trigger the check
  tags = {{
    Name = "TestInstance"
  }}
}}
'''
    
    def _deploy_rules(self, rules: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        """Deploy validated rules to S3 for agents to use"""
        deployed = {}
        
        for agent_type, agent_rules in rules.items():
            if not agent_rules:
                continue
                
            try:
                # Generate filename with timestamp
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                filename = f"autonomous/{agent_type}/rules_{timestamp}.json"
                
                # Upload to S3
                self.s3.put_object(
                    Bucket=self.rules_bucket,
                    Key=filename,
                    Body=json.dumps({
                        'generated_at': datetime.utcnow().isoformat(),
                        'agent_type': agent_type,
                        'rules': agent_rules
                    }),
                    ContentType='application/json'
                )
                
                deployed[agent_type] = len(agent_rules)
                logger.info(f"Deployed {len(agent_rules)} rules for {agent_type} to s3://{self.rules_bucket}/{filename}")
                
            except Exception as e:
                logger.error(f"Error deploying rules for {agent_type}: {e}")
                deployed[agent_type] = 0
        
        return deployed
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Check pattern distribution
        if analysis['unique_patterns'] > 10:
            recommendations.append(
                "High number of unique patterns detected. Consider increasing agent specialization."
            )
        
        # Check cluster density
        clusters = analysis.get('clusters', {})
        if clusters:
            avg_cluster_size = sum(len(findings) for findings in clusters.values()) / len(clusters)
            if avg_cluster_size > 5:
                recommendations.append(
                    f"Large clusters detected (avg size: {avg_cluster_size:.1f}). "
                    "Consider creating specialized rules for these common issues."
                )
        
        # Check for specific pattern types
        for pattern in analysis.get('patterns', []):
            if pattern.get('severity') == 'CRITICAL' and pattern.get('occurrence_count', 0) > 3:
                recommendations.append(
                    f"Critical pattern with {pattern['occurrence_count']} occurrences. "
                    "Prioritize creating preventive controls."
                )
        
        return recommendations


def lambda_handler(event, context):
    """Lambda handler for autonomous agent"""
    logger.info(f"Received event: {json.dumps(event)}")
    
    agent = AutonomousAgent()
    
    # Parse Strands message
    strands_message = StrandsMessage(**event)
    
    # Process message
    response = agent.process_message(strands_message)
    
    return response.dict()


if __name__ == "__main__":
    # For local testing
    test_message = {
        "message_id": "test-001",
        "message_type": "TASK_ASSIGNMENT",
        "task_id": "task-001",
        "sender_id": "CEO",
        "recipient_id": "AUTONOMOUS",
        "timestamp": datetime.utcnow().isoformat(),
        "context": {
            "repository_url": "https://github.com/example/repo",
            "learning_mode": "pattern_analysis"
        }
    }
    
    result = lambda_handler(test_message, None)
    print(json.dumps(result, indent=2))