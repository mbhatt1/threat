#!/usr/bin/env python3
"""
Test script for remediation system
"""
import boto3
import json
import time
import argparse
from datetime import datetime

def test_remediation_lambda(function_name, test_case):
    """Test remediation Lambda with a specific test case"""
    lambda_client = boto3.client('lambda')
    
    print(f"\n{'='*60}")
    print(f"Testing: {test_case['name']}")
    print(f"{'='*60}")
    
    payload = test_case['payload']
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps(payload)
        )
        
        response_payload = json.loads(response['Payload'].read())
        status_code = response.get('StatusCode', 0)
        
        print(f"\nStatus Code: {status_code}")
        print(f"Response: {json.dumps(response_payload, indent=2)}")
        
        if status_code == 200:
            print("✅ Test PASSED")
        else:
            print("❌ Test FAILED")
            
        return status_code == 200
        
    except Exception as e:
        print(f"❌ Test FAILED with error: {str(e)}")
        return False

def get_test_cases():
    """Get test cases for different remediation scenarios"""
    return [
        {
            "name": "AWS Access Key Remediation",
            "payload": {
                "finding_type": "aws_access_key",
                "details": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "user_name": "test-user",
                    "file_path": "config/prod.env",
                    "line_number": 42
                },
                "repository": "test-repo",
                "scan_id": f"test-scan-{int(time.time())}"
            }
        },
        {
            "name": "Secrets Manager Rotation",
            "payload": {
                "finding_type": "aws_secret",
                "details": {
                    "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
                    "secret_value": "exposed-secret-value",
                    "file_path": "src/config.py",
                    "line_number": 15
                },
                "repository": "test-repo",
                "scan_id": f"test-scan-{int(time.time())}"
            }
        },
        {
            "name": "Database Password Rotation",
            "payload": {
                "finding_type": "database_password",
                "details": {
                    "db_instance_id": "test-database",
                    "password": "exposed-password",
                    "file_path": "database/config.json",
                    "line_number": 8
                },
                "repository": "test-repo",
                "scan_id": f"test-scan-{int(time.time())}"
            }
        },
        {
            "name": "SSH Key Management",
            "payload": {
                "finding_type": "ssh_private_key",
                "details": {
                    "key_fingerprint": "SHA256:abcd1234efgh5678",
                    "key_name": "test-key",
                    "file_path": ".ssh/id_rsa",
                    "line_number": 1
                },
                "repository": "test-repo",
                "scan_id": f"test-scan-{int(time.time())}"
            }
        }
    ]

def test_agent_integration(cluster_name, service_name):
    """Test remediation integration with secrets agent"""
    ecs_client = boto3.client('ecs')
    
    print(f"\n{'='*60}")
    print("Testing Agent Integration")
    print(f"{'='*60}")
    
    try:
        # Check if service has ENABLE_REMEDIATION set
        response = ecs_client.describe_services(
            cluster=cluster_name,
            services=[service_name]
        )
        
        if response['services']:
            service = response['services'][0]
            task_def_arn = service['taskDefinition']
            
            # Get task definition
            task_def = ecs_client.describe_task_definition(
                taskDefinition=task_def_arn
            )
            
            # Check environment variables
            container_def = task_def['taskDefinition']['containerDefinitions'][0]
            env_vars = {e['name']: e['value'] for e in container_def.get('environment', [])}
            
            print(f"Service: {service_name}")
            print(f"Task Definition: {task_def_arn}")
            print("\nEnvironment Variables:")
            print(f"  ENABLE_REMEDIATION: {env_vars.get('ENABLE_REMEDIATION', 'NOT SET')}")
            print(f"  REMEDIATION_LAMBDA_NAME: {env_vars.get('REMEDIATION_LAMBDA_NAME', 'NOT SET')}")
            
            if env_vars.get('ENABLE_REMEDIATION') == 'true':
                print("✅ Remediation is ENABLED for this agent")
            else:
                print("❌ Remediation is DISABLED for this agent")
                
        else:
            print(f"❌ Service {service_name} not found")
            
    except Exception as e:
        print(f"❌ Failed to check agent integration: {str(e)}")

def verify_permissions(role_name):
    """Verify IAM permissions for remediation"""
    iam_client = boto3.client('iam')
    
    print(f"\n{'='*60}")
    print("Verifying IAM Permissions")
    print(f"{'='*60}")
    
    required_actions = [
        "iam:DeleteAccessKey",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "secretsmanager:RotateSecret",
        "secretsmanager:UpdateSecret",
        "rds:ModifyDBInstance",
        "ec2:DescribeKeyPairs",
        "ec2:DeleteKeyPair",
        "dynamodb:PutItem",
        "sns:Publish"
    ]
    
    try:
        # Get role policies
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        attached_policies = response['AttachedPolicies']
        
        response = iam_client.list_role_policies(RoleName=role_name)
        inline_policies = response['PolicyNames']
        
        print(f"Role: {role_name}")
        print(f"Attached Policies: {len(attached_policies)}")
        print(f"Inline Policies: {len(inline_policies)}")
        
        # Parse and verify each policy document
        verified_actions = set()
        
        # Check attached policies
        for policy_arn in attached_policies:
            try:
                # Get policy version
                policy_response = iam.get_policy(PolicyArn=policy_arn)
                default_version = policy_response['Policy']['DefaultVersionId']
                
                # Get policy document
                version_response = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version
                )
                policy_doc = version_response['PolicyVersion']['Document']
                
                # Extract allowed actions
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        verified_actions.update(actions)
                        
            except Exception as e:
                print(f"  Warning: Could not retrieve policy {policy_arn}: {e}")
        
        # Check inline policies
        for policy_name in inline_policies:
            try:
                policy_response = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policy_doc = policy_response['PolicyDocument']
                
                # Extract allowed actions
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        verified_actions.update(actions)
                        
            except Exception as e:
                print(f"  Warning: Could not retrieve inline policy {policy_name}: {e}")
        
        # Check required actions
        print("\nPermission Verification:")
        missing_actions = []
        for action in required_actions:
            # Check if action is allowed (including wildcards)
            allowed = False
            for verified_action in verified_actions:
                if verified_action == action or verified_action == '*':
                    allowed = True
                    break
                # Check wildcard patterns like 'ecs:*'
                if '*' in verified_action:
                    prefix = verified_action.replace('*', '')
                    if action.startswith(prefix):
                        allowed = True
                        break
            
            if allowed:
                print(f"  ✅ {action}")
            else:
                print(f"  ❌ {action} (missing)")
                missing_actions.append(action)
        
        if missing_actions:
            print(f"\n⚠️  Missing {len(missing_actions)} required permissions")
        else:
            print("\n✅ All required permissions verified")
        
    except Exception as e:
        print(f"❌ Failed to verify permissions: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Test remediation system')
    parser.add_argument('--function-name', required=True, help='Remediation Lambda function name')
    parser.add_argument('--cluster', help='ECS cluster name')
    parser.add_argument('--service', help='ECS service name for secrets agent')
    parser.add_argument('--role', help='IAM role name to verify permissions')
    parser.add_argument('--test-case', type=int, help='Specific test case index to run')
    
    args = parser.parse_args()
    
    print(f"Remediation System Test - {datetime.now().isoformat()}")
    
    # Test Lambda function
    test_cases = get_test_cases()
    results = []
    
    if args.test_case is not None:
        # Run specific test case
        if 0 <= args.test_case < len(test_cases):
            result = test_remediation_lambda(args.function_name, test_cases[args.test_case])
            results.append(result)
        else:
            print(f"Invalid test case index: {args.test_case}")
    else:
        # Run all test cases
        for test_case in test_cases:
            result = test_remediation_lambda(args.function_name, test_case)
            results.append(result)
            time.sleep(2)  # Avoid rate limiting
    
    # Test agent integration if specified
    if args.cluster and args.service:
        test_agent_integration(args.cluster, args.service)
    
    # Verify permissions if specified
    if args.role:
        verify_permissions(args.role)
    
    # Summary
    print(f"\n{'='*60}")
    print("Test Summary")
    print(f"{'='*60}")
    print(f"Total Tests: {len(results)}")
    print(f"Passed: {sum(results)}")
    print(f"Failed: {len(results) - sum(results)}")
    
    if all(results):
        print("\n✅ All tests PASSED!")
        return 0
    else:
        print("\n❌ Some tests FAILED!")
        return 1

if __name__ == "__main__":
    exit(main())