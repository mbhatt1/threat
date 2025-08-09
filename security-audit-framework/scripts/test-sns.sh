#!/bin/bash

# Test script for SNS-triggered security scans
# This script demonstrates various ways to trigger scans via SNS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get SNS topic ARNs from CloudFormation outputs
STACK_PREFIX="SecurityAudit-dev"
REGION=${AWS_REGION:-us-east-1}

echo -e "${YELLOW}Getting SNS topic ARNs...${NC}"
SCAN_TOPIC=$(aws cloudformation describe-stacks \
    --stack-name "${STACK_PREFIX}-SNS" \
    --query "Stacks[0].Outputs[?OutputKey=='ScanRequestTopicArn'].OutputValue" \
    --output text \
    --region ${REGION})

GITHUB_TOPIC=$(aws cloudformation describe-stacks \
    --stack-name "${STACK_PREFIX}-SNS" \
    --query "Stacks[0].Outputs[?OutputKey=='GitHubWebhookTopicArn'].OutputValue" \
    --output text \
    --region ${REGION})

SCHEDULED_TOPIC=$(aws cloudformation describe-stacks \
    --stack-name "${STACK_PREFIX}-SNS" \
    --query "Stacks[0].Outputs[?OutputKey=='ScheduledScanTopicArn'].OutputValue" \
    --output text \
    --region ${REGION})

echo -e "${GREEN}Main Scan Topic: ${SCAN_TOPIC}${NC}"
echo -e "${GREEN}GitHub Topic: ${GITHUB_TOPIC}${NC}"
echo -e "${GREEN}Scheduled Topic: ${SCHEDULED_TOPIC}${NC}"

# Function to publish message and show result
publish_message() {
    local topic=$1
    local message=$2
    local attributes=$3
    local description=$4
    
    echo -e "\n${YELLOW}${description}${NC}"
    echo "Message: ${message}"
    
    if [ -n "$attributes" ]; then
        MESSAGE_ID=$(aws sns publish \
            --topic-arn "$topic" \
            --message "$message" \
            --message-attributes "$attributes" \
            --region ${REGION} \
            --query 'MessageId' \
            --output text)
    else
        MESSAGE_ID=$(aws sns publish \
            --topic-arn "$topic" \
            --message "$message" \
            --region ${REGION} \
            --query 'MessageId' \
            --output text)
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Published successfully. MessageId: ${MESSAGE_ID}${NC}"
    else
        echo -e "${RED}✗ Failed to publish message${NC}"
    fi
}

# Test 1: Simple manual scan
echo -e "\n${YELLOW}=== Test 1: Simple Manual Scan ===${NC}"
publish_message "$SCAN_TOPIC" \
    "https://github.com/example/test-repo.git" \
    '{"scan_enabled":{"DataType":"String","StringValue":"true"}}' \
    "Triggering scan with repository URL as plain text"

# Test 2: Manual scan with options
echo -e "\n${YELLOW}=== Test 2: Manual Scan with Options ===${NC}"
MESSAGE='{
  "type": "manual_scan",
  "repository_url": "https://github.com/example/secure-app.git",
  "branch": "develop",
  "scan_options": {
    "deep_scan": true,
    "cost_limit": 50.0,
    "specific_agents": ["SAST", "SECRETS", "API_SECURITY"]
  }
}'
ATTRIBUTES='{
  "scan_enabled": {"DataType":"String","StringValue":"true"},
  "Priority": {"DataType":"String","StringValue":"high"},
  "Requester": {"DataType":"String","StringValue":"security-team"}
}'
publish_message "$SCAN_TOPIC" "$MESSAGE" "$ATTRIBUTES" "Manual scan with specific options"

# Test 3: GitHub webhook simulation
echo -e "\n${YELLOW}=== Test 3: GitHub Webhook Simulation ===${NC}"
GITHUB_MESSAGE='{
  "ref": "refs/heads/main",
  "after": "abc123def456",
  "repository": {
    "clone_url": "https://github.com/example/webapp.git",
    "name": "webapp",
    "owner": {
      "login": "example"
    },
    "private": false,
    "language": "Python"
  },
  "pusher": {
    "name": "developer"
  }
}'
publish_message "$GITHUB_TOPIC" "$GITHUB_MESSAGE" \
    '{"event_type":{"DataType":"String","StringValue":"push"}}' \
    "GitHub push event"

# Test 4: Scheduled scan
echo -e "\n${YELLOW}=== Test 4: Scheduled Scan ===${NC}"
SCHEDULED_MESSAGE='{
  "type": "scheduled_scan",
  "repository_url": "https://github.com/example/critical-service.git",
  "branch": "main",
  "schedule": "daily",
  "scan_options": {
    "deep_scan": false,
    "priority": "normal"
  }
}'
publish_message "$SCHEDULED_TOPIC" "$SCHEDULED_MESSAGE" "" "Daily scheduled scan"

# Test 5: Custom integration
echo -e "\n${YELLOW}=== Test 5: Custom Integration ===${NC}"
CUSTOM_MESSAGE='{
  "type": "custom_integration",
  "repository_url": "https://gitlab.com/example/microservice.git",
  "branch": "feature/security-fix",
  "integration_name": "CI/CD Pipeline",
  "custom_data": {
    "build_id": "12345",
    "commit_sha": "xyz789",
    "triggered_by": "merge_request"
  },
  "scan_options": {
    "skip_agents": ["IaC"],
    "notification_email": "team@example.com"
  }
}'
CUSTOM_ATTRIBUTES='{
  "scan_enabled": {"DataType":"String","StringValue":"true"},
  "DeepScan": {"DataType":"String","StringValue":"false"},
  "CostLimit": {"DataType":"Number","StringValue":"25.0"}
}'
publish_message "$SCAN_TOPIC" "$CUSTOM_MESSAGE" "$CUSTOM_ATTRIBUTES" "Custom CI/CD integration"

# Test 6: CodeCommit event simulation
echo -e "\n${YELLOW}=== Test 6: CodeCommit Event (requires CodeCommit setup) ===${NC}"
echo "Note: CodeCommit events are automatically sent to the CodeCommit topic when configured"
echo "To set up CodeCommit triggers:"
echo "  aws codecommit put-repository-triggers \\"
echo "    --repository-name YOUR_REPO \\"
echo "    --triggers name=SecurityScan,destinationArn=${SCAN_TOPIC},branches=main,develop,events=all"

# Test 7: Security Hub finding (requires Security Hub)
echo -e "\n${YELLOW}=== Test 7: Security Hub Finding (requires Security Hub setup) ===${NC}"
echo "Note: Security Hub findings are automatically sent when configured"
echo "To test manually, you can create a custom finding in Security Hub"

echo -e "\n${YELLOW}=== Checking scan status ===${NC}"
echo "To check the status of triggered scans:"
echo "1. Check Step Functions console: https://console.aws.amazon.com/states/"
echo "2. Query DynamoDB scan table:"
echo "   aws dynamodb scan --table-name security-scans --limit 5"
echo "3. Check CloudWatch Logs for the SNS handler Lambda"

echo -e "\n${GREEN}Test script completed!${NC}"