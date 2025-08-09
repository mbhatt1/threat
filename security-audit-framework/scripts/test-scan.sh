#!/bin/bash
set -e

# Test Scan Script for Security Audit Framework
# Usage: ./test-scan.sh <repository-url>

REPO_URL="${1:-https://github.com/example/test-repo}"
BRANCH="${2:-main}"

echo "🚀 Starting test scan for repository: $REPO_URL"
echo "📌 Branch: $BRANCH"

# Get API Gateway URL from CloudFormation
API_URL=$(aws cloudformation describe-stacks \
  --stack-name SecurityAuditAPIStack \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
  --output text)

if [ -z "$API_URL" ]; then
  echo "❌ Error: Could not find API Gateway URL"
  exit 1
fi

echo "🔗 API URL: $API_URL"

# Create scan request
SCAN_RESPONSE=$(curl -s -X POST "$API_URL/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "'$REPO_URL'",
    "branch": "'$BRANCH'",
    "scan_options": {
      "agents": ["bedrock_unified", "autonomous_code_analyzer", "autonomous_threat_intel"],
      "deep_scan": true,
      "ai_components": {
        "sql_injection": true,
        "threat_intelligence": true,
        "root_cause": false,
        "pure_ai": true,
        "sandbox": true
      }
    }
  }')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')

if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "null" ]; then
  echo "❌ Error creating scan:"
  echo $SCAN_RESPONSE | jq .
  exit 1
fi

echo "✅ Scan created successfully!"
echo "📝 Scan ID: $SCAN_ID"

# Poll for scan completion
echo "⏳ Waiting for scan to complete..."

while true; do
  STATUS_RESPONSE=$(curl -s "$API_URL/v1/scans/$SCAN_ID/status")
  STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
  PROGRESS=$(echo $STATUS_RESPONSE | jq -r '.progress.percentage // 0')
  
  echo -ne "\r🔄 Status: $STATUS | Progress: $PROGRESS%"
  
  if [ "$STATUS" = "COMPLETED" ]; then
    echo -e "\n✅ Scan completed!"
    break
  elif [ "$STATUS" = "FAILED" ]; then
    echo -e "\n❌ Scan failed!"
    echo $STATUS_RESPONSE | jq .
    exit 1
  fi
  
  sleep 5
done

# Get scan results
echo "📊 Fetching results..."
RESULTS=$(curl -s "$API_URL/v1/scans/$SCAN_ID/results")

# Display summary
echo "📈 Scan Summary:"
echo "================"
echo $RESULTS | jq '{
  total_findings: .summary.total_findings,
  critical: .summary.by_severity.critical,
  high: .summary.by_severity.high,
  medium: .summary.by_severity.medium,
  low: .summary.by_severity.low,
  ai_insights: .ai_analysis.key_insights
}'

# Test AI-specific endpoints
echo -e "\n🤖 Testing AI Security Components..."

# Test SQL Injection Detector
echo "Testing SQL Injection Detector..."
SQL_TEST=$(curl -s -X POST "$API_URL/v1/ai-security/sql-injection" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
    "language": "python"
  }')
echo "Risk Score: $(echo $SQL_TEST | jq -r '.risk_score')"

# Test Threat Intelligence
echo -e "\nTesting Threat Intelligence..."
THREAT_TEST=$(curl -s -X POST "$API_URL/v1/ai-security/threat-intelligence" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_results": {
      "vulnerabilities": ["SQL_INJECTION"],
      "exposed_endpoints": ["/api/users"],
      "technologies": ["python", "flask"]
    }
  }')
echo "Threat Assessment: $(echo $THREAT_TEST | jq -r '.threat_assessment.overall_risk')"

echo -e "\n✅ Test scan completed successfully!"