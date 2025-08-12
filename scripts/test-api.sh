#!/bin/bash

# Test script for Security Audit Framework API
set -e

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if API endpoint is provided
if [ -z "$1" ]; then
    # Try to read from .env file
    if [ -f ".env.dev" ]; then
        source .env.dev
    else
        print_error "Usage: $0 <API_ENDPOINT> or set API_ENDPOINT in .env.dev"
        exit 1
    fi
else
    API_ENDPOINT=$1
fi

# Sample repository for testing
TEST_REPO="https://github.com/juice-shop/juice-shop"
TEST_BRANCH="master"

print_status "Testing Security Audit Framework API"
print_status "API Endpoint: $API_ENDPOINT"

# Check AWS credentials
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    print_warning "AWS credentials not found in environment"
    print_status "Attempting to use AWS CLI credentials..."
    export AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id)
    export AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)
    export AWS_REGION=$(aws configure get region)
fi

if [ -z "$AWS_REGION" ]; then
    export AWS_REGION="us-east-1"
    print_warning "AWS_REGION not set, defaulting to us-east-1"
fi

# Function to make API call
api_call() {
    local method=$1
    local path=$2
    local data=$3
    
    if [ -z "$data" ]; then
        curl -s -X $method \
            --user $AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY \
            --aws-sigv4 "aws:amz:${AWS_REGION}:execute-api" \
            -H "Content-Type: application/json" \
            "${API_ENDPOINT}${path}"
    else
        curl -s -X $method \
            --user $AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY \
            --aws-sigv4 "aws:amz:${AWS_REGION}:execute-api" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "${API_ENDPOINT}${path}"
    fi
}

# Test 1: Start a new scan
print_status "Test 1: Starting a new security scan..."

SCAN_REQUEST='{
  "repo_url": "'$TEST_REPO'",
  "branch": "'$TEST_BRANCH'",
  "priority": "normal"
}'

RESPONSE=$(api_call POST "/scans" "$SCAN_REQUEST")
echo "Response: $RESPONSE"

# Extract scan_id from response
SCAN_ID=$(echo $RESPONSE | jq -r '.scan_id')

if [ "$SCAN_ID" == "null" ] || [ -z "$SCAN_ID" ]; then
    print_error "Failed to start scan"
    exit 1
fi

print_status "Scan started successfully! Scan ID: $SCAN_ID"

# Test 2: Get scan status
print_status "Test 2: Checking scan status..."

sleep 5  # Wait a bit before checking

RESPONSE=$(api_call GET "/scans/$SCAN_ID")
echo "Response: $RESPONSE"

STATUS=$(echo $RESPONSE | jq -r '.status')
print_status "Scan status: $STATUS"

# Test 3: List all scans
print_status "Test 3: Listing recent scans..."

RESPONSE=$(api_call GET "/scans?limit=5")
echo "Response: $RESPONSE"

# Test 4: Monitor scan progress
print_status "Test 4: Monitoring scan progress..."

MAX_WAIT=300  # 5 minutes
ELAPSED=0
INTERVAL=10

while [ $ELAPSED -lt $MAX_WAIT ]; do
    RESPONSE=$(api_call GET "/scans/$SCAN_ID")
    STATUS=$(echo $RESPONSE | jq -r '.status')
    
    print_status "Current status: $STATUS"
    
    if [ "$STATUS" == "COMPLETED" ] || [ "$STATUS" == "FAILED" ]; then
        break
    fi
    
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ "$STATUS" == "COMPLETED" ]; then
    print_status "Scan completed successfully!"
    
    # Get final results
    TOTAL_FINDINGS=$(echo $RESPONSE | jq -r '.total_findings // 0')
    print_status "Total findings: $TOTAL_FINDINGS"
    
elif [ "$STATUS" == "FAILED" ]; then
    print_error "Scan failed!"
    exit 1
else
    print_warning "Scan is still running after $MAX_WAIT seconds"
fi

print_status "API tests completed!"