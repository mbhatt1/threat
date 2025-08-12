#!/bin/bash

# Security Audit Framework Deployment Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Please install AWS CLI."
        exit 1
    fi
    
    # Check CDK CLI
    if ! command -v cdk &> /dev/null; then
        print_error "AWS CDK not found. Please install AWS CDK: npm install -g aws-cdk"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found. Please install Python 3.11 or later."
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker not found. Please install Docker."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure'."
        exit 1
    fi
    
    print_status "All prerequisites met!"
}

# Setup virtual environment
setup_environment() {
    print_status "Setting up Python virtual environment..."
    
    cd cdk
    
    # Create virtual environment if it doesn't exist
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt
    
    cd ..
}

# Bootstrap CDK (if needed)
bootstrap_cdk() {
    print_status "Checking CDK bootstrap status..."
    
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    REGION=$(aws configure get region)
    
    if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region $REGION &> /dev/null; then
        print_status "Bootstrapping CDK in region $REGION..."
        cdk bootstrap aws://$ACCOUNT_ID/$REGION
    else
        print_status "CDK already bootstrapped in region $REGION"
    fi
}

# Deploy stacks
deploy_stacks() {
    cd cdk
    source .venv/bin/activate
    
    # Get deployment environment
    ENV=${1:-dev}
    print_status "Deploying to environment: $ENV"
    
    # Synthesize the app
    print_status "Synthesizing CDK app..."
    cdk synth --context env=$ENV
    
    # Deploy all stacks
    print_status "Deploying all stacks..."
    cdk deploy --all --require-approval never --context env=$ENV
    
    cd ..
}

# Post-deployment tasks
post_deployment() {
    print_status "Running post-deployment tasks..."
    
    # Get API endpoint
    API_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name SecurityAudit-${ENV}-API \
        --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
        --output text)
    
    if [ ! -z "$API_ENDPOINT" ]; then
        print_status "API Endpoint: $API_ENDPOINT"
        
        # Save to config file
        echo "API_ENDPOINT=$API_ENDPOINT" > .env.${ENV}
    fi
    
    print_status "Deployment complete!"
    print_status "Dashboard URL: https://console.aws.amazon.com/cloudwatch/home?region=$REGION#dashboards:name=security-audit-overview"
}

# Main execution
main() {
    print_status "Starting Security Audit Framework deployment..."
    
    check_prerequisites
    setup_environment
    bootstrap_cdk
    
    # Get environment from command line argument
    ENV=${1:-dev}
    
    # Confirm deployment
    print_warning "This will deploy the Security Audit Framework to AWS account $ACCOUNT_ID in region $REGION"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        deploy_stacks $ENV
        post_deployment
    else
        print_status "Deployment cancelled."
    fi
}

# Run main function
main $@