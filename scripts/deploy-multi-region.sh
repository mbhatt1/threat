#!/bin/bash
set -euo pipefail

# Multi-region deployment script for AI Security Audit Framework
# This script deploys the framework across multiple AWS regions

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="${ENVIRONMENT:-dev}"
AWS_PROFILE="${AWS_PROFILE:-default}"
PRIMARY_REGION="us-east-1"
STACK_PREFIX="AISecurityAudit"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed"
        exit 1
    fi
    
    # Check CDK
    if ! command -v cdk &> /dev/null; then
        print_error "AWS CDK is not installed"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity --profile "$AWS_PROFILE" &> /dev/null; then
        print_error "AWS credentials not configured for profile: $AWS_PROFILE"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

# Function to get regions based on environment
get_deployment_regions() {
    case $ENVIRONMENT in
        dev)
            echo "us-east-1"
            ;;
        staging)
            echo "us-east-1 us-west-2"
            ;;
        prod)
            echo "us-east-1 us-west-2 eu-west-1 ap-southeast-1"
            ;;
        *)
            print_error "Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac
}

# Function to bootstrap CDK in a region
bootstrap_region() {
    local region=$1
    print_info "Bootstrapping CDK in region: $region"
    
    if cdk bootstrap "aws://${AWS_ACCOUNT_ID}/${region}" \
        --profile "$AWS_PROFILE" \
        --context environment="$ENVIRONMENT" 2>&1 | grep -q "already bootstrapped"; then
        print_info "Region $region already bootstrapped"
    else
        print_success "Successfully bootstrapped region: $region"
    fi
}

# Function to deploy stacks in a region
deploy_region() {
    local region=$1
    local is_primary=$2
    
    print_info "Deploying to region: $region (Primary: $is_primary)"
    
    # Set region-specific context
    local context_args=(
        "--context" "environment=$ENVIRONMENT"
        "--context" "region=$region"
        "--context" "isPrimaryRegion=$is_primary"
    )
    
    # Deploy shared infrastructure first (only in primary region)
    if [ "$is_primary" == "true" ]; then
        print_info "Deploying shared infrastructure stacks..."
        
        # Deploy parameter stack
        cdk deploy "${STACK_PREFIX}ParametersStack-${ENVIRONMENT}" \
            --profile "$AWS_PROFILE" \
            --region "$region" \
            --require-approval never \
            "${context_args[@]}"
        
        # Deploy IAM stack (global)
        cdk deploy "${STACK_PREFIX}IAMStack-${ENVIRONMENT}" \
            --profile "$AWS_PROFILE" \
            --region "$region" \
            --require-approval never \
            "${context_args[@]}"
    fi
    
    # Deploy regional stacks
    print_info "Deploying regional stacks..."
    
    # Deploy in order of dependencies
    local stacks=(
        "${STACK_PREFIX}NetworkStack-${ENVIRONMENT}"
        "${STACK_PREFIX}StorageStack-${ENVIRONMENT}"
        "${STACK_PREFIX}LambdaStack-${ENVIRONMENT}"
        "${STACK_PREFIX}EventBridgeStack-${ENVIRONMENT}"
        "${STACK_PREFIX}MonitoringStack-${ENVIRONMENT}"
        "${STACK_PREFIX}APIStack-${ENVIRONMENT}"
    )
    
    # Add region-specific stacks
    if [ "$region" == "$PRIMARY_REGION" ]; then
        stacks+=(
            "${STACK_PREFIX}QuickSightStack-${ENVIRONMENT}"
            "${STACK_PREFIX}AthenaStack-${ENVIRONMENT}"
        )
    fi
    
    for stack in "${stacks[@]}"; do
        print_info "Deploying stack: $stack"
        
        if cdk deploy "$stack" \
            --profile "$AWS_PROFILE" \
            --region "$region" \
            --require-approval never \
            "${context_args[@]}"; then
            print_success "Successfully deployed: $stack"
        else
            print_error "Failed to deploy: $stack"
            return 1
        fi
    done
    
    return 0
}

# Function to configure cross-region replication
configure_replication() {
    print_info "Configuring cross-region replication..."
    
    # Configure S3 bucket replication
    if [ "$ENVIRONMENT" != "dev" ]; then
        print_info "Setting up S3 cross-region replication..."
        
        # This would be handled by the CDK stack with replication rules
        print_info "S3 replication configured via CDK"
    fi
    
    # Configure DynamoDB global tables
    if [ "$ENVIRONMENT" == "prod" ]; then
        print_info "Setting up DynamoDB global tables..."
        
        # Global tables are configured via CDK
        print_info "DynamoDB global tables configured via CDK"
    fi
    
    print_success "Cross-region replication configured"
}

# Function to validate deployment
validate_deployment() {
    local region=$1
    print_info "Validating deployment in region: $region"
    
    # Check if API Gateway is responding
    local api_url=$(aws cloudformation describe-stacks \
        --stack-name "${STACK_PREFIX}APIStack-${ENVIRONMENT}" \
        --region "$region" \
        --profile "$AWS_PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$api_url" ]; then
        if curl -s -o /dev/null -w "%{http_code}" "${api_url}/health" | grep -q "200"; then
            print_success "API is healthy in region: $region"
        else
            print_warning "API health check failed in region: $region"
        fi
    else
        print_warning "Could not find API URL in region: $region"
    fi
}

# Function to create deployment summary
create_deployment_summary() {
    local regions=$1
    local deployment_id=$(date +%Y%m%d-%H%M%S)
    local summary_file="deployment-summary-${deployment_id}.json"
    
    print_info "Creating deployment summary..."
    
    cat > "$summary_file" <<EOF
{
  "deployment_id": "${deployment_id}",
  "environment": "${ENVIRONMENT}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "regions": [
EOF
    
    local first=true
    for region in $regions; do
        if [ "$first" != true ]; then
            echo "," >> "$summary_file"
        fi
        first=false
        
        local api_url=$(aws cloudformation describe-stacks \
            --stack-name "${STACK_PREFIX}APIStack-${ENVIRONMENT}" \
            --region "$region" \
            --profile "$AWS_PROFILE" \
            --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" \
            --output text 2>/dev/null || echo "null")
        
        cat >> "$summary_file" <<EOF
    {
      "region": "${region}",
      "api_url": "${api_url}",
      "is_primary": $([ "$region" == "$PRIMARY_REGION" ] && echo "true" || echo "false")
    }
EOF
    done
    
    cat >> "$summary_file" <<EOF
  ]
}
EOF
    
    print_success "Deployment summary created: $summary_file"
}

# Main deployment flow
main() {
    print_info "Starting multi-region deployment"
    print_info "Environment: $ENVIRONMENT"
    print_info "AWS Profile: $AWS_PROFILE"
    
    # Check prerequisites
    check_prerequisites
    
    # Get AWS account ID
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text)
    print_info "AWS Account ID: $AWS_ACCOUNT_ID"
    
    # Get deployment regions
    REGIONS=$(get_deployment_regions)
    print_info "Deployment regions: $REGIONS"
    
    # Bootstrap all regions
    for region in $REGIONS; do
        bootstrap_region "$region"
    done
    
    # Deploy to each region
    local deployment_success=true
    for region in $REGIONS; do
        local is_primary="false"
        if [ "$region" == "$PRIMARY_REGION" ]; then
            is_primary="true"
        fi
        
        if ! deploy_region "$region" "$is_primary"; then
            deployment_success=false
            print_error "Deployment failed in region: $region"
            break
        fi
    done
    
    if [ "$deployment_success" == "true" ]; then
        # Configure cross-region features
        configure_replication
        
        # Validate deployments
        for region in $REGIONS; do
            validate_deployment "$region"
        done
        
        # Create deployment summary
        create_deployment_summary "$REGIONS"
        
        print_success "Multi-region deployment completed successfully!"
        
        # Print useful information
        print_info "Deployment Summary:"
        for region in $REGIONS; do
            local api_url=$(aws cloudformation describe-stacks \
                --stack-name "${STACK_PREFIX}APIStack-${ENVIRONMENT}" \
                --region "$region" \
                --profile "$AWS_PROFILE" \
                --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" \
                --output text 2>/dev/null || echo "N/A")
            
            echo -e "  ${GREEN}${region}${NC}: ${api_url}"
        done
    else
        print_error "Multi-region deployment failed!"
        exit 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -p|--profile)
            AWS_PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -e, --environment ENV    Deployment environment (dev|staging|prod)"
            echo "  -p, --profile PROFILE    AWS profile to use"
            echo "  -h, --help              Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main deployment
main