#!/bin/bash

# Dependency Security Scanning Script
# This script scans Python dependencies and Docker images for security vulnerabilities

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Security Dependency Scanning ==="
echo "Starting at: $(date)"
echo ""

# Create results directory
RESULTS_DIR="security-scan-results"
mkdir -p "$RESULTS_DIR"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install required tools if not present
echo "Checking required tools..."

if ! command_exists pip-audit; then
    echo "Installing pip-audit..."
    pip install pip-audit
fi

if ! command_exists safety; then
    echo "Installing safety..."
    pip install safety
fi

if ! command_exists bandit; then
    echo "Installing bandit..."
    pip install bandit
fi

if ! command_exists trivy && [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Installing Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
fi

echo ""

# Scan Python dependencies
echo "=== Scanning Python Dependencies ==="

# Function to scan a requirements file
scan_requirements() {
    local req_file=$1
    local base_name=$(basename "$req_file" .txt)
    local dir_name=$(dirname "$req_file")
    local safe_name=$(echo "$dir_name" | sed 's/\//_/g')
    
    echo -e "\n${YELLOW}Scanning: $req_file${NC}"
    
    # pip-audit scan
    echo "Running pip-audit..."
    if pip-audit -r "$req_file" --format json > "$RESULTS_DIR/${safe_name}_${base_name}_pip-audit.json" 2>/dev/null; then
        vuln_count=$(jq '.vulnerabilities | length' "$RESULTS_DIR/${safe_name}_${base_name}_pip-audit.json")
        if [ "$vuln_count" -gt 0 ]; then
            echo -e "${RED}Found $vuln_count vulnerabilities with pip-audit${NC}"
            jq -r '.vulnerabilities[] | "  - \(.name) \(.version): \(.description)"' "$RESULTS_DIR/${safe_name}_${base_name}_pip-audit.json"
        else
            echo -e "${GREEN}No vulnerabilities found with pip-audit${NC}"
        fi
    else
        echo -e "${RED}pip-audit scan failed${NC}"
    fi
    
    # Safety scan
    echo "Running safety check..."
    if safety check -r "$req_file" --json > "$RESULTS_DIR/${safe_name}_${base_name}_safety.json" 2>/dev/null; then
        echo -e "${GREEN}Safety check completed${NC}"
    else
        echo -e "${YELLOW}Safety found issues (see report for details)${NC}"
    fi
}

# Find and scan all requirements files
for req_file in $(find . -name requirements.txt -not -path "./venv/*" -not -path "./.venv/*" -not -path "./env/*"); do
    scan_requirements "$req_file"
done

echo ""

# Scan Python code for security issues
echo "=== Scanning Python Code with Bandit ==="
bandit_output="$RESULTS_DIR/bandit-report.json"
if bandit -r src/ -f json -o "$bandit_output" 2>/dev/null; then
    echo -e "${GREEN}Bandit scan completed${NC}"
    
    # Show high severity issues
    high_issues=$(jq '.results | map(select(.issue_severity == "HIGH")) | length' "$bandit_output")
    if [ "$high_issues" -gt 0 ]; then
        echo -e "${RED}Found $high_issues high severity issues:${NC}"
        jq -r '.results[] | select(.issue_severity == "HIGH") | "  - \(.filename):\(.line_number) - \(.issue_text)"' "$bandit_output"
    fi
else
    echo -e "${YELLOW}Bandit found potential security issues${NC}"
fi

echo ""

# Scan Docker images
echo "=== Scanning Docker Images ==="

# Scan Dockerfiles
for dockerfile in $(find . -name Dockerfile -not -path "./venv/*"); do
    echo -e "\n${YELLOW}Scanning: $dockerfile${NC}"
    
    if command_exists trivy; then
        safe_name=$(echo "$dockerfile" | sed 's/\//_/g')
        trivy config "$dockerfile" --format json --output "$RESULTS_DIR/${safe_name}_trivy.json" 2>/dev/null || true
        
        # Check for high/critical issues
        if [ -f "$RESULTS_DIR/${safe_name}_trivy.json" ]; then
            high_count=$(jq '[.Results[].Misconfigurations[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "$RESULTS_DIR/${safe_name}_trivy.json" 2>/dev/null || echo "0")
            if [ "$high_count" -gt 0 ]; then
                echo -e "${RED}Found $high_count HIGH/CRITICAL issues in $dockerfile${NC}"
            else
                echo -e "${GREEN}No HIGH/CRITICAL issues found in $dockerfile${NC}"
            fi
        fi
    else
        echo "Trivy not available - skipping Dockerfile scan"
    fi
done

# Build and scan container images if Docker is available
if command_exists docker && command_exists trivy; then
    echo -e "\n${YELLOW}Building and scanning container images...${NC}"
    
    # Autonomous agent image
    if [ -f "src/agents/autonomous/Dockerfile" ]; then
        echo "Building autonomous agent image..."
        if docker build -t security-audit-autonomous:scan src/agents/autonomous/ >/dev/null 2>&1; then
            echo "Scanning autonomous agent image..."
            trivy image security-audit-autonomous:scan --format json --output "$RESULTS_DIR/autonomous-image-scan.json" 2>/dev/null || true
            
            # Clean up
            docker rmi security-audit-autonomous:scan >/dev/null 2>&1 || true
        fi
    fi
fi

echo ""

# Generate summary report
echo "=== Generating Summary Report ==="
report_file="$RESULTS_DIR/security-summary.txt"

{
    echo "Security Scan Summary Report"
    echo "Generated: $(date)"
    echo "================================"
    echo ""
    
    echo "Python Dependency Vulnerabilities:"
    total_vulns=0
    for audit_file in "$RESULTS_DIR"/*pip-audit.json; do
        if [ -f "$audit_file" ]; then
            count=$(jq '.vulnerabilities | length' "$audit_file" 2>/dev/null || echo "0")
            total_vulns=$((total_vulns + count))
            if [ "$count" -gt 0 ]; then
                echo "  - $(basename "$audit_file"): $count vulnerabilities"
            fi
        fi
    done
    echo "  Total: $total_vulns vulnerabilities found"
    echo ""
    
    echo "Code Security Issues (Bandit):"
    if [ -f "$RESULTS_DIR/bandit-report.json" ]; then
        high=$(jq '.results | map(select(.issue_severity == "HIGH")) | length' "$RESULTS_DIR/bandit-report.json" 2>/dev/null || echo "0")
        medium=$(jq '.results | map(select(.issue_severity == "MEDIUM")) | length' "$RESULTS_DIR/bandit-report.json" 2>/dev/null || echo "0")
        low=$(jq '.results | map(select(.issue_severity == "LOW")) | length' "$RESULTS_DIR/bandit-report.json" 2>/dev/null || echo "0")
        echo "  - High: $high"
        echo "  - Medium: $medium"
        echo "  - Low: $low"
    else
        echo "  - No Bandit results available"
    fi
    echo ""
    
    echo "Container Security Issues:"
    for trivy_file in "$RESULTS_DIR"/*trivy.json; do
        if [ -f "$trivy_file" ]; then
            echo "  - $(basename "$trivy_file"):"
            jq -r '.Results[].Misconfigurations[]? | "    \(.Severity): \(.Title)"' "$trivy_file" 2>/dev/null || echo "    No issues found"
        fi
    done
    
} > "$report_file"

echo -e "${GREEN}Summary report generated: $report_file${NC}"
echo ""
cat "$report_file"

echo ""
echo "=== Scan Complete ==="
echo "Detailed results are available in: $RESULTS_DIR/"

# Exit with error if vulnerabilities found
if [ "$total_vulns" -gt 0 ] || [ "${high:-0}" -gt 0 ]; then
    echo -e "\n${RED}Security issues detected! Please review and remediate.${NC}"
    exit 1
else
    echo -e "\n${GREEN}No critical security issues found.${NC}"
    exit 0
fi