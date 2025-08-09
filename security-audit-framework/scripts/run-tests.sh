#!/bin/bash

# Run tests for Security Audit Framework

set -e

echo "=============================="
echo "Security Audit Framework Tests"
echo "=============================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to project root
cd "$(dirname "$0")/.."

# Install test dependencies
echo -e "\n${YELLOW}Installing test dependencies...${NC}"
pip install -r tests/requirements.txt

# Run unit tests
echo -e "\n${YELLOW}Running unit tests...${NC}"
pytest tests/unit -v -m "not integration" || {
    echo -e "${RED}Unit tests failed${NC}"
    exit 1
}

# Run integration tests (optional, requires AWS setup)
if [ "$1" == "--integration" ]; then
    echo -e "\n${YELLOW}Running integration tests...${NC}"
    pytest tests/integration -v -m "not requires_aws" || {
        echo -e "${RED}Integration tests failed${NC}"
        exit 1
    }
fi

# Run all tests with coverage
if [ "$1" == "--all" ]; then
    echo -e "\n${YELLOW}Running all tests with coverage...${NC}"
    pytest tests/ -v --cov=src --cov-report=html --cov-report=term || {
        echo -e "${RED}Tests failed${NC}"
        exit 1
    }
    echo -e "\n${GREEN}Coverage report generated in htmlcov/index.html${NC}"
fi

# Run specific test file
if [ "$1" == "--file" ] && [ -n "$2" ]; then
    echo -e "\n${YELLOW}Running tests in $2...${NC}"
    pytest "$2" -v || {
        echo -e "${RED}Tests failed${NC}"
        exit 1
    }
fi

# Show help
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: ./scripts/run-tests.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (no args)       Run unit tests only"
    echo "  --integration   Run unit and integration tests"
    echo "  --all          Run all tests with coverage report"
    echo "  --file <path>  Run specific test file"
    echo "  --help, -h     Show this help message"
    exit 0
fi

echo -e "\n${GREEN}Tests completed successfully!${NC}"