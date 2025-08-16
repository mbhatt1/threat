#!/bin/bash
# Bundle script for AI Security Analyzer Lambda
# This ensures all dependencies and source files are properly packaged

set -e

LAMBDA_DIR=$(dirname "$0")
BUILD_DIR="${LAMBDA_DIR}/build"

echo "Building AI Security Analyzer Lambda..."

# Clean build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Copy Lambda handler
cp "${LAMBDA_DIR}/handler.py" "${BUILD_DIR}/"
cp "${LAMBDA_DIR}/requirements.txt" "${BUILD_DIR}/"

# Copy ai_models directory (going up to src, then into ai_models)
echo "Copying ai_models directory..."
cp -r "${LAMBDA_DIR}/../../ai_models" "${BUILD_DIR}/"

# Install dependencies
echo "Installing dependencies..."
cd "${BUILD_DIR}"
pip install -r requirements.txt -t . --upgrade

# Create deployment package
echo "Creating deployment package..."
zip -r ../lambda-deployment.zip . -x "*.pyc" -x "*__pycache__*"

echo "Bundle created successfully!"