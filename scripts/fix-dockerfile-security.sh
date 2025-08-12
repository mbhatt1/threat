#!/bin/bash

# Script to update Dockerfiles to run as non-root user

echo "Updating Dockerfiles to use non-root users..."

# List of Dockerfiles to update (excluding Lambda runtime ones)
dockerfiles=(
    "src/agents/bedrock_sast/Dockerfile"
    "src/agents/sast/Dockerfile"
    "src/agents/autonomous_supply_chain/Dockerfile"
    "src/agents/autonomous/Dockerfile"
    "src/agents/iac/Dockerfile"
    "src/agents/autonomous_threat_intel/Dockerfile"
    "src/agents/autonomous_infra_security/Dockerfile"
    "src/agents/dependency/Dockerfile"
    "src/agents/autonomous_code_analyzer/Dockerfile"
    "src/agents/secrets/Dockerfile"
    "src/agents/red_team/Dockerfile"
)

# Security improvements to add after FROM statement
security_additions='
# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser
'

# Security improvements to add before CMD
user_switch='
# Change ownership of app directory
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser
'

for dockerfile in "${dockerfiles[@]}"; do
    if [ -f "$dockerfile" ]; then
        echo "Updating $dockerfile..."
        
        # Create a temporary file
        tmp_file="${dockerfile}.tmp"
        
        # Process the Dockerfile
        awk -v security="$security_additions" -v userswitch="$user_switch" '
        /^FROM/ && !done_from {
            print $0
            print security
            done_from=1
            next
        }
        /^CMD/ && !done_user {
            print userswitch
            done_user=1
        }
        {print}
        ' "$dockerfile" > "$tmp_file"
        
        # Replace the original file
        mv "$tmp_file" "$dockerfile"
        
        echo "✓ Updated $dockerfile"
    else
        echo "⚠ File not found: $dockerfile"
    fi
done

echo "
Security updates applied:
- Created non-root user 'appuser' with UID 1001
- Changed ownership of /app directory to appuser
- Switched to non-root user before running the application
"