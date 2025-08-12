#!/bin/bash
# Secure Archive Demo Script
# Demonstrates the secure archive functionality

set -e

echo "=== Security Audit Framework - Secure Archive Demo ==="
echo

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running from project root
if [ ! -f "setup.py" ]; then
    echo -e "${RED}Error: Please run this script from the project root directory${NC}"
    exit 1
fi

# Demo directory
DEMO_DIR="demo_archive_test"
ARCHIVE_NAME="demo_archive.tar.gz"
ENCRYPTED_NAME="demo_archive.tar.gz.enc"

echo -e "${BLUE}1. Creating demo directory with sample files...${NC}"
mkdir -p $DEMO_DIR/{src,config,docs}

# Create sample files
cat > $DEMO_DIR/src/app.py << 'EOF'
#!/usr/bin/env python3
"""Sample application file"""

def main():
    print("Hello from secure archive demo!")

if __name__ == "__main__":
    main()
EOF

cat > $DEMO_DIR/config/settings.json << 'EOF'
{
    "app_name": "SecureArchiveDemo",
    "version": "1.0.0",
    "features": {
        "encryption": true,
        "compression": true
    }
}
EOF

cat > $DEMO_DIR/docs/README.md << 'EOF'
# Secure Archive Demo

This is a demonstration of the secure archive functionality.

## Features
- Compression with tar.gz
- AES-256-GCM encryption
- S3 upload/download support
- On-the-fly analysis
EOF

# Create a sensitive file for security detection
cat > $DEMO_DIR/config/.env << 'EOF'
API_KEY=demo-secret-key-12345
DATABASE_PASSWORD=demo-password
EOF

echo -e "${GREEN}✓ Demo directory created${NC}"
echo

# Archive the directory
echo -e "${BLUE}2. Creating tar.gz archive...${NC}"
python3 -m src.shared.secure_archive archive $DEMO_DIR

if [ -f "$ARCHIVE_NAME" ]; then
    echo -e "${GREEN}✓ Archive created: $ARCHIVE_NAME${NC}"
    ls -lh *.tar.gz | grep -E "demo_archive.*tar.gz"
else
    # Try with different naming pattern
    ARCHIVE_NAME=$(ls -1 ${DEMO_DIR}_*.tar.gz 2>/dev/null | head -n 1)
    if [ -n "$ARCHIVE_NAME" ]; then
        echo -e "${GREEN}✓ Archive created: $ARCHIVE_NAME${NC}"
        ls -lh "$ARCHIVE_NAME"
    else
        echo -e "${RED}✗ Archive creation failed${NC}"
        exit 1
    fi
fi
echo

# Analyze the archive
echo -e "${BLUE}3. Analyzing archive contents...${NC}"
python3 -m src.shared.secure_archive analyze "$ARCHIVE_NAME"
echo

# Encrypt the archive
echo -e "${BLUE}4. Encrypting archive...${NC}"
echo -e "${YELLOW}Using password: 'demo-password' (for demonstration only)${NC}"
echo "demo-password" | python3 -m src.shared.secure_archive archive $DEMO_DIR --password demo-password

# Find the encrypted file
ENCRYPTED_NAME=$(ls -1 *.enc 2>/dev/null | head -n 1)
if [ -n "$ENCRYPTED_NAME" ]; then
    echo -e "${GREEN}✓ Archive encrypted: $ENCRYPTED_NAME${NC}"
    ls -lh "$ENCRYPTED_NAME"
    
    # Show size comparison
    ORIG_SIZE=$(stat -f%z "$ARCHIVE_NAME" 2>/dev/null || stat -c%s "$ARCHIVE_NAME")
    ENC_SIZE=$(stat -f%z "$ENCRYPTED_NAME" 2>/dev/null || stat -c%s "$ENCRYPTED_NAME")
    echo -e "  Original size: ${YELLOW}$ORIG_SIZE bytes${NC}"
    echo -e "  Encrypted size: ${YELLOW}$ENC_SIZE bytes${NC}"
else
    echo -e "${RED}✗ Encryption failed${NC}"
fi
echo

# Test decryption
echo -e "${BLUE}5. Testing decryption...${NC}"
if [ -n "$ENCRYPTED_NAME" ]; then
    # Remove original to test decryption
    rm -f "$ARCHIVE_NAME"
    
    echo "demo-password" | python3 -m src.shared.secure_archive decrypt "$ENCRYPTED_NAME" --password demo-password
    
    if [ -f "$ARCHIVE_NAME" ]; then
        echo -e "${GREEN}✓ Archive decrypted successfully${NC}"
    else
        # Check for other output names
        DECRYPTED=$(ls -1 *.tar.gz 2>/dev/null | grep -v ".enc" | head -n 1)
        if [ -n "$DECRYPTED" ]; then
            echo -e "${GREEN}✓ Archive decrypted: $DECRYPTED${NC}"
        else
            echo -e "${RED}✗ Decryption failed${NC}"
        fi
    fi
fi
echo

# Using the CLI tool
echo -e "${BLUE}6. Using the CLI tool...${NC}"
echo -e "${YELLOW}Note: Make sure to run 'pip install -e .' first${NC}"

# Check if CLI is installed
if command -v saf-cli &> /dev/null; then
    echo -e "${GREEN}✓ CLI tool is installed${NC}"
    echo
    
    # Show help
    echo -e "${BLUE}Available archive commands:${NC}"
    saf-cli archive --help | head -20
    echo
    
    # Quick backup demo
    echo -e "${BLUE}7. Quick backup demo...${NC}"
    echo -e "${YELLOW}This would normally upload to S3 if configured${NC}"
    echo "demo-password" | saf-cli quick-backup $DEMO_DIR -p
else
    echo -e "${YELLOW}CLI tool not installed. Run 'pip install -e .' to install${NC}"
fi

# Cleanup
echo
echo -e "${BLUE}8. Cleaning up...${NC}"
read -p "Remove demo files? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf $DEMO_DIR
    rm -f demo_archive*.tar.gz*
    rm -f ${DEMO_DIR}_*.tar.gz*
    rm -f *.enc
    echo -e "${GREEN}✓ Demo files cleaned up${NC}"
else
    echo -e "${YELLOW}Demo files kept for inspection${NC}"
fi

echo
echo -e "${GREEN}=== Demo completed ===${NC}"
echo
echo "Key features demonstrated:"
echo "  • Directory archiving with tar.gz compression"
echo "  • AES-256-GCM encryption with password"
echo "  • Archive content analysis"
echo "  • Security concern detection (.env files)"
echo "  • Encryption/decryption workflow"
echo
echo "For S3 integration, set ARCHIVE_S3_BUCKET environment variable"