#!/bin/bash

# OAuth2/OIDC Zero Trust Security Audit - Entry Point
# This script calls the main audit tool in the security-audit directory

set -e

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_AUDIT_DIR="$SCRIPT_DIR/security-audit"

# Colors for output
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if security-audit directory exists
if [ ! -d "$SECURITY_AUDIT_DIR" ]; then
    echo -e "${RED}[ERROR]${NC} Security audit directory not found: $SECURITY_AUDIT_DIR"
    exit 1
fi

# Check if the main script exists
if [ ! -f "$SECURITY_AUDIT_DIR/run_security_audit.sh" ]; then
    echo -e "${RED}[ERROR]${NC} Security audit script not found: $SECURITY_AUDIT_DIR/run_security_audit.sh"
    exit 1
fi

# Print info and delegate to the main script
echo -e "${BLUE}[INFO]${NC} Delegating to security audit tool..."
exec "$SECURITY_AUDIT_DIR/run_security_audit.sh" "$@" 