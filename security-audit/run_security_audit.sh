#!/bin/bash

# OAuth2/OIDC Zero Trust Security Audit Runner
# Quick and easy script to run comprehensive security audits

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="$SCRIPT_DIR/security_audit.py"
CONFIG_FILE="$SCRIPT_DIR/security_audit_config.yaml"
PYTHON_CMD="python3"

# Function to print colored output
print_status() {
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
    print_status "Checking prerequisites..."
    
    # Check if Python 3 is available
    if ! command -v $PYTHON_CMD &> /dev/null; then
        print_error "Python 3 is not installed or not in PATH"
        exit 1
    fi
    
    # Check if audit script exists
    if [ ! -f "$AUDIT_SCRIPT" ]; then
        print_error "Security audit script not found: $AUDIT_SCRIPT"
        exit 1
    fi
    
    # Make script executable
    chmod +x "$AUDIT_SCRIPT"
    
    print_success "Prerequisites check passed"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Try to install with pip
    if command -v pip3 &> /dev/null; then
        pip3 install requests pyyaml --user --quiet 2>/dev/null || {
            print_warning "Could not install dependencies via pip3"
            print_warning "The script will use built-in modules only"
        }
    else
        print_warning "pip3 not available, using built-in modules only"
    fi
}

# Function to check if services are running
check_services() {
    print_status "Checking if target services are running..."
    
    # Check PEP endpoint
    if curl -s --connect-timeout 3 http://localhost:5000 > /dev/null 2>&1; then
        print_success "PEP endpoint is accessible"
    else
        print_warning "PEP endpoint (port 5000) is not accessible"
        print_warning "Make sure docker compose services are running"
    fi
    
    # Check OIDC provider
    if curl -s --connect-timeout 3 http://localhost:5556 > /dev/null 2>&1; then
        print_success "OIDC provider is accessible"
    else
        print_warning "OIDC provider (port 5556) is not accessible"
    fi
    
    # Check backend application
    if curl -s --connect-timeout 3 http://localhost:8080 > /dev/null 2>&1; then
        print_success "Backend application is accessible"
    else
        print_warning "Backend application (port 8080) is not accessible"
    fi
}

# Function to create configuration if needed
setup_configuration() {
    if [ ! -f "$CONFIG_FILE" ]; then
        print_status "Creating default configuration..."
        cd "$SCRIPT_DIR" && $PYTHON_CMD "$AUDIT_SCRIPT" --create-config
        print_success "Configuration created: $CONFIG_FILE"
    else
        print_status "Using existing configuration: $CONFIG_FILE"
    fi
}

# Function to run the security audit
run_audit() {
    local verbose=""
    local custom_config=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose="--verbose"
                shift
                ;;
            -c|--config)
                custom_config="--config $2"
                shift 2
                ;;
            *)
                # Unknown option
                shift
                ;;
        esac
    done
    
    print_status "Starting OAuth2/OIDC Zero Trust Security Audit..."
    echo ""
    
    # Run the audit (change to script directory)
    cd "$SCRIPT_DIR"
    if $PYTHON_CMD "$AUDIT_SCRIPT" $verbose $custom_config; then
        echo ""
        print_success "Security audit completed successfully!"
        
        # List generated reports
        if ls "$SCRIPT_DIR"/security_audit_report_*.json "$SCRIPT_DIR"/security_audit_report_*.html > /dev/null 2>&1; then
            print_status "Generated reports:"
            ls -la "$SCRIPT_DIR"/security_audit_report_*.json "$SCRIPT_DIR"/security_audit_report_*.html | while read line; do
                echo "  $line"
            done
        fi
        
        return 0
    else
        echo ""
        print_error "Security audit failed or found critical issues!"
        print_status "Check the generated reports for detailed findings"
        return 1
    fi
}

# Function to open HTML report
open_report() {
    local html_report=$(ls -t "$SCRIPT_DIR"/security_audit_report_*.html 2>/dev/null | head -1)
    
    if [ -f "$html_report" ]; then
        print_status "Opening HTML report: $html_report"
        
        # Try different browsers/viewers
        if command -v xdg-open &> /dev/null; then
            xdg-open "$html_report" &
        elif command -v firefox &> /dev/null; then
            firefox "$html_report" &
        elif command -v chromium &> /dev/null; then
            chromium "$html_report" &
        elif command -v google-chrome &> /dev/null; then
            google-chrome "$html_report" &
        else
            print_warning "No browser found. Please open $html_report manually"
        fi
    else
        print_error "No HTML report found"
    fi
}

# Function to show help
show_help() {
    echo "OAuth2/OIDC Zero Trust Security Audit Runner"
    echo ""
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  audit     Run security audit (default)"
    echo "  check     Check prerequisites and services"
    echo "  setup     Setup configuration"
    echo "  report    Open latest HTML report"
    echo "  clean     Clean old reports"
    echo "  help      Show this help message"
    echo ""
    echo "Options:"
    echo "  -v, --verbose    Enable verbose logging"
    echo "  -c, --config     Use custom configuration file"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run basic audit"
    echo "  $0 audit --verbose    # Run with verbose output"
    echo "  $0 check             # Check system status"
    echo "  $0 report            # Open latest report"
}

# Function to clean old reports
clean_reports() {
    print_status "Cleaning old security audit reports..."
    
    # Keep only the 5 most recent reports
    cd "$SCRIPT_DIR"
    if ls security_audit_report_*.json > /dev/null 2>&1; then
        ls -t security_audit_report_*.json | tail -n +6 | xargs rm -f
    fi
    
    if ls security_audit_report_*.html > /dev/null 2>&1; then
        ls -t security_audit_report_*.html | tail -n +6 | xargs rm -f
    fi
    
    # Clean log file if it's too large (>10MB)
    if [ -f "$SCRIPT_DIR/security_audit.log" ]; then
        if [ $(stat -c%s "$SCRIPT_DIR/security_audit.log") -gt 10485760 ]; then
            tail -n 1000 "$SCRIPT_DIR/security_audit.log" > "$SCRIPT_DIR/security_audit.log.tmp"
            mv "$SCRIPT_DIR/security_audit.log.tmp" "$SCRIPT_DIR/security_audit.log"
            print_status "Truncated large log file"
        fi
    fi
    
    print_success "Cleanup completed"
}

# Main execution
main() {
    echo "🔒 OAuth2/OIDC Zero Trust Security Audit Tool"
    echo "============================================="
    echo ""
    
    # Parse command
    local command="${1:-audit}"
    shift 2>/dev/null || true
    
    case "$command" in
        audit)
            check_prerequisites
            install_dependencies
            setup_configuration
            check_services
            echo ""
            run_audit "$@"
            ;;
        check)
            check_prerequisites
            check_services
            ;;
        setup)
            check_prerequisites
            setup_configuration
            ;;
        report)
            open_report
            ;;
        clean)
            clean_reports
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 