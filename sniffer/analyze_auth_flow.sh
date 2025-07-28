#!/bin/bash

# Authentication Flow Analyzer
# Analyzes CSV exports from network captures to understand OIDC/OAuth2 flows

set -e

echo "🔍 Authentication Flow Analyzer"
echo "================================"

# Check if CSV files exist
CSV_DIR="/var/captures"
if [ -d "/opt/sniffer" ]; then
    CSV_DIR="/opt/sniffer"
fi

# Function to analyze HTTP requests
analyze_http_requests() {
    local file="$1"
    local description="$2"
    
    echo ""
    echo "📊 $description"
    echo "$(printf '=%.0s' {1..50})"
    
    if [ ! -f "$file" ]; then
        echo "❌ File not found: $file"
        return
    fi
    
    # Extract HTTP requests
    echo "🔗 HTTP Requests:"
    grep "HTTP" "$file" | grep -E "(GET|POST|PUT|DELETE)" | head -10 | while IFS=',' read -r no time src dst protocol length info; do
        # Clean the fields
        time=$(echo "$time" | tr -d '"')
        src=$(echo "$src" | tr -d '"')
        dst=$(echo "$dst" | tr -d '"')
        info=$(echo "$info" | tr -d '"')
        
        printf "  %8s | %-15s → %-15s | %s\n" "$time" "$src" "$dst" "$info"
    done
    
    # Count different types
    echo ""
    echo "📈 HTTP Response Codes:"
    grep "HTTP/1.1" "$file" | cut -d'"' -f8 | sort | uniq -c | sort -nr
}

# Function to extract authentication timeline
extract_auth_timeline() {
    echo ""
    echo "⏱️ Authentication Timeline"
    echo "$(printf '=%.0s' {1..50})"
    
    # Look for key authentication events across all files
    for file in backend.csv external.csv flask.csv; do
        if [ -f "$file" ]; then
            echo ""
            echo "📄 File: $file"
            
            # Extract OAuth2/OIDC specific requests
            grep -E "(oauth2callback|/token|/keys|/userinfo|302 Found)" "$file" | head -5 | while IFS=',' read -r no time src dst protocol length info; do
                time=$(echo "$time" | tr -d '"')
                info=$(echo "$info" | tr -d '"')
                printf "  %8s | %s\n" "$time" "$info"
            done
        fi
    done
}

# Function to identify network segments
identify_networks() {
    echo ""
    echo "🌐 Network Segment Analysis"
    echo "$(printf '=%.0s' {1..50})"
    
    for file in *.csv; do
        if [ -f "$file" ]; then
            echo ""
            echo "📄 $file:"
            
            # Extract unique IP addresses
            cut -d',' -f3,4 "$file" | tr -d '"' | grep -E "^172\." | sort | uniq | head -10 | while read line; do
                echo "  $line"
            done
        fi
    done
}

# Function to generate summary report
generate_summary() {
    echo ""
    echo "📋 Authentication Flow Summary"
    echo "$(printf '=%.0s' {1..50})"
    
    # Count total packets per file
    for file in *.csv; do
        if [ -f "$file" ]; then
            count=$(wc -l < "$file")
            echo "📦 $file: $((count-1)) packets captured"
        fi
    done
    
    echo ""
    echo "🔐 Key Security Events Detected:"
    
    # Look for specific security-relevant events
    if grep -q "POST /token" *.csv 2>/dev/null; then
        echo "  ✅ OAuth2 token exchange detected"
    fi
    
    if grep -q "GET /keys" *.csv 2>/dev/null; then
        echo "  ✅ JWT public key retrieval detected"
    fi
    
    if grep -q "GET /userinfo" *.csv 2>/dev/null; then
        echo "  ✅ User information request detected"
    fi
    
    if grep -q "oauth2callback" *.csv 2>/dev/null; then
        echo "  ✅ OAuth2 callback flow detected"
    fi
    
    if grep -q "302 Found" *.csv 2>/dev/null; then
        echo "  ✅ HTTP redirections detected (authentication flow)"
    fi
}

# Main analysis
cd "$CSV_DIR" 2>/dev/null || cd /var/captures 2>/dev/null || cd .

# Analyze each network segment
analyze_http_requests "backend.csv" "Backend Network Traffic (172.25.1.x)"
analyze_http_requests "external.csv" "Application Network Traffic (172.25.2.x)" 
analyze_http_requests "flask.csv" "Infrastructure Communications"

# Extract timeline and network info
extract_auth_timeline
identify_networks
generate_summary

echo ""
echo "✅ Analysis complete!"
echo ""
echo "📚 For detailed documentation, see: AUTHENTICATION_FLOW_ANALYSIS.md"
echo "🔧 To re-run analysis: ./analyze_auth_flow.sh" 