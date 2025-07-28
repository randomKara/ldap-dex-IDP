#!/bin/bash

# Log Analysis Helper Script
# Provides various filtering and analysis options for captured traffic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PCAP_DIR="$SCRIPT_DIR/pcap"

show_help() {
    echo "PEP Advanced Traffic Sniffer - Log Analysis Tool"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Basic Options:"
    echo "  -h, --help              Show this help message"
    echo "  -l, --list              List all available log files"
    echo "  -s, --summary           Show traffic summary"
    echo "  -r, --requests          Show HTTP requests only"
    echo "  -R, --responses         Show HTTP responses only"
    echo "  -a, --auth              Show authentication flows"
    echo "  -o, --oidc              Show OIDC/OAuth2 flows"
    echo "  -c, --cookies           Show cookie operations"
    echo "  -e, --errors            Show HTTP errors (4xx, 5xx)"
    echo "  -t, --timeline          Show chronological timeline"
    echo "  -f FILE, --file FILE    Analyze specific log file"
    echo "  -p, --pcap              List packet capture files"
    echo "  --live                  Monitor live logs (tail -f)"
    echo ""
    echo "Advanced Analysis:"
    echo "  --dashboard             Show real-time analysis dashboard"
    echo "  --flows                 Show flow correlation analysis"
    echo "  --sessions              Show session tracking data"
    echo "  --security              Show security events and anomalies"
    echo "  --performance           Show performance analysis"
    echo "  --interfaces            Show per-interface traffic breakdown"
    echo "  --patterns              Show traffic pattern analysis"
    echo ""
    echo "Network Analysis:"
    echo "  --user-traffic          Show User→PEP traffic (eth2)"
    echo "  --dex-traffic           Show PEP→Dex traffic (eth1)"
    echo "  --flask-traffic         Show PEP→Flask traffic (eth0)"
    echo "  --correlations          Show cross-interface correlations"
    echo ""
    echo "Examples:"
    echo "  $0 --summary            # Show overall traffic summary"
    echo "  $0 --dashboard          # Show real-time analysis dashboard"
    echo "  $0 --user-traffic       # Show all user→PEP interactions"
    echo "  $0 --flows --live       # Monitor flow correlations in real-time"
    echo "  $0 --security           # Show security events and anomalies"
}

list_files() {
    echo "=== Available Log Files ==="
    if [ -d "$LOG_DIR" ]; then
        ls -la "$LOG_DIR"/*.log 2>/dev/null || echo "No log files found"
    else
        echo "Log directory not found: $LOG_DIR"
    fi
    
    echo ""
    echo "=== Available PCAP Files ==="
    if [ -d "$PCAP_DIR" ]; then
        ls -la "$PCAP_DIR"/*.pcap 2>/dev/null || echo "No PCAP files found"
    else
        echo "PCAP directory not found: $PCAP_DIR"
    fi
}

get_latest_log() {
    find "$LOG_DIR" -name "*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-
}

show_summary() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    if [ ! -f "$file" ]; then
        echo "Log file not found: $file"
        return 1
    fi
    
    echo "=== TRAFFIC SUMMARY for $file ==="
    echo ""
    echo "HTTP Requests:"
    grep -c "HTTP_REQUEST:" "$file" 2>/dev/null || echo "0"
    echo ""
    echo "HTTP Responses:"
    grep -c "HTTP_RESPONSE:" "$file" 2>/dev/null || echo "0"
    echo ""
    echo "Top Request Methods:"
    grep "HTTP_REQUEST:" "$file" 2>/dev/null | grep -oE "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)" | sort | uniq -c | sort -nr
    echo ""
    echo "Response Status Codes:"
    grep "Status Code:" "$file" 2>/dev/null | cut -d: -f2 | sort | uniq -c | sort -nr
    echo ""
    echo "Unique Hosts:"
    grep "Host:" "$file" 2>/dev/null | cut -d: -f2- | sort | uniq
    echo ""
    echo "Authentication Headers:"
    grep -c "Authorization:" "$file" 2>/dev/null || echo "0"
    echo ""
    echo "Cookie Operations:"
    echo "  Set-Cookie: $(grep -c "Set-Cookie:" "$file" 2>/dev/null || echo "0")"
    echo "  Cookie: $(grep -c "Cookie:" "$file" 2>/dev/null || echo "0")"
}

show_requests() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== HTTP REQUESTS ==="
    grep "HTTP_REQUEST:" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_responses() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== HTTP RESPONSES ==="
    grep "HTTP_RESPONSE:" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_auth() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== AUTHENTICATION FLOWS ==="
    grep -E "(Authorization:|WWW-Authenticate:|oauth|oidc|token)" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_oidc() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== OIDC/OAUTH2 FLOWS ==="
    grep -E "(oauth2callback|/auth|/token|/userinfo|/keys|code=|state=)" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_cookies() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== COOKIE OPERATIONS ==="
    grep -E "(Cookie:|Set-Cookie:)" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_errors() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== HTTP ERRORS ==="
    grep -E "Status Code: [45][0-9][0-9]" "$file" 2>/dev/null | while read -r line; do
        echo "$line"
    done
}

show_timeline() {
    local file="$1"
    if [ -z "$file" ]; then
        file=$(get_latest_log)
    fi
    
    echo "=== CHRONOLOGICAL TIMELINE ==="
    grep -E "\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]" "$file" 2>/dev/null | sort
}

monitor_live() {
    local latest_log=$(get_latest_log)
    if [ -z "$latest_log" ]; then
        echo "No log files found for live monitoring"
        return 1
    fi
    
    echo "=== LIVE MONITORING: $latest_log ==="
    echo "Press Ctrl+C to stop..."
    tail -f "$latest_log"
}

# Advanced analysis functions
show_dashboard() {
    echo "=== REAL-TIME DASHBOARD ==="
    local latest_rt_log=$(find "$LOG_DIR" -name "realtime_analysis_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_rt_log" ]; then
        tail -50 "$latest_rt_log" | grep -E "(DASHBOARD|TRAFFIC_OVERVIEW|AUTHENTICATION_EVENTS|ERROR_SUMMARY)"
    else
        echo "No real-time analysis data available"
    fi
}

show_flows() {
    echo "=== FLOW CORRELATION ANALYSIS ==="
    local latest_flow_log=$(find "$LOG_DIR" -name "flow_correlation_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_flow_log" ]; then
        tail -100 "$latest_flow_log" | grep -E "(FLOW_CORRELATION|SESSION_FLOW|CORRELATION_REPORT)"
    else
        echo "No flow correlation data available"
    fi
}

show_sessions() {
    echo "=== SESSION TRACKING ==="
    local latest_session_log=$(find "$LOG_DIR" -name "session_tracking_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_session_log" ]; then
        tail -100 "$latest_session_log" | grep -E "(SESSION_CREATED|SESSION_UPDATED|USER_REQUEST|PATTERN)"
    else
        echo "No session tracking data available"
    fi
}

show_security() {
    echo "=== SECURITY EVENTS & ANOMALIES ==="
    local latest_rt_log=$(find "$LOG_DIR" -name "realtime_analysis_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_rt_log" ]; then
        grep -E "(ANOMALY_DETECTED|SECURITY_ANOMALIES|AUTH_ANALYSIS)" "$latest_rt_log" | tail -50
    else
        echo "No security analysis data available"
    fi
}

show_performance() {
    echo "=== PERFORMANCE ANALYSIS ==="
    local latest_rt_log=$(find "$LOG_DIR" -name "realtime_analysis_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_rt_log" ]; then
        grep -E "(SLOW_RESPONSE|SERVER_ERROR|PERFORMANCE)" "$latest_rt_log" | tail -30
    else
        echo "No performance analysis data available"
    fi
}

show_interfaces() {
    echo "=== PER-INTERFACE TRAFFIC BREAKDOWN ==="
    echo ""
    echo "🌐 User Requests (eth2 - External Network):"
    show_interface_traffic "user_requests"
    echo ""
    echo "🔐 Dex Authentication (eth1 - Backend Network):"
    show_interface_traffic "dex_authentication" 
    echo ""
    echo "📱 Flask Communication (eth0 - App Network):"
    show_interface_traffic "flask_communication"
}

show_interface_traffic() {
    local interface_type="$1"
    local latest_log=$(find "$LOG_DIR" -name "${interface_type}_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_log" ]; then
        echo "  📊 Traffic Summary:"
        grep -c "HTTP_REQUEST" "$latest_log" 2>/dev/null && echo "    HTTP Requests" || echo "    HTTP Requests: 0"
        grep -c "HTTP_RESPONSE" "$latest_log" 2>/dev/null && echo "    HTTP Responses" || echo "    HTTP Responses: 0"
        grep -c "OIDC_FLOW" "$latest_log" 2>/dev/null && echo "    OIDC Flows" || echo "    OIDC Flows: 0"
        echo "  📈 Recent Activity:"
        tail -10 "$latest_log" | grep -E "(HTTP_REQUEST|HTTP_RESPONSE|OIDC_FLOW)" | sed 's/^/    /'
    else
        echo "  No data available for $interface_type"
    fi
}

show_patterns() {
    echo "=== TRAFFIC PATTERN ANALYSIS ==="
    local latest_rt_log=$(find "$LOG_DIR" -name "realtime_analysis_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_rt_log" ]; then
        echo "🔍 Detected Patterns:"
        grep -E "(RAPID_REQUESTS|SUSPICIOUS_PATH|PATTERN)" "$latest_rt_log" | tail -20
    else
        echo "No pattern analysis data available"
    fi
}

show_correlations() {
    echo "=== CROSS-INTERFACE CORRELATIONS ==="
    local latest_flow_log=$(find "$LOG_DIR" -name "flow_correlation_*.log" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    if [ -n "$latest_flow_log" ]; then
        grep "FLOW_CORRELATION" "$latest_flow_log" | tail -20
    else
        echo "No correlation data available"
    fi
}

# Parse command line arguments
LIVE_MODE=false
TARGET_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            list_files
            exit 0
            ;;
        -s|--summary)
            show_summary "$TARGET_FILE"
            exit 0
            ;;
        -r|--requests)
            show_requests "$TARGET_FILE"
            exit 0
            ;;
        -R|--responses)
            show_responses "$TARGET_FILE"
            exit 0
            ;;
        -a|--auth)
            show_auth "$TARGET_FILE"
            if [ "$LIVE_MODE" = true ]; then
                echo ""
                echo "=== LIVE AUTH MONITORING ==="
                monitor_live | grep -E "(Authorization:|WWW-Authenticate:|oauth|oidc|token)"
            fi
            exit 0
            ;;
        -o|--oidc)
            show_oidc "$TARGET_FILE"
            exit 0
            ;;
        -c|--cookies)
            show_cookies "$TARGET_FILE"
            exit 0
            ;;
        -e|--errors)
            show_errors "$TARGET_FILE"
            exit 0
            ;;
        -t|--timeline)
            show_timeline "$TARGET_FILE"
            exit 0
            ;;
        -f|--file)
            TARGET_FILE="$2"
            shift
            ;;
        -p|--pcap)
            echo "=== PCAP Files ==="
            ls -la "$PCAP_DIR"/*.pcap 2>/dev/null || echo "No PCAP files found"
            exit 0
            ;;
        --live)
            LIVE_MODE=true
            ;;
        --dashboard)
            show_dashboard
            exit 0
            ;;
        --flows)
            show_flows
            if [ "$LIVE_MODE" = true ]; then
                echo ""
                echo "=== LIVE FLOW MONITORING ==="
                monitor_live | grep -E "(FLOW_CORRELATION|SESSION_FLOW)"
            fi
            exit 0
            ;;
        --sessions)
            show_sessions
            exit 0
            ;;
        --security)
            show_security
            exit 0
            ;;
        --performance)
            show_performance
            exit 0
            ;;
        --interfaces)
            show_interfaces
            exit 0
            ;;
        --patterns)
            show_patterns
            exit 0
            ;;
        --user-traffic)
            echo "=== USER → PEP TRAFFIC (eth2) ==="
            show_interface_traffic "user_requests"
            exit 0
            ;;
        --dex-traffic)
            echo "=== PEP → DEX TRAFFIC (eth1) ==="
            show_interface_traffic "dex_authentication"
            exit 0
            ;;
        --flask-traffic)
            echo "=== PEP → FLASK TRAFFIC (eth0) ==="
            show_interface_traffic "flask_communication"
            exit 0
            ;;
        --correlations)
            show_correlations
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# If no specific action was requested, show help
if [ "$LIVE_MODE" = true ]; then
    monitor_live
else
    show_help
fi 