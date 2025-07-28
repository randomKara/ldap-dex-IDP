#!/bin/bash

# Simple Traffic Analyzer - Actually Works!

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"

show_help() {
    echo "Simple PEP Traffic Analyzer"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help"
    echo "  -a, --all         Show all captured traffic"
    echo "  -r, --requests    Show HTTP requests only"
    echo "  -R, --responses   Show HTTP responses only"
    echo "  -c, --cookies     Show cookie operations"
    echo "  -o, --oauth       Show OAuth/OIDC flows"
    echo "  -f, --flows       Show traffic flows (IP:PORT)"
    echo "  -s, --summary     Show traffic summary"
    echo "  -l, --live        Monitor live traffic"
    echo "  --external        Show external user traffic"
    echo "  --backend         Show backend Dex traffic"
    echo "  --app             Show application Flask traffic"
    echo ""
}

get_latest_log() {
    local pattern="$1"
    find "$LOG_DIR" -name "$pattern" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-
}

show_all() {
    echo "=== ALL CAPTURED TRAFFIC ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        tail -100 "$main_log"
    else
        echo "No traffic data found"
    fi
}

show_requests() {
    echo "=== HTTP REQUESTS ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        grep -E "HTTP_(GET|POST)" "$main_log" | tail -50
    else
        echo "No request data found"
    fi
}

show_responses() {
    echo "=== HTTP RESPONSES ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        grep "HTTP_RESPONSE" "$main_log" | tail -50
    else
        echo "No response data found"
    fi
}

show_cookies() {
    echo "=== COOKIE OPERATIONS ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        grep -E "(COOKIE|SET_COOKIE)" "$main_log" | tail -30
    else
        echo "No cookie data found"
    fi
}

show_oauth() {
    echo "=== OAUTH/OIDC FLOWS ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        grep -E "(OAUTH|AUTH_)" "$main_log" | tail -30
    else
        echo "No OAuth data found"
    fi
}

show_flows() {
    echo "=== TRAFFIC FLOWS ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        grep "FLOW:" "$main_log" | tail -50
    else
        echo "No flow data found"
    fi
}

show_summary() {
    echo "=== TRAFFIC SUMMARY ==="
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        echo "📊 Traffic Statistics:"
        echo "  HTTP Requests: $(grep -c "HTTP_GET\|HTTP_POST" "$main_log" 2>/dev/null || echo 0)"
        echo "  HTTP Responses: $(grep -c "HTTP_RESPONSE" "$main_log" 2>/dev/null || echo 0)"
        echo "  OAuth Events: $(grep -c "OAUTH\|AUTH_" "$main_log" 2>/dev/null || echo 0)"
        echo "  Cookie Operations: $(grep -c "COOKIE\|SET_COOKIE" "$main_log" 2>/dev/null || echo 0)"
        echo "  Traffic Flows: $(grep -c "FLOW:" "$main_log" 2>/dev/null || echo 0)"
        echo ""
        echo "🌐 Network Activity:"
        echo "  External Traffic: $(ls -la "$LOG_DIR"/external_user_traffic_*.log 2>/dev/null | wc -l) log files"
        echo "  Backend Traffic: $(ls -la "$LOG_DIR"/backend_dex_traffic_*.log 2>/dev/null | wc -l) log files"
        echo "  App Traffic: $(ls -la "$LOG_DIR"/application_flask_traffic_*.log 2>/dev/null | wc -l) log files"
        echo ""
        echo "📁 Files:"
        ls -la "$LOG_DIR"/*.log 2>/dev/null | tail -5
    else
        echo "No traffic data found"
    fi
}

show_interface_traffic() {
    local interface_name="$1"
    local pattern="$2"
    
    echo "=== $interface_name ==="
    local log_file=$(get_latest_log "$pattern")
    if [ -n "$log_file" ]; then
        echo "📊 Recent Activity:"
        tail -20 "$log_file" | grep -E "(HTTP_|FLOW:|OAUTH|COOKIE)" | head -10
        echo ""
        echo "📈 Statistics:"
        echo "  HTTP Requests: $(grep -c "HTTP_GET\|HTTP_POST" "$log_file" 2>/dev/null || echo 0)"
        echo "  HTTP Responses: $(grep -c "HTTP_RESPONSE" "$log_file" 2>/dev/null || echo 0)"
        echo "  Traffic Flows: $(grep -c "FLOW:" "$log_file" 2>/dev/null || echo 0)"
    else
        echo "No data available"
    fi
}

monitor_live() {
    echo "=== LIVE TRAFFIC MONITORING ==="
    echo "Press Ctrl+C to stop..."
    local main_log=$(get_latest_log "complete_traffic_*.log")
    if [ -n "$main_log" ]; then
        tail -f "$main_log"
    else
        echo "No live data available"
    fi
}

# Parse arguments
case "$1" in
    -h|--help)
        show_help
        ;;
    -a|--all)
        show_all
        ;;
    -r|--requests)
        show_requests
        ;;
    -R|--responses)
        show_responses
        ;;
    -c|--cookies)
        show_cookies
        ;;
    -o|--oauth)
        show_oauth
        ;;
    -f|--flows)
        show_flows
        ;;
    -s|--summary)
        show_summary
        ;;
    -l|--live)
        monitor_live
        ;;
    --external)
        show_interface_traffic "EXTERNAL USER TRAFFIC" "external_user_traffic_*.log"
        ;;
    --backend)
        show_interface_traffic "BACKEND DEX TRAFFIC" "backend_dex_traffic_*.log"
        ;;
    --app)
        show_interface_traffic "APPLICATION FLASK TRAFFIC" "application_flask_traffic_*.log"
        ;;
    *)
        show_summary
        ;;
esac 