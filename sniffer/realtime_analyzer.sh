#!/bin/bash

# Real-time Traffic Analysis Engine
# Provides live analysis dashboard and intelligent traffic monitoring

LOG_FILE="$1"
if [ -z "$LOG_FILE" ]; then
    LOG_FILE="/var/log/sniffer/realtime_analysis.log"
fi

echo "=== Real-time Analysis Engine Started ===" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "=========================================" >> "$LOG_FILE"

# Analysis data storage
TEMP_DIR="/tmp/realtime_analysis"
mkdir -p "$TEMP_DIR"

STATS_FILE="$TEMP_DIR/stats"
ANOMALIES_FILE="$TEMP_DIR/anomalies"
PERFORMANCE_FILE="$TEMP_DIR/performance"
SECURITY_FILE="$TEMP_DIR/security_events"

# Initialize analysis files
> "$STATS_FILE"
> "$ANOMALIES_FILE"
> "$PERFORMANCE_FILE"  
> "$SECURITY_FILE"

# Performance counters
declare -A request_counts
declare -A response_times
declare -A error_counts
declare -A auth_events
declare -A suspicious_patterns

# Function to update traffic statistics
update_traffic_stats() {
    local timestamp="$1"
    local interface="$2"
    local traffic_type="$3"
    local details="$4"
    
    # Update counters
    local key="${interface}_${traffic_type}"
    request_counts["$key"]=$((${request_counts["$key"]:-0} + 1))
    
    echo "$timestamp|TRAFFIC_STAT|$interface|$traffic_type|${request_counts["$key"]}|$details" >> "$STATS_FILE"
    
    # Real-time logging
    echo "[$timestamp] STATS_UPDATE: $interface/$traffic_type count: ${request_counts["$key"]}" >> "$LOG_FILE"
}

# Function to analyze authentication patterns
analyze_auth_pattern() {
    local timestamp="$1"
    local event_type="$2"
    local details="$3"
    
    auth_events["$event_type"]=$((${auth_events["$event_type"]:-0} + 1))
    
    echo "$timestamp|AUTH_PATTERN|$event_type|${auth_events["$event_type"]}|$details" >> "$SECURITY_FILE"
    echo "[$timestamp] AUTH_ANALYSIS: $event_type event #${auth_events["$event_type"]}" >> "$LOG_FILE"
    
    # Detect authentication anomalies
    case "$event_type" in
        "FAILED_LOGIN")
            if [ "${auth_events["FAILED_LOGIN"]}" -gt 5 ]; then
                detect_anomaly "$timestamp" "BRUTE_FORCE" "Multiple failed login attempts: ${auth_events["FAILED_LOGIN"]}"
            fi
            ;;
        "RAPID_LOGINS")
            detect_anomaly "$timestamp" "SUSPICIOUS_AUTH" "Rapid login pattern detected"
            ;;
        "UNAUTHORIZED_ACCESS")
            detect_anomaly "$timestamp" "SECURITY_BREACH" "Unauthorized access attempt"
            ;;
    esac
}

# Function to detect anomalies
detect_anomaly() {
    local timestamp="$1"
    local anomaly_type="$2"
    local description="$3"
    
    echo "$timestamp|ANOMALY|$anomaly_type|$description" >> "$ANOMALIES_FILE"
    echo "[$timestamp] ⚠️  ANOMALY_DETECTED: $anomaly_type - $description" >> "$LOG_FILE"
    
    # Track suspicious patterns
    suspicious_patterns["$anomaly_type"]=$((${suspicious_patterns["$anomaly_type"]:-0} + 1))
}

# Function to analyze response times
analyze_response_time() {
    local timestamp="$1"
    local endpoint="$2"
    local response_code="$3"
    local estimated_time="$4"
    
    echo "$timestamp|PERFORMANCE|$endpoint|$response_code|$estimated_time" >> "$PERFORMANCE_FILE"
    
    # Detect slow responses
    if [ "$estimated_time" -gt 5000 ]; then  # More than 5 seconds
        detect_anomaly "$timestamp" "SLOW_RESPONSE" "Slow response on $endpoint: ${estimated_time}ms"
    fi
    
    # Detect errors
    case "$response_code" in
        5*)
            error_counts["5xx"]=$((${error_counts["5xx"]:-0} + 1))
            detect_anomaly "$timestamp" "SERVER_ERROR" "HTTP $response_code on $endpoint"
            ;;
        4*)
            error_counts["4xx"]=$((${error_counts["4xx"]:-0} + 1))
            if [ "$response_code" = "401" ]; then
                analyze_auth_pattern "$timestamp" "UNAUTHORIZED_ACCESS" "$endpoint"
            fi
            ;;
    esac
}

# Function to analyze OIDC flows
analyze_oidc_security() {
    local timestamp="$1"
    local flow_type="$2"
    local parameters="$3"
    
    echo "[$timestamp] OIDC_SECURITY: $flow_type analysis" >> "$LOG_FILE"
    
    case "$flow_type" in
        "authorization_code")
            # Check code format and security
            if [[ "$parameters" =~ code=([^&]+) ]]; then
                local code="${BASH_REMATCH[1]}"
                local code_length=${#code}
                
                if [ "$code_length" -lt 20 ]; then
                    detect_anomaly "$timestamp" "WEAK_AUTH_CODE" "Authorization code too short: $code_length chars"
                fi
                
                echo "$timestamp|OIDC_SECURITY|AUTH_CODE|$code_length|$code" >> "$SECURITY_FILE"
            fi
            ;;
        "state_parameter")
            # Verify state parameter security
            if [[ "$parameters" =~ state=([^&]+) ]]; then
                local state="${BASH_REMATCH[1]}"
                local state_length=${#state}
                
                if [ "$state_length" -lt 10 ]; then
                    detect_anomaly "$timestamp" "WEAK_STATE" "State parameter too short: $state_length chars"
                fi
            fi
            ;;
        "token_exchange")
            echo "$timestamp|OIDC_SECURITY|TOKEN_EXCHANGE|DETECTED" >> "$SECURITY_FILE"
            ;;
    esac
}

# Function to generate real-time dashboard
generate_dashboard() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "" >> "$LOG_FILE"
    echo "[$timestamp] ═══════════════════════════════════════" >> "$LOG_FILE"
    echo "[$timestamp] 📊 REAL-TIME TRAFFIC DASHBOARD" >> "$LOG_FILE"
    echo "[$timestamp] ═══════════════════════════════════════" >> "$LOG_FILE"
    
    # Traffic Statistics
    echo "[$timestamp] 🌐 TRAFFIC OVERVIEW:" >> "$LOG_FILE"
    for key in "${!request_counts[@]}"; do
        IFS='_' read -r interface traffic_type <<< "$key"
        echo "[$timestamp]   $interface ($traffic_type): ${request_counts["$key"]} requests" >> "$LOG_FILE"
    done
    
    # Authentication Statistics
    if [ ${#auth_events[@]} -gt 0 ]; then
        echo "[$timestamp] 🔐 AUTHENTICATION EVENTS:" >> "$LOG_FILE"
        for event in "${!auth_events[@]}"; do
            echo "[$timestamp]   $event: ${auth_events["$event"]} events" >> "$LOG_FILE"
        done
    fi
    
    # Error Statistics
    if [ ${#error_counts[@]} -gt 0 ]; then
        echo "[$timestamp] ❌ ERROR SUMMARY:" >> "$LOG_FILE"
        for error_type in "${!error_counts[@]}"; do
            echo "[$timestamp]   $error_type errors: ${error_counts["$error_type"]}" >> "$LOG_FILE"
        done
    fi
    
    # Security Anomalies
    if [ ${#suspicious_patterns[@]} -gt 0 ]; then
        echo "[$timestamp] ⚠️  SECURITY ANOMALIES:" >> "$LOG_FILE"
        for pattern in "${!suspicious_patterns[@]}"; do
            echo "[$timestamp]   $pattern: ${suspicious_patterns["$pattern"]} incidents" >> "$LOG_FILE"
        done
    fi
    
    # Active Connections Summary
    local active_connections=$(netstat -tn 2>/dev/null | grep -E ":(80|5556|8080)" | grep ESTABLISHED | wc -l)
    echo "[$timestamp] 🔗 ACTIVE CONNECTIONS: $active_connections" >> "$LOG_FILE"
    
    # Network Interface Status
    echo "[$timestamp] 🌍 NETWORK INTERFACES:" >> "$LOG_FILE"
    for iface in eth0 eth1 eth2; do
        local rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
        local tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
        echo "[$timestamp]   $iface: RX=${rx_bytes}B TX=${tx_bytes}B" >> "$LOG_FILE"
    done
    
    echo "[$timestamp] ═══════════════════════════════════════" >> "$LOG_FILE"
}

# Function to detect traffic patterns
detect_traffic_patterns() {
    local timestamp="$1"
    local recent_requests=()
    
    # Analyze recent traffic for patterns
    mapfile -t recent_requests < <(tail -20 "$STATS_FILE")
    
    local rapid_requests=0
    local last_timestamp=""
    
    for request in "${recent_requests[@]}"; do
        IFS='|' read -r req_timestamp _ _ _ _ _ <<< "$request"
        
        if [ -n "$last_timestamp" ]; then
            local time_diff=$(( $(date -d "$req_timestamp" +%s) - $(date -d "$last_timestamp" +%s) ))
            if [ "$time_diff" -lt 1 ]; then
                ((rapid_requests++))
            fi
        fi
        last_timestamp="$req_timestamp"
    done
    
    # Detect DDoS-like patterns
    if [ "$rapid_requests" -gt 10 ]; then
        detect_anomaly "$timestamp" "RAPID_REQUESTS" "Detected $rapid_requests rapid requests in recent history"
    fi
}

# Function to analyze HTTP patterns
analyze_http_pattern() {
    local timestamp="$1"
    local method="$2"
    local path="$3"
    local response_code="$4"
    local interface="$5"
    
    # Update traffic stats
    update_traffic_stats "$timestamp" "$interface" "HTTP_$method" "$path"
    
    # Analyze specific patterns
    case "$path" in
        "/oauth2callback")
            analyze_auth_pattern "$timestamp" "OAUTH_CALLBACK" "$path"
            ;;
        "/logout")
            analyze_auth_pattern "$timestamp" "LOGOUT" "$path"
            ;;
        "/"*)
            # Root access patterns
            update_traffic_stats "$timestamp" "$interface" "ROOT_ACCESS" "$method"
            ;;
        *"admin"*|*"config"*|*".env"*)
            # Suspicious path access
            detect_anomaly "$timestamp" "SUSPICIOUS_PATH" "Access to sensitive path: $path"
            ;;
    esac
    
    # Estimate response time (basic heuristic)
    local estimated_time=1000  # Default 1 second
    case "$response_code" in
        2*) estimated_time=500 ;;
        3*) estimated_time=300 ;;
        4*) estimated_time=200 ;;
        5*) estimated_time=3000 ;;
    esac
    
    analyze_response_time "$timestamp" "$path" "$response_code" "$estimated_time"
}

# Main analysis loop
echo "Starting real-time traffic analysis..." >> "$LOG_FILE"

# Monitor all log files for analysis
tail -F /var/log/sniffer/*_communication_*.log /var/log/sniffer/*_authentication_*.log /var/log/sniffer/*_requests_*.log 2>/dev/null | while read line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Analyze HTTP requests
    if [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*HTTP_REQUEST:[[:space:]]*([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        purpose="${BASH_REMATCH[2]}"
        method="${BASH_REMATCH[3]}"
        path="${BASH_REMATCH[4]}"
        
        analyze_http_pattern "$log_timestamp" "$method" "$path" "unknown" "$purpose"
        
    # Analyze HTTP responses
    elif [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*HTTP_RESPONSE:[[:space:]]*HTTP/[0-9]\.[0-9][[:space:]]+([0-9]{3}) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        purpose="${BASH_REMATCH[2]}"
        response_code="${BASH_REMATCH[3]}"
        
        analyze_response_time "$log_timestamp" "unknown" "$response_code" 1000
        
    # Analyze OIDC flows
    elif [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*OIDC_FLOW:[[:space:]]*(.+) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        purpose="${BASH_REMATCH[2]}"
        oidc_content="${BASH_REMATCH[3]}"
        
        if [[ "$oidc_content" =~ oauth2callback ]]; then
            analyze_oidc_security "$log_timestamp" "authorization_code" "$oidc_content"
        elif [[ "$oidc_content" =~ authorize ]]; then
            analyze_oidc_security "$log_timestamp" "state_parameter" "$oidc_content"
        elif [[ "$oidc_content" =~ token ]]; then
            analyze_oidc_security "$log_timestamp" "token_exchange" "$oidc_content"
        fi
        
    # Analyze OIDC parameters
    elif [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*OIDC_PARAM:[[:space:]]*(.+) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        purpose="${BASH_REMATCH[2]}"
        param_content="${BASH_REMATCH[3]}"
        
        if [[ "$param_content" =~ authorization_code= ]]; then
            analyze_oidc_security "$log_timestamp" "authorization_code" "$param_content"
        elif [[ "$param_content" =~ state= ]]; then
            analyze_oidc_security "$log_timestamp" "state_parameter" "$param_content"
        fi
    fi
    
    # Detect traffic patterns periodically
    detect_traffic_patterns "$timestamp"
done &

# Generate periodic dashboards and reports
while true; do
    sleep 30  # Update dashboard every 30 seconds
    generate_dashboard
done 