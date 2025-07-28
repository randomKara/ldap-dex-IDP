#!/bin/bash

# Flow Correlation Engine
# Correlates traffic flows across different network interfaces to track complete sessions

LOG_FILE="$1"
if [ -z "$LOG_FILE" ]; then
    LOG_FILE="/var/log/sniffer/flow_correlation.log"
fi

echo "=== Flow Correlation Engine Started ===" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "=======================================" >> "$LOG_FILE"

# Temporary files for correlation data
TEMP_DIR="/tmp/flow_correlation"
mkdir -p "$TEMP_DIR"

FLOWS_FILE="$TEMP_DIR/active_flows"
SESSIONS_FILE="$TEMP_DIR/active_sessions"
CORRELATIONS_FILE="$TEMP_DIR/correlations"

# Initialize correlation tracking files
> "$FLOWS_FILE"
> "$SESSIONS_FILE" 
> "$CORRELATIONS_FILE"

# Function to track a flow
track_flow() {
    local timestamp="$1"
    local interface="$2"
    local src_ip="$3"
    local src_port="$4"
    local dst_ip="$5"
    local dst_port="$6"
    local purpose="$7"
    
    local flow_id="${src_ip}:${src_port}-${dst_ip}:${dst_port}"
    local reverse_flow_id="${dst_ip}:${dst_port}-${src_ip}:${src_port}"
    
    # Record the flow
    echo "$timestamp|$interface|$flow_id|$purpose|$src_ip|$src_port|$dst_ip|$dst_port" >> "$FLOWS_FILE"
    
    echo "[$timestamp] FLOW_TRACKED: $interface -> $flow_id ($purpose)" >> "$LOG_FILE"
    
    # Check for flow correlations
    correlate_flows "$timestamp" "$flow_id" "$reverse_flow_id" "$interface" "$purpose"
}

# Function to correlate flows across interfaces
correlate_flows() {
    local timestamp="$1"
    local flow_id="$2"
    local reverse_flow_id="$3"
    local current_interface="$4"
    local current_purpose="$5"
    
    # Look for related flows in other interfaces
    while IFS='|' read -r prev_timestamp prev_interface prev_flow_id prev_purpose prev_src_ip prev_src_port prev_dst_ip prev_dst_port; do
        if [ "$prev_interface" != "$current_interface" ]; then
            # Check if this could be the same session
            if [[ "$prev_src_ip" == *"172.25"* ]] && [[ "$prev_dst_ip" == *"172.25"* ]]; then
                # Network-to-network correlation
                echo "[$timestamp] FLOW_CORRELATION: $current_interface ($current_purpose) <-> $prev_interface ($prev_purpose)" >> "$LOG_FILE"
                echo "$timestamp|$current_interface|$prev_interface|$flow_id|$prev_flow_id|NETWORK_HOP" >> "$CORRELATIONS_FILE"
                
                # Track session flow
                track_session "$timestamp" "$current_interface" "$prev_interface" "$current_purpose" "$prev_purpose"
            fi
        fi
    done < "$FLOWS_FILE"
}

# Function to track complete sessions
track_session() {
    local timestamp="$1"
    local interface1="$2"
    local interface2="$3"
    local purpose1="$4"
    local purpose2="$5"
    
    local session_id=$(echo "$interface1-$interface2-$purpose1-$purpose2" | md5sum | cut -d' ' -f1 | cut -c1-8)
    
    echo "[$timestamp] SESSION_FLOW: $session_id -> $interface1 ($purpose1) <-> $interface2 ($purpose2)" >> "$LOG_FILE"
    echo "$timestamp|$session_id|$interface1|$interface2|$purpose1|$purpose2|ACTIVE" >> "$SESSIONS_FILE"
}

# Function to analyze OIDC authentication flows
analyze_oidc_flow() {
    local timestamp="$1"
    local content="$2"
    
    if [[ "$content" =~ oauth2callback.*code=([^&[:space:]]+) ]]; then
        local auth_code="${BASH_REMATCH[1]}"
        echo "[$timestamp] OIDC_ANALYSIS: Authorization code received: $auth_code" >> "$LOG_FILE"
        
        # Track authorization flow
        echo "$timestamp|OIDC|AUTH_CODE|$auth_code" >> "$CORRELATIONS_FILE"
        
    elif [[ "$content" =~ /auth.*response_type=code ]]; then
        echo "[$timestamp] OIDC_ANALYSIS: Authorization request initiated" >> "$LOG_FILE"
        echo "$timestamp|OIDC|AUTH_REQUEST|INITIATED" >> "$CORRELATIONS_FILE"
        
    elif [[ "$content" =~ /token ]]; then
        echo "[$timestamp] OIDC_ANALYSIS: Token exchange detected" >> "$LOG_FILE"
        echo "$timestamp|OIDC|TOKEN_EXCHANGE|DETECTED" >> "$CORRELATIONS_FILE"
    fi
}

# Function to generate correlation reports
generate_correlation_report() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "" >> "$LOG_FILE"
    echo "[$timestamp] === CORRELATION REPORT ===" >> "$LOG_FILE"
    
    # Active flows summary
    local total_flows=$(wc -l < "$FLOWS_FILE")
    echo "[$timestamp] Total tracked flows: $total_flows" >> "$LOG_FILE"
    
    # Interface activity summary
    echo "[$timestamp] Interface Activity:" >> "$LOG_FILE"
    cut -d'|' -f2,4 "$FLOWS_FILE" | sort | uniq -c | while read count interface_purpose; do
        echo "[$timestamp]   $interface_purpose: $count flows" >> "$LOG_FILE"
    done
    
    # Session summary  
    local total_sessions=$(wc -l < "$SESSIONS_FILE")
    echo "[$timestamp] Total active sessions: $total_sessions" >> "$LOG_FILE"
    
    # Correlation summary
    local total_correlations=$(wc -l < "$CORRELATIONS_FILE")
    echo "[$timestamp] Total correlations: $total_correlations" >> "$LOG_FILE"
    
    echo "[$timestamp] =============================" >> "$LOG_FILE"
}

# Main correlation loop
echo "Starting flow correlation monitoring..." >> "$LOG_FILE"

# Monitor all interface logs for correlation data
tail -F /var/log/sniffer/*_communication_*.log /var/log/sniffer/*_authentication_*.log /var/log/sniffer/*_requests_*.log 2>/dev/null | while read line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Extract flow information from logs
    if [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[([^\]]+)\][[:space:]]*FLOW:[[:space:]]*([0-9.]+):([0-9]+)[[:space:]]*->[[:space:]]*([0-9.]+):([0-9]+) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        purpose="${BASH_REMATCH[2]}"
        src_ip="${BASH_REMATCH[3]}"
        src_port="${BASH_REMATCH[4]}"
        dst_ip="${BASH_REMATCH[5]}"
        dst_port="${BASH_REMATCH[6]}"
        
        # Determine interface from purpose
        case "$purpose" in
            *"Flask"*) interface="eth0" ;;
            *"Dex"*) interface="eth1" ;;
            *"User"*) interface="eth2" ;;
            *) interface="unknown" ;;
        esac
        
        track_flow "$timestamp" "$interface" "$src_ip" "$src_port" "$dst_ip" "$dst_port" "$purpose"
        
    # Analyze OIDC flows
    elif [[ "$line" =~ OIDC_FLOW ]]; then
        analyze_oidc_flow "$timestamp" "$line"
    fi
done &

# Generate periodic correlation reports
while true; do
    sleep 60  # Generate report every minute
    generate_correlation_report
done 