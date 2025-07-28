#!/bin/bash

# Session Tracker
# Reconstructs complete user sessions by tracking authentication flows and subsequent requests

LOG_FILE="$1"
if [ -z "$LOG_FILE" ]; then
    LOG_FILE="/var/log/sniffer/session_tracking.log"
fi

echo "=== Session Tracker Started ===" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "===============================" >> "$LOG_FILE"

# Session tracking data
TEMP_DIR="/tmp/session_tracker"
mkdir -p "$TEMP_DIR"

SESSIONS_FILE="$TEMP_DIR/sessions"
USER_SESSIONS_FILE="$TEMP_DIR/user_sessions"
AUTHENTICATION_FILE="$TEMP_DIR/authentication_events"

# Initialize tracking files
> "$SESSIONS_FILE"
> "$USER_SESSIONS_FILE"
> "$AUTHENTICATION_FILE"

# Function to generate session ID
generate_session_id() {
    local user_ip="$1"
    local timestamp="$2"
    echo "${user_ip}_$(echo "$timestamp" | md5sum | cut -d' ' -f1 | cut -c1-8)"
}

# Function to track authentication event
track_authentication() {
    local timestamp="$1"
    local event_type="$2"
    local details="$3"
    local user_ip="$4"
    
    echo "$timestamp|$event_type|$details|$user_ip" >> "$AUTHENTICATION_FILE"
    echo "[$timestamp] AUTH_EVENT: $event_type for $user_ip - $details" >> "$LOG_FILE"
    
    # Create or update session
    case "$event_type" in
        "LOGIN_INITIATED")
            local session_id=$(generate_session_id "$user_ip" "$timestamp")
            echo "$timestamp|$session_id|$user_ip|LOGIN_STARTED|$details" >> "$SESSIONS_FILE"
            echo "[$timestamp] SESSION_CREATED: $session_id for $user_ip" >> "$LOG_FILE"
            ;;
        "LOGIN_COMPLETED")
            update_session_status "$timestamp" "$user_ip" "AUTHENTICATED" "$details"
            ;;
        "ACCESS_GRANTED")
            update_session_status "$timestamp" "$user_ip" "ACTIVE" "$details"
            ;;
        "SESSION_TIMEOUT")
            update_session_status "$timestamp" "$user_ip" "EXPIRED" "$details"
            ;;
    esac
}

# Function to update session status
update_session_status() {
    local timestamp="$1"
    local user_ip="$2"
    local new_status="$3"
    local details="$4"
    
    # Find the latest session for this user
    local session_entry=$(grep "|$user_ip|" "$SESSIONS_FILE" | tail -1)
    if [ -n "$session_entry" ]; then
        IFS='|' read -r orig_timestamp session_id ip old_status old_details <<< "$session_entry"
        echo "$timestamp|$session_id|$user_ip|$new_status|$details" >> "$SESSIONS_FILE"
        echo "[$timestamp] SESSION_UPDATED: $session_id status: $old_status -> $new_status" >> "$LOG_FILE"
    fi
}

# Function to track user request
track_user_request() {
    local timestamp="$1"
    local user_ip="$2"
    local method="$3"
    local path="$4"
    local response_code="$5"
    
    # Find active session for this user
    local session_entry=$(grep "|$user_ip|" "$SESSIONS_FILE" | grep -E "(AUTHENTICATED|ACTIVE)" | tail -1)
    if [ -n "$session_entry" ]; then
        IFS='|' read -r orig_timestamp session_id ip status details <<< "$session_entry"
        echo "$timestamp|$session_id|$method|$path|$response_code|$user_ip" >> "$USER_SESSIONS_FILE"
        echo "[$timestamp] USER_REQUEST: $session_id -> $method $path ($response_code)" >> "$LOG_FILE"
        
        # Analyze request patterns
        analyze_request_pattern "$timestamp" "$session_id" "$method" "$path" "$response_code"
    else
        echo "[$timestamp] UNTRACKED_REQUEST: $user_ip -> $method $path (no active session)" >> "$LOG_FILE"
    fi
}

# Function to analyze request patterns
analyze_request_pattern() {
    local timestamp="$1"
    local session_id="$2"
    local method="$3"
    local path="$4"
    local response_code="$5"
    
    # Pattern analysis
    case "$path" in
        "/")
            echo "[$timestamp] PATTERN: $session_id - Main page access" >> "$LOG_FILE"
            ;;
        "/oauth2callback"*)
            echo "[$timestamp] PATTERN: $session_id - OAuth callback received" >> "$LOG_FILE"
            track_authentication "$timestamp" "LOGIN_COMPLETED" "OAuth callback" "$(get_session_ip "$session_id")"
            ;;
        "/logout")
            echo "[$timestamp] PATTERN: $session_id - Logout initiated" >> "$LOG_FILE"
            update_session_status "$timestamp" "$(get_session_ip "$session_id")" "LOGGED_OUT" "User logout"
            ;;
        */api/*)
            echo "[$timestamp] PATTERN: $session_id - API call: $path" >> "$LOG_FILE"
            ;;
        */static/*)
            echo "[$timestamp] PATTERN: $session_id - Static resource: $path" >> "$LOG_FILE"
            ;;
        *)
            echo "[$timestamp] PATTERN: $session_id - Other resource: $path" >> "$LOG_FILE"
            ;;
    esac
    
    # Response code analysis
    case "$response_code" in
        2*)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Success" >> "$LOG_FILE"
            ;;
        302|303)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Redirect (likely auth flow)" >> "$LOG_FILE"
            ;;
        401)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Unauthorized (auth required)" >> "$LOG_FILE"
            track_authentication "$timestamp" "LOGIN_INITIATED" "401 Unauthorized" "$(get_session_ip "$session_id")"
            ;;
        403)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Forbidden (access denied)" >> "$LOG_FILE"
            ;;
        4*)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Client error" >> "$LOG_FILE"
            ;;
        5*)
            echo "[$timestamp] RESPONSE_ANALYSIS: $session_id - Server error" >> "$LOG_FILE"
            ;;
    esac
}

# Function to get session IP
get_session_ip() {
    local session_id="$1"
    grep "|$session_id|" "$SESSIONS_FILE" | tail -1 | cut -d'|' -f3
}

# Function to generate session report
generate_session_report() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "" >> "$LOG_FILE"
    echo "[$timestamp] === SESSION REPORT ===" >> "$LOG_FILE"
    
    # Active sessions
    local active_sessions=$(grep -E "(AUTHENTICATED|ACTIVE)" "$SESSIONS_FILE" | cut -d'|' -f2 | sort | uniq | wc -l)
    echo "[$timestamp] Active sessions: $active_sessions" >> "$LOG_FILE"
    
    # Session statistics
    echo "[$timestamp] Session Status Summary:" >> "$LOG_FILE"
    cut -d'|' -f4 "$SESSIONS_FILE" | sort | uniq -c | while read count status; do
        echo "[$timestamp]   $status: $count" >> "$LOG_FILE"
    done
    
    # Request statistics
    if [ -s "$USER_SESSIONS_FILE" ]; then
        echo "[$timestamp] Request Statistics:" >> "$LOG_FILE"
        local total_requests=$(wc -l < "$USER_SESSIONS_FILE")
        echo "[$timestamp]   Total requests: $total_requests" >> "$LOG_FILE"
        
        # Requests by method
        cut -d'|' -f3 "$USER_SESSIONS_FILE" | sort | uniq -c | while read count method; do
            echo "[$timestamp]   $method: $count requests" >> "$LOG_FILE"
        done
        
        # Response codes
        cut -d'|' -f5 "$USER_SESSIONS_FILE" | sort | uniq -c | while read count code; do
            echo "[$timestamp]   HTTP $code: $count responses" >> "$LOG_FILE"
        done
    fi
    
    echo "[$timestamp] ========================" >> "$LOG_FILE"
}

# Function to detect session timeouts
detect_session_timeouts() {
    local current_time=$(date +%s)
    local timeout_threshold=1800  # 30 minutes
    
    while IFS='|' read -r timestamp session_id user_ip status details; do
        if [[ "$status" == "ACTIVE" || "$status" == "AUTHENTICATED" ]]; then
            local session_time=$(date -d "$timestamp" +%s 2>/dev/null || echo "$current_time")
            local time_diff=$((current_time - session_time))
            
            if [ "$time_diff" -gt "$timeout_threshold" ]; then
                local now=$(date '+%Y-%m-%d %H:%M:%S')
                echo "[$now] SESSION_TIMEOUT: $session_id (inactive for ${time_diff}s)" >> "$LOG_FILE"
                track_authentication "$now" "SESSION_TIMEOUT" "Inactive for ${time_diff}s" "$user_ip"
            fi
        fi
    done < "$SESSIONS_FILE"
}

# Main session tracking loop
echo "Starting session tracking..." >> "$LOG_FILE"

# Monitor all interface logs for session data
tail -F /var/log/sniffer/*_requests_*.log /var/log/sniffer/*_authentication_*.log 2>/dev/null | while read line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Extract HTTP requests
    if [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[[^\]]+\][[:space:]]*HTTP_REQUEST:[[:space:]]*([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        method="${BASH_REMATCH[2]}"
        path="${BASH_REMATCH[3]}"
        
        # Extract user IP from previous FLOW line (this is a simplification)
        user_ip="external_user"  # This would need more sophisticated IP extraction
        
        track_user_request "$log_timestamp" "$user_ip" "$method" "$path" "unknown"
        
    # Extract HTTP responses
    elif [[ "$line" =~ \[([^\]]+)\][[:space:]]*\[[^\]]+\][[:space:]]*HTTP_RESPONSE:[[:space:]]*HTTP/[0-9]\.[0-9][[:space:]]+([0-9]{3}) ]]; then
        log_timestamp="${BASH_REMATCH[1]}"
        response_code="${BASH_REMATCH[2]}"
        
        # This would need correlation with the previous request
        echo "[$log_timestamp] RESPONSE_TRACKED: $response_code" >> "$LOG_FILE"
        
    # Extract OIDC flows
    elif [[ "$line" =~ OIDC_FLOW.*oauth2callback ]]; then
        track_authentication "$timestamp" "LOGIN_COMPLETED" "OAuth callback" "external_user"
        
    elif [[ "$line" =~ OIDC_FLOW.*authorize ]]; then
        track_authentication "$timestamp" "LOGIN_INITIATED" "OAuth authorization" "external_user"
    fi
done &

# Periodic tasks
while true; do
    sleep 60  # Run every minute
    generate_session_report
    detect_session_timeouts
done 