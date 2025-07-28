#!/bin/bash

# Per-Interface Advanced Traffic Monitor
# Monitors specific interface with detailed packet analysis and classification

INTERFACE="$1"
LOG_FILE="$2" 
PURPOSE="$3"

if [ -z "$INTERFACE" ] || [ -z "$LOG_FILE" ] || [ -z "$PURPOSE" ]; then
    echo "Usage: $0 <interface> <log_file> <purpose>"
    exit 1
fi

echo "=== $PURPOSE Interface Monitor Started ===" >> "$LOG_FILE"
echo "Interface: $INTERFACE" >> "$LOG_FILE"
echo "Purpose: $PURPOSE" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "=======================================" >> "$LOG_FILE"

# Function to analyze packet content and classify
analyze_packet() {
    local line="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # HTTP Request detection
    if [[ "$line" =~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)[[:space:]] ]]; then
        echo "[$timestamp] [$PURPOSE] HTTP_REQUEST: $line" >> "$LOG_FILE"
        
        # Extract method and path
        if [[ "$line" =~ ^([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
            method="${BASH_REMATCH[1]}"
            path="${BASH_REMATCH[2]}"
            echo "[$timestamp] [$PURPOSE] REQUEST_ANALYSIS: Method=$method, Path=$path" >> "$LOG_FILE"
        fi
        
    # HTTP Response detection  
    elif [[ "$line" =~ ^HTTP/[0-9]\.[0-9][[:space:]]+([0-9]{3}) ]]; then
        status_code="${BASH_REMATCH[1]}"
        echo "[$timestamp] [$PURPOSE] HTTP_RESPONSE: $line" >> "$LOG_FILE"
        echo "[$timestamp] [$PURPOSE] RESPONSE_ANALYSIS: StatusCode=$status_code" >> "$LOG_FILE"
        
        # Classify response types
        case "$status_code" in
            2*) echo "[$timestamp] [$PURPOSE] RESPONSE_TYPE: SUCCESS" >> "$LOG_FILE" ;;
            3*) echo "[$timestamp] [$PURPOSE] RESPONSE_TYPE: REDIRECT" >> "$LOG_FILE" ;;
            4*) echo "[$timestamp] [$PURPOSE] RESPONSE_TYPE: CLIENT_ERROR" >> "$LOG_FILE" ;;
            5*) echo "[$timestamp] [$PURPOSE] RESPONSE_TYPE: SERVER_ERROR" >> "$LOG_FILE" ;;
        esac
        
    # Header detection
    elif [[ "$line" =~ ^([A-Za-z-]+):[[:space:]]*(.+)$ ]]; then
        header_name="${BASH_REMATCH[1]}"
        header_value="${BASH_REMATCH[2]}"
        echo "[$timestamp] [$PURPOSE] HTTP_HEADER: $header_name: $header_value" >> "$LOG_FILE"
        
        # Special header analysis
        case "$header_name" in
            "Authorization"|"Cookie"|"Set-Cookie")
                echo "[$timestamp] [$PURPOSE] SECURITY_HEADER: $header_name" >> "$LOG_FILE"
                ;;
            "Content-Type"|"Content-Length")
                echo "[$timestamp] [$PURPOSE] CONTENT_HEADER: $header_name=$header_value" >> "$LOG_FILE"
                ;;
            "Location")
                echo "[$timestamp] [$PURPOSE] REDIRECT_HEADER: $header_value" >> "$LOG_FILE"
                ;;
            "X-"*|"Access-Control-"*)
                echo "[$timestamp] [$PURPOSE] CUSTOM_HEADER: $header_name" >> "$LOG_FILE"
                ;;
        esac
        
    # OAuth/OIDC detection
    elif [[ "$line" =~ (oauth2callback|authorize|token|userinfo|keys|code=|state=|access_token|refresh_token|id_token) ]]; then
        echo "[$timestamp] [$PURPOSE] OIDC_FLOW: $line" >> "$LOG_FILE"
        
        # Extract OIDC parameters
        if [[ "$line" =~ code=([^&[:space:]]+) ]]; then
            echo "[$timestamp] [$PURPOSE] OIDC_PARAM: authorization_code=${BASH_REMATCH[1]}" >> "$LOG_FILE"
        fi
        if [[ "$line" =~ state=([^&[:space:]]+) ]]; then
            echo "[$timestamp] [$PURPOSE] OIDC_PARAM: state=${BASH_REMATCH[1]}" >> "$LOG_FILE"
        fi
        
    # JSON detection
    elif [[ "$line" =~ ^\{.*\}$ ]] || [[ "$line" =~ ^\".*\":.*$ ]]; then
        echo "[$timestamp] [$PURPOSE] JSON_DATA: $line" >> "$LOG_FILE"
        
    # URL parameter detection
    elif [[ "$line" =~ [?&]([^=]+)=([^&[:space:]]+) ]]; then
        echo "[$timestamp] [$PURPOSE] URL_PARAM: ${BASH_REMATCH[1]}=${BASH_REMATCH[2]}" >> "$LOG_FILE"
        
    # Generic content
    elif [[ -n "$line" && ! "$line" =~ ^[[:space:]]*$ ]]; then
        echo "[$timestamp] [$PURPOSE] CONTENT: $line" >> "$LOG_FILE"
    fi
}

# Monitor interface with detailed packet analysis
tcpdump -i "$INTERFACE" -l -A -s 0 -nn 2>/dev/null | while IFS= read -r line; do
    timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Packet header detection
    if [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+ ]]; then
        echo "" >> "$LOG_FILE"
        echo "[$timestamp] [$PURPOSE] NEW_PACKET: $line" >> "$LOG_FILE"
        
        # Extract source and destination IPs
        if [[ "$line" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)[[:space:]]*>[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+) ]]; then
            src_ip="${BASH_REMATCH[1]}"
            src_port="${BASH_REMATCH[2]}"
            dst_ip="${BASH_REMATCH[3]}"
            dst_port="${BASH_REMATCH[4]}"
            
            echo "[$timestamp] [$PURPOSE] FLOW: $src_ip:$src_port -> $dst_ip:$dst_port" >> "$LOG_FILE"
            
            # Classify traffic direction and purpose
            case "$dst_port" in
                80) echo "[$timestamp] [$PURPOSE] TRAFFIC_TYPE: HTTP_WEB" >> "$LOG_FILE" ;;
                443) echo "[$timestamp] [$PURPOSE] TRAFFIC_TYPE: HTTPS_WEB" >> "$LOG_FILE" ;;
                5556) echo "[$timestamp] [$PURPOSE] TRAFFIC_TYPE: DEX_OIDC" >> "$LOG_FILE" ;;
                8080) echo "[$timestamp] [$PURPOSE] TRAFFIC_TYPE: FLASK_APP" >> "$LOG_FILE" ;;
                *) echo "[$timestamp] [$PURPOSE] TRAFFIC_TYPE: OTHER_PORT_$dst_port" >> "$LOG_FILE" ;;
            esac
        fi
        
    # Hex dump detection  
    elif [[ "$line" =~ ^[[:space:]]*0x[0-9a-f]+ ]]; then
        echo "[$timestamp] [$PURPOSE] HEX_DATA: $line" >> "$LOG_FILE"
        
    # ASCII content analysis
    else
        analyze_packet "$line"
    fi
done 