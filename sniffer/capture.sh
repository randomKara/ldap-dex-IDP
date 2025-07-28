#!/bin/bash

# Real-time traffic capture and logging
# Captures all network traffic and logs it with timestamps and details

LOG_FILE="$1"
if [ -z "$LOG_FILE" ]; then
    LOG_FILE="/var/log/sniffer/capture.log"
fi

echo "=== Real-time Traffic Capture Started ===" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "=========================================" >> "$LOG_FILE"

# Monitor all interfaces for HTTP traffic
tcpdump -i any -l -A -s 0 'tcp port 80 or tcp port 5556 or tcp port 8080' 2>/dev/null | while IFS= read -r line; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Check if this is a new packet
    if [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+ ]]; then
        echo "" >> "$LOG_FILE"
        echo "[$TIMESTAMP] NEW_PACKET: $line" >> "$LOG_FILE"
    elif [[ "$line" =~ ^[[:space:]]*0x[0-9a-f]+ ]]; then
        # Hex dump line
        echo "[$TIMESTAMP] HEX_DATA: $line" >> "$LOG_FILE"
    elif [[ -n "$line" ]]; then
        # ASCII content or other data
        # Try to detect HTTP headers and requests
        if [[ "$line" =~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ]]; then
            echo "[$TIMESTAMP] HTTP_REQUEST: $line" >> "$LOG_FILE"
        elif [[ "$line" =~ ^HTTP/ ]]; then
            echo "[$TIMESTAMP] HTTP_RESPONSE: $line" >> "$LOG_FILE"
        elif [[ "$line" =~ ^(Host:|Content-Type:|Authorization:|Cookie:|User-Agent:|Accept:|Content-Length:) ]]; then
            echo "[$TIMESTAMP] HTTP_HEADER: $line" >> "$LOG_FILE"
        elif [[ "$line" =~ ^(Location:|Set-Cookie:|X-|Access-Control) ]]; then
            echo "[$TIMESTAMP] HTTP_HEADER: $line" >> "$LOG_FILE"
        else
            echo "[$TIMESTAMP] CONTENT: $line" >> "$LOG_FILE"
        fi
    fi
done 