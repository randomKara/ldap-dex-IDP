#!/bin/bash

# HTTP Traffic Analyzer
# Analyzes HTTP requests/responses and creates structured logs

LOG_FILE="$1"
if [ -z "$LOG_FILE" ]; then
    LOG_FILE="/var/log/sniffer/http_analysis.log"
fi

echo "=== HTTP Traffic Analysis Started ===" >> "$LOG_FILE"
echo "Timestamp: $(date)" >> "$LOG_FILE"
echo "=====================================" >> "$LOG_FILE"

# Use tshark to analyze HTTP traffic with detailed output
tshark -i any -f 'tcp port 80 or tcp port 5556 or tcp port 8080' -Y 'http' -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e http.request.method \
    -e http.request.uri \
    -e http.host \
    -e http.user_agent \
    -e http.response.code \
    -e http.content_type \
    -e http.content_length \
    -e http.authorization \
    -e http.cookie \
    -e http.set_cookie \
    -e http.location \
    -E header=y -E separator='|' 2>/dev/null | while IFS='|' read -r timestamp src_ip dst_ip src_port dst_port method uri host user_agent response_code content_type content_length auth cookie set_cookie location; do
    
    if [ -n "$timestamp" ]; then
        echo "" >> "$LOG_FILE"
        echo "=== HTTP TRANSACTION ===" >> "$LOG_FILE"
        echo "Timestamp: $timestamp" >> "$LOG_FILE"
        echo "Source: $src_ip:$src_port" >> "$LOG_FILE"
        echo "Destination: $dst_ip:$dst_port" >> "$LOG_FILE"
        
        if [ -n "$method" ]; then
            echo "REQUEST:" >> "$LOG_FILE"
            echo "  Method: $method" >> "$LOG_FILE"
            echo "  URI: $uri" >> "$LOG_FILE"
            echo "  Host: $host" >> "$LOG_FILE"
            echo "  User-Agent: $user_agent" >> "$LOG_FILE"
            [ -n "$auth" ] && echo "  Authorization: $auth" >> "$LOG_FILE"
            [ -n "$cookie" ] && echo "  Cookie: $cookie" >> "$LOG_FILE"
        fi
        
        if [ -n "$response_code" ]; then
            echo "RESPONSE:" >> "$LOG_FILE"
            echo "  Status Code: $response_code" >> "$LOG_FILE"
            echo "  Content-Type: $content_type" >> "$LOG_FILE"
            echo "  Content-Length: $content_length" >> "$LOG_FILE"
            [ -n "$set_cookie" ] && echo "  Set-Cookie: $set_cookie" >> "$LOG_FILE"
            [ -n "$location" ] && echo "  Location: $location" >> "$LOG_FILE"
        fi
    fi
done &

# Also monitor network connections in real-time
while true; do
    sleep 30
    echo "" >> "$LOG_FILE"
    echo "=== NETWORK CONNECTIONS STATUS ===" >> "$LOG_FILE"
    echo "Timestamp: $(date)" >> "$LOG_FILE"
    netstat -tulpn 2>/dev/null | grep -E ":(80|5556|8080)" >> "$LOG_FILE"
    echo "=================================" >> "$LOG_FILE"
done 