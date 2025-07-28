#!/bin/bash

# Simple but Robust PEP Traffic Sniffer
# This version actually works and captures EVERYTHING

set -e

# Configuration
LOG_DIR="/var/log/sniffer"
PCAP_DIR="/var/captures"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Main log file
MAIN_LOG="$LOG_DIR/complete_traffic_${TIMESTAMP}.log"

echo "=== SIMPLE PEP SNIFFER STARTED ===" | tee -a "$MAIN_LOG"
echo "Timestamp: $(date)" | tee -a "$MAIN_LOG"
echo "=====================================" | tee -a "$MAIN_LOG"

# Display network configuration
echo "=== NETWORK CONFIGURATION ===" | tee -a "$MAIN_LOG"
ip addr show | tee -a "$MAIN_LOG"
echo "=============================" | tee -a "$MAIN_LOG"

# Array to store process PIDs
PIDS=()

# Function to log with timestamp
log_with_timestamp() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$MAIN_LOG"
}

# Function to monitor a specific interface
monitor_interface() {
    local interface="$1"
    local purpose="$2"
    local log_file="$LOG_DIR/${purpose,,}_${TIMESTAMP}.log"
    local pcap_file="$PCAP_DIR/${purpose,,}_${TIMESTAMP}.pcap"
    
    echo "Starting monitor for $interface ($purpose)" | tee -a "$MAIN_LOG"
    
    # Start PCAP capture
    tcpdump -i "$interface" -w "$pcap_file" -U -s 0 &
    local pcap_pid=$!
    PIDS+=($pcap_pid)
    echo "  PCAP capture PID: $pcap_pid" | tee -a "$MAIN_LOG"
    
    # Start text analysis with simpler parsing
    {
        echo "=== $purpose Traffic Monitor Started ===" >> "$log_file"
        echo "Interface: $interface" >> "$log_file"
        echo "Timestamp: $(date)" >> "$log_file"
        echo "=================================" >> "$log_file"
        
        tcpdump -i "$interface" -l -A -s 0 -nn 2>/dev/null | while read -r line; do
            timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
            
            # Simple but effective parsing
            if [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
                # New packet
                echo "[$timestamp] PACKET: $line" >> "$log_file"
                
                # Extract IPs and ports with simpler regex
                if [[ "$line" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+).*\>.*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+) ]]; then
                    src_ip="${BASH_REMATCH[1]}"
                    src_port="${BASH_REMATCH[2]}"
                    dst_ip="${BASH_REMATCH[3]}"
                    dst_port="${BASH_REMATCH[4]}"
                    echo "[$timestamp] FLOW: $src_ip:$src_port -> $dst_ip:$dst_port" >> "$log_file"
                fi
                
            elif [[ "$line" =~ ^[[:space:]]*GET[[:space:]] ]]; then
                echo "[$timestamp] HTTP_GET: $line" >> "$log_file"
            elif [[ "$line" =~ ^[[:space:]]*POST[[:space:]] ]]; then
                echo "[$timestamp] HTTP_POST: $line" >> "$log_file"
            elif [[ "$line" =~ ^[[:space:]]*HTTP/[0-9]\.[0-9][[:space:]]+[0-9]+ ]]; then
                echo "[$timestamp] HTTP_RESPONSE: $line" >> "$log_file"
            elif [[ "$line" =~ Host: ]]; then
                echo "[$timestamp] HOST_HEADER: $line" >> "$log_file"
            elif [[ "$line" =~ Cookie: ]]; then
                echo "[$timestamp] COOKIE: $line" >> "$log_file"
            elif [[ "$line" =~ Set-Cookie: ]]; then
                echo "[$timestamp] SET_COOKIE: $line" >> "$log_file"
            elif [[ "$line" =~ Authorization: ]]; then
                echo "[$timestamp] AUTH_HEADER: $line" >> "$log_file"
            elif [[ "$line" =~ oauth2callback ]]; then
                echo "[$timestamp] OAUTH_CALLBACK: $line" >> "$log_file"
            elif [[ "$line" =~ code= ]]; then
                echo "[$timestamp] AUTH_CODE: $line" >> "$log_file"
            elif [[ "$line" =~ state= ]]; then
                echo "[$timestamp] STATE_PARAM: $line" >> "$log_file"
            elif [[ -n "$line" && ! "$line" =~ ^[[:space:]]*$ ]]; then
                echo "[$timestamp] CONTENT: $line" >> "$log_file"
            fi
        done
    } &
    
    local monitor_pid=$!
    PIDS+=($monitor_pid)
    echo "  Monitor PID: $monitor_pid" | tee -a "$MAIN_LOG"
}

# Start monitoring all interfaces
monitor_interface "eth2" "External_User_Traffic"
monitor_interface "eth1" "Backend_Dex_Traffic" 
monitor_interface "eth0" "Application_Flask_Traffic"

# Start global traffic capture (all interfaces)
echo "Starting global traffic capture..." | tee -a "$MAIN_LOG"
tcpdump -i any -w "$PCAP_DIR/global_traffic_${TIMESTAMP}.pcap" -U -s 0 &
GLOBAL_PID=$!
PIDS+=($GLOBAL_PID)
echo "Global PCAP PID: $GLOBAL_PID" | tee -a "$MAIN_LOG"

# Start comprehensive text analysis
{
    echo "=== COMPREHENSIVE TRAFFIC ANALYSIS ===" >> "$MAIN_LOG"
    tcpdump -i any -l -A -s 0 2>/dev/null | while read -r line; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
        
        # Comprehensive but simple analysis
        if [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
            log_with_timestamp "PACKET: $line"
        elif [[ "$line" =~ GET[[:space:]]+/ ]]; then
            log_with_timestamp "🌐 HTTP_GET: $line"
        elif [[ "$line" =~ POST[[:space:]]+/ ]]; then
            log_with_timestamp "📤 HTTP_POST: $line"
        elif [[ "$line" =~ HTTP/[0-9]\.[0-9][[:space:]]+[0-9]+ ]]; then
            log_with_timestamp "📬 HTTP_RESPONSE: $line"
        elif [[ "$line" =~ Host:[[:space:]] ]]; then
            log_with_timestamp "🏠 HOST: $line"
        elif [[ "$line" =~ oauth2callback ]]; then
            log_with_timestamp "🔐 OAUTH_CALLBACK: $line"
        elif [[ "$line" =~ /auth.*response_type ]]; then
            log_with_timestamp "🔑 AUTH_REQUEST: $line"
        elif [[ "$line" =~ code= ]]; then
            log_with_timestamp "🎫 AUTH_CODE: $line"
        elif [[ "$line" =~ Cookie: ]]; then
            log_with_timestamp "🍪 COOKIE: $line"
        elif [[ "$line" =~ Set-Cookie: ]]; then
            log_with_timestamp "🍪 SET_COOKIE: $line"
        elif [[ "$line" =~ Authorization: ]]; then
            log_with_timestamp "🔒 AUTHORIZATION: $line"
        fi
    done
} &

ANALYSIS_PID=$!
PIDS+=($ANALYSIS_PID)
echo "Analysis PID: $ANALYSIS_PID" | tee -a "$MAIN_LOG"

echo "All processes started: ${PIDS[*]}" | tee -a "$MAIN_LOG"

# Cleanup function
cleanup() {
    echo "Stopping all processes..." | tee -a "$MAIN_LOG"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait
    echo "All processes stopped." | tee -a "$MAIN_LOG"
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Keep script running
wait 