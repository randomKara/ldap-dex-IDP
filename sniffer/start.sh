#!/bin/bash

# PEP Advanced Traffic Sniffer - Main startup script
# Captures ALL traffic on ALL interfaces with detailed analysis

set -e

# Configuration
LOG_DIR="/var/log/sniffer"
PCAP_DIR="/var/captures"
TARGET_CONTAINER="${TARGET_CONTAINER:-pep}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# Create timestamp for all files
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Define network interfaces and their purposes
declare -A INTERFACES=(
    ["eth0"]="app-network:172.25.2.40:Flask_Communication"
    ["eth1"]="backend-network:172.25.1.40:Dex_Authentication" 
    ["eth2"]="external-network:172.25.0.40:User_Requests"
    ["lo"]="loopback:127.0.0.1:Local_Communication"
)

# Create dedicated log files for each interface
MAIN_LOG="$LOG_DIR/pep_traffic_${TIMESTAMP}.log"
CORRELATION_LOG="$LOG_DIR/flow_correlation_${TIMESTAMP}.log"
SESSION_LOG="$LOG_DIR/session_tracking_${TIMESTAMP}.log"

echo "=== PEP Traffic Sniffer Started ===" | tee -a "$MAIN_LOG"
echo "Timestamp: $(date)" | tee -a "$MAIN_LOG"
echo "Target Container: $TARGET_CONTAINER" | tee -a "$MAIN_LOG"
echo "Capture Filter: $CAPTURE_FILTER" | tee -a "$MAIN_LOG"
echo "Log Level: $LOG_LEVEL" | tee -a "$MAIN_LOG"
echo "PCAP File: $PCAP_FILE" | tee -a "$MAIN_LOG"
echo "==========================================" | tee -a "$MAIN_LOG"

# Wait for network interfaces to be available
echo "Waiting for network interfaces..." | tee -a "$MAIN_LOG"
sleep 5

# Display network configuration
echo "=== Network Interfaces ===" | tee -a "$MAIN_LOG"
ip addr show | tee -a "$MAIN_LOG"
echo "=== Network Routes ===" | tee -a "$MAIN_LOG"
ip route show | tee -a "$MAIN_LOG"
echo "=========================" | tee -a "$MAIN_LOG"

# Start advanced monitoring processes
echo "Starting advanced multi-interface packet capture..." | tee -a "$MAIN_LOG"

# Array to store all process PIDs
PIDS=()

# Start interface-specific captures
for iface in "${!INTERFACES[@]}"; do
    IFS=':' read -r network ip purpose <<< "${INTERFACES[$iface]}"
    
    echo "Starting capture on $iface ($purpose)" | tee -a "$MAIN_LOG"
    
    # Per-interface PCAP capture
    IFACE_PCAP="$PCAP_DIR/${purpose,,}_${TIMESTAMP}.pcap"
    tcpdump -i "$iface" -w "$IFACE_PCAP" -U -s 0 &
    PIDS+=($!)
    echo "  $purpose PCAP: PID $!, File: $IFACE_PCAP" | tee -a "$MAIN_LOG"
    
    # Per-interface detailed analysis  
    IFACE_LOG="$LOG_DIR/${purpose,,}_${TIMESTAMP}.log"
    ./interface_monitor.sh "$iface" "$IFACE_LOG" "$purpose" &
    PIDS+=($!)
    echo "  $purpose Monitor: PID $!, Log: $IFACE_LOG" | tee -a "$MAIN_LOG"
done

# Start global analysis processes
echo "Starting global analysis processes..." | tee -a "$MAIN_LOG"

# Flow correlation engine
./flow_correlator.sh "$CORRELATION_LOG" &
PIDS+=($!)
echo "  Flow Correlator: PID $!" | tee -a "$MAIN_LOG"

# Session tracker
./session_tracker.sh "$SESSION_LOG" &
PIDS+=($!)
echo "  Session Tracker: PID $!" | tee -a "$MAIN_LOG"

# Real-time analyzer
./realtime_analyzer.sh "$MAIN_LOG" &
PIDS+=($!)
echo "  Real-time Analyzer: PID $!" | tee -a "$MAIN_LOG"

echo "All monitoring processes started: ${PIDS[*]}" | tee -a "$MAIN_LOG"

# Function to cleanup on exit
cleanup() {
    echo "Stopping all sniffer processes..." | tee -a "$MAIN_LOG"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait
    echo "All sniffer processes stopped." | tee -a "$MAIN_LOG"
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Keep the script running
wait 