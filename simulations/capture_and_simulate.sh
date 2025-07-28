#!/bin/bash
#
# Capture & Simulate Orchestrator
#
# This master script automates the entire process of:
# 1. Starting the full infrastructure, including the PEP network sniffer.
# 2. Running a traffic generation script to simulate various user scenarios.
# 3. Cleaning up all services.
# 4. Providing the user with the path to the resulting network captures.

set -e

# --- Configuration ---
TRAFFIC_GENERATOR_SCRIPT="./simulations/generate_all_traffic.sh"
CAPTURE_DIR="./sniffer/pcap"

# --- Main Logic ---

echo "================================================="
echo "🚀 Starting Capture & Simulation Session"
echo "================================================="

# 1. Start all services, including the sniffer
echo -e "\n--- 1. Starting all services (including pep-sniffer)... ---"
docker compose up -d
echo "Waiting for services to initialize..."
sleep 20 # Increased wait time to ensure all services are fully ready

# 2. Run the traffic generator
echo -e "\n--- 2. Executing traffic generation scenarios... ---"
if [ -f "$TRAFFIC_GENERATOR_SCRIPT" ]; then
    "$TRAFFIC_GENERATOR_SCRIPT"
else
    echo "❌ ERROR: Traffic generator script not found at ${TRAFFIC_GENERATOR_SCRIPT}"
    docker compose down
    exit 1
fi

echo -e "\n--- 3. Simulation complete. Shutting down services... ---"
# 3. Clean up and stop all services
docker compose down

echo -e "\n================================================="
echo "✅ Session Finished Successfully!"
echo "================================================="
echo "📂 Your network captures are located in: ${CAPTURE_DIR}"
echo "   You can now analyze the .pcap files with Wireshark or other tools."
echo ""
ls -lt "${CAPTURE_DIR}" | head -n 5 