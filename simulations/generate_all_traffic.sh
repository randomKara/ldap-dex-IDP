#!/bin/bash
#
# PEP Traffic Generator
#
# This script executes a series of common user interaction scenarios to generate
# realistic network traffic around the PEP for analysis. It does not perform
# pass/fail validation; its sole purpose is to stimulate the network.

# --- Configuration ---
# Uses the same environment variables as the simulation script
SIMULATION_SCRIPT="./simulations/simulate_pep_flow.sh"
FLASK_APP_IP="172.25.2.50"
FLASK_APP_PORT="8080"

# --- Utility Functions ---

# Announce which scenario is being executed
announce() {
  echo -e "\n\n================================================="
  echo "🚀 GENERATING TRAFFIC: $1"
  echo "================================================="
}

# --- Traffic Generation Scenarios ---

# Scenario 1: Successful Authentication (user1)
generate_scn01() {
  announce "SCN01: Successful Authentication (user1)"
  export USERNAME="user1"
  export PASSWORD="password1"
  export EXPECTED_GREETING="Hello, user1"
  "$SIMULATION_SCRIPT" || echo "  -> Flow for user1 completed."
}

# Scenario 2: Successful Authentication (user2) & Access Sub-Resource
generate_scn02() {
  announce "SCN02: Successful Authentication & Sub-Resource Access (user2)"
  export USERNAME="user2"
  export PASSWORD="password2"
  export EXPECTED_GREETING="Hello, user2"
  export TARGET_PATH="/other"
  "$SIMULATION_SCRIPT" || echo "  -> Flow for user2 completed."
}

# Scenario 3: Invalid Credentials
generate_scn03() {
  announce "SCN03: Invalid Credentials (user1 with wrong password)"
  export USERNAME="user1"
  export PASSWORD="wrongpassword"
  export EXPECTED_GREETING="nonexistent" # Ensure it fails to find this
  "$SIMULATION_SCRIPT" || echo "  -> Failed login flow completed."
}

# Scenario 4: Direct Access to Backend
generate_scn04() {
    announce "SCN04: Direct Backend Access Attempt"
    echo "   - Attempting to curl the internal Flask app at http://${FLASK_APP_IP}:${FLASK_APP_PORT}"
    if curl --connect-timeout 5 "http://${FLASK_APP_IP}:${FLASK_APP_PORT}"; then
        echo "  -> WARNING: Connection to internal app was unexpectedly successful."
    else
        echo "  -> Connection attempt completed (expected to fail)."
    fi
}

# Scenario 6: User Header Injection Check (user3)
generate_scn06() {
    announce "SCN06: Header Injection Flow (user3)"
    export USERNAME="user3"
    export PASSWORD="password3"
    export EXPECTED_GREETING="Email: user3@example.org"
    "$SIMULATION_SCRIPT" || echo "  -> Flow for user3 completed."
}

# --- Main Execution ---

# Modify Flask app once to display headers for relevant scenarios
echo "Modifying Flask app to return user headers for detailed analysis..."
docker compose exec flask-app bash -c '
    echo \"\"\"
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
@app.route("/other")
def index():
    user = request.headers.get("Remote-User", "Anonymous")
    email = request.headers.get("X-User-Email", "N/A")
    name = request.headers.get("X-User-Name", "N/A")
    groups = request.headers.get("X-User-Groups", "N/A")
    return f"Hello, {user}! Email: {email}, Name: {name}, Groups: {groups}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
\"\"\" > /app/app.py
'
docker compose restart flask-app
echo "Waiting for Flask app to restart..."
sleep 5

# Execute all traffic generation scenarios
generate_scn01
sleep 2
generate_scn02
sleep 2
generate_scn03
sleep 2
generate_scn04
sleep 2
generate_scn06

echo -e "\n\n================================================="
echo "✅ All traffic generation scenarios have been executed."
echo "=================================================" 