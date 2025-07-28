#!/bin/bash
#
# PEP Test Scenario Runner
#
# This script executes a suite of automated tests against the PEP to validate
# various authentication and security scenarios.

set -e

# --- Configuration ---
SIMULATION_SCRIPT="./simulations/simulate_pep_flow.sh"
FLASK_APP_IP="172.25.2.50"
FLASK_APP_PORT="8080"
PEP_URL="http://172.25.0.40:5000"

# --- Test Framework Functions ---
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to print a consistent header for each test case
run_test() {
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  local test_name="$1"
  local command_to_run="$2"

  echo -e "\n\n================================================="
  echo "🚀 RUNNING TEST: $test_name"
  echo "================================================="

  # Execute the command and capture its exit code
  if eval "$command_to_run"; then
    echo -e "\n-------------------------------------------------"
    echo "✅ TEST PASSED: $test_name"
    echo "-------------------------------------------------"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    return 0
  else
    echo -e "\n-------------------------------------------------"
    echo "❌ TEST FAILED: $test_name"
    echo "-------------------------------------------------"
    return 1
  fi
}

# --- Test Scenarios ---

# Scenario 1: Successful Authentication (user1)
test_scn01() {
  export USERNAME="user1"
  export PASSWORD="password1"
  export EXPECTED_GREETING="Hello, user1" # Assuming Flask customizes the greeting
  "$SIMULATION_SCRIPT"
}

# Scenario 2: Successful Authentication (user2) & Access Sub-Resource
test_scn02() {
  export USERNAME="user2"
  export PASSWORD="password2"
  export EXPECTED_GREETING="Hello, user2"
  export TARGET_PATH="/other"
  "$SIMULATION_SCRIPT"
}

# Scenario 3: Invalid Credentials
test_scn03() {
  export USERNAME="user1"
  export PASSWORD="wrongpassword"
  # We expect the final grep to fail, so we invert the result with !
  ! "$SIMULATION_SCRIPT"
}

# Scenario 4: Direct Access to Backend (should fail)
test_scn04() {
    echo "Attempting to curl the internal Flask app directly..."
    if curl --connect-timeout 5 "http://${FLASK_APP_IP}:${FLASK_APP_PORT}"; then
        echo "❌ FAILURE: Unexpectedly able to connect to the internal Flask App."
        return 1
    else
        echo "✅ SUCCESS: Connection to internal Flask App timed out or was refused as expected."
        return 0
    fi
}


# --- Main Execution ---

# Ensure all services are running
echo "Starting all services for the test suite..."
docker compose up -d

echo "Waiting for services to be healthy..."
sleep 15 # Give services time to start

# Modify Flask app to display user headers for SCN06
run_test "SCN06-PREP: Modify Flask app for header verification" "
  docker compose exec flask-app bash -c '
    echo \"\"\"
from flask import Flask, request

app = Flask(__name__)

@app.route(\\\"/\")
@app.route(\\\"/other\")
def index():
    user = request.headers.get(\\\"Remote-User\\\", \\\"Anonymous\\\")
    email = request.headers.get(\\\"X-User-Email\\\", \\\"N/A\\\")
    name = request.headers.get(\\\"X-User-Name\\\", \\\"N/A\\\")
    groups = request.headers.get(\\\"X-User-Groups\\\", \\\"N/A\\\")
    return f\\\"Hello, {user}! Email: {email}, Name: {name}, Groups: {groups}\\\"

if __name__ == \\\"__main__\\\":
    app.run(host=\\\"0.0.0.0\\\", port=8080)
\"\"\" > /app/app.py
  ' && docker compose restart flask-app && sleep 5
"

# Run all test scenarios
run_test "SCN01: Successful Authentication (user1)" "test_scn01"
run_test "SCN02: Successful Authentication & Sub-Resource Access (user2)" "test_scn02"
run_test "SCN03: Invalid Credentials" "test_scn03"
run_test "SCN04: Direct Backend Access" "test_scn04"

# Scenario 6: Verify User Header Injection
run_test "SCN06: Verify User Header Injection (user3)" '
  export USERNAME="user3"
  export PASSWORD="password3"
  export EXPECTED_GREETING="Email: user3@example.org"
  "$SIMULATION_SCRIPT"
'


# --- Reporting ---
echo -e "\n\n================================================="
echo "📊 TEST SUITE COMPLETE"
echo "================================================="
echo "PASSED: ${PASSED_TESTS} / ${TOTAL_TESTS}"

# Cleanup
echo "Bringing down services..."
docker compose down

if [ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]; then
    echo "✅ All tests passed successfully!"
    exit 0
else
    echo "❌ Some tests failed."
    exit 1
fi 