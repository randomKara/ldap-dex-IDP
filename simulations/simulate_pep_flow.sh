#!/bin/bash
#
# PEP/OIDC Flow Simulator
#
# This script simulates a full OIDC authentication flow against the PEP,
# including handling redirects, submitting credentials, and managing cookies.
# It's designed to be called by scenario-specific test scripts.

set -e

# --- Configuration ---
# These variables are expected to be exported by the calling script.
PEP_URL="${PEP_URL:-"http://172.25.0.40:5000"}"
DEX_PROXY_URL="${DEX_PROXY_URL:-"http://172.25.0.30"}"
USERNAME="${USERNAME:-"user1"}"
PASSWORD="${PASSWORD:-"password1"}"
EXPECTED_GREETING="${EXPECTED_GREETING:-"Hello from Flask!"}"
TARGET_PATH="${TARGET_PATH:-"/"}"

COOKIE_JAR=$(mktemp)

# --- Utility Functions ---

# Function to print a formatted step in the process
step() {
  echo -e "\n\n--- $1 ---"
}

# Cleanup function to remove the cookie jar on exit
cleanup() {
  rm -f "$COOKIE_JAR"
}

# Set a trap to call the cleanup function on script exit
trap cleanup EXIT

# --- Simulation Logic ---

# 1. Initial Request to PEP
step "1. Initial Request to PEP at ${PEP_URL}${TARGET_PATH}"
echo "   - Expecting a 302 redirect to Dex."
initial_response_headers=$(curl -s -L -c "$COOKIE_JAR" -D - "${PEP_URL}${TARGET_PATH}")
auth_url=$(echo "$initial_response_headers" | grep -i 'Location:' | awk '{print $2}' | tr -d '\r')

if [ -z "$auth_url" ]; then
    echo "❌ ERROR: Did not receive a redirect URL from the PEP."
    exit 1
fi
echo "✅ SUCCESS: Redirected to Dex authentication page."
echo "   - Auth URL: ${auth_url}"

# 2. Submit Credentials to Dex
step "2. Submitting credentials (user: ${USERNAME}) to Dex"
dex_login_url=$(echo "$auth_url" | sed 's/auth?req=/auth\/local?req=/')
echo "   - Posting to: ${dex_login_url}"

# We follow redirects (-L) as Dex will redirect back to the PEP's callback URL.
# The PEP will then handle the code/token exchange and set the final session cookie.
login_response_headers=$(curl -s -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -d "login=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -D - \
  "$dex_login_url")

final_location=$(echo "$login_response_headers" | grep -i 'Location:' | awk '{print $2}' | tr -d '\r' | tail -n 1)

if [[ "$final_location" != "${PEP_URL}${TARGET_PATH}" && "$final_location" != "$TARGET_PATH" ]]; then
    echo "⚠️  WARN: Final redirection was not to the PEP's root. This might be okay."
    echo "   - Final Location: ${final_location}"
fi
echo "✅ SUCCESS: Credentials submitted and OIDC flow completed."


# 3. Access Protected Application
step "3. Accessing protected application at ${PEP_URL}${TARGET_PATH}"
echo "   - Using the session cookie provided by the PEP."

final_response=$(curl -s -b "$COOKIE_JAR" "${PEP_URL}${TARGET_PATH}")

# 4. Final Verification
step "4. Verifying final access"
if echo "$final_response" | grep -q "$EXPECTED_GREETING"; then
    echo "✅ SUCCESS: Successfully accessed the protected application!"
    echo "   - Found expected greeting: '${EXPECTED_GREETING}'"
    echo -e "\n--- Application Response ---"
    echo "$final_response"
    echo "--------------------------"
    exit 0
else
    echo "❌ FAILURE: Could not access the protected application or find expected content."
    echo "   - Did not find: '${EXPECTED_GREETING}'"
    echo -e "\n--- Application Response ---"
    echo "$final_response"
    echo "--------------------------"
    exit 1
fi 