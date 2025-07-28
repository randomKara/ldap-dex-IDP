# Automated PEP Traffic Generation & Capture Suite

This directory contains a suite of scripts to **simulate various user interaction flows** and **capture the resulting network traffic** around the Policy Enforcement Point (PEP).

The primary goal is to generate a rich dataset (`.pcap` files) for analyzing the PEP's behavior in different scenarios, rather than running pass/fail tests.

## 🚀 One-Step Capture & Simulation

To run the entire process (start services, generate traffic, capture packets, and clean up), simply execute the master orchestrator script from the project root:

```bash
./simulations/capture_and_simulate.sh
```

This script will:
1.  **Start all services**, including the `pep-sniffer`.
2.  **Wait** for the services to become stable.
3.  **Execute a series of traffic generation scenarios** to simulate realistic user activity.
4.  **Stop and remove all services** once the simulation is complete.
5.  **Display the location of the newly created `.pcap` files**, ready for your analysis.

## 🚦 Traffic Scenarios Generated

The simulation script will generate network traffic corresponding to the following user stories:

-   **SCN01: Successful Login**: A user (`user1`) successfully authenticates.
-   **SCN02: Sub-Resource Access**: An authenticated user (`user2`) navigates to a different page within the application.
-   **SCN03: Failed Login**: A user (`user1`) attempts to log in with an incorrect password.
-   **SCN04: Direct Backend Access Attempt**: A request is made directly to the internal Flask application, simulating an attempt to bypass the PEP.
-   **SCN06: Header Injection Flow**: A user (`user3`) logs in, allowing you to observe the PEP injecting user-specific headers into the backend request.

At the end of the process, you will have a comprehensive set of `.pcap` files in the `sniffer/pcap/` directory, each timestamped, allowing you to correlate the captured packets with the specific scenarios that were running.

## 🛠️ Script Architecture

-   **`capture_and_simulate.sh`**: The master orchestrator. This is the only script you need to run.
-   **`generate_all_traffic.sh`**: Called by the orchestrator. It runs through all predefined user scenarios.
-   **`simulate_pep_flow.sh`**: The core simulation engine that uses `curl` to mimic a user's browser during the OIDC login flow. 