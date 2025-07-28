# PEP Traffic Sniffer

This directory contains a comprehensive network traffic sniffing system designed to capture and analyze all traffic flowing in and out of the PEP (Policy Enforcement Point) container without affecting its behavior.

## Overview

The sniffer system captures:
- All HTTP/HTTPS traffic on ports 80, 5556, and 8080
- Complete packet-level data in PCAP format
- Structured logs with timestamps and traffic analysis
- Real-time monitoring capabilities

## Architecture

The sniffer runs as a separate container that shares the same network stack as the PEP container using `network_mode: "container:pep"`. This allows it to capture all network traffic without any configuration changes to the PEP itself.

### Components

1. **`start.sh`** - Main startup script that coordinates all sniffing activities
2. **`capture.sh`** - Real-time traffic capture with detailed logging
3. **`analyze.sh`** - HTTP traffic analysis and structured logging
4. **`analyze_logs.sh`** - Helper script for log analysis and filtering
5. **`Dockerfile`** - Container image with tcpdump, tshark, and analysis tools

## Usage

### Starting the Sniffer

The sniffer is automatically started when you run:

```bash
docker compose up -d
```

### Accessing Logs

Logs are stored in `./sniffer/logs/` and PCAP files in `./sniffer/pcap/`:

```bash
# List all log files
ls -la sniffer/logs/

# List all PCAP files
ls -la sniffer/pcap/

# View latest log in real-time
tail -f sniffer/logs/pep_traffic_*.log
```

### Log Analysis

Use the provided analysis script for various filtering options:

```bash
# Make the script executable
chmod +x sniffer/analyze_logs.sh

# Show help
./sniffer/analyze_logs.sh --help

# Show traffic summary
./sniffer/analyze_logs.sh --summary

# Monitor authentication flows in real-time
./sniffer/analyze_logs.sh --auth --live

# Show HTTP requests only
./sniffer/analyze_logs.sh --requests

# Show HTTP errors
./sniffer/analyze_logs.sh --errors

# Show OIDC/OAuth2 flows
./sniffer/analyze_logs.sh --oidc
```

## Log Formats

### Main Traffic Log

Contains timestamped entries with traffic classification:

```
[2024-01-20 14:30:45.123] HTTP_REQUEST: GET /oauth2callback?code=xyz&state=abc HTTP/1.1
[2024-01-20 14:30:45.124] HTTP_HEADER: Host: 172.25.0.40
[2024-01-20 14:30:45.125] HTTP_HEADER: Cookie: session_id=12345
```

### HTTP Analysis Log

Structured analysis of HTTP transactions:

```
=== HTTP TRANSACTION ===
Timestamp: Jan 20, 2024 14:30:45.123456789 UTC
Source: 172.25.0.1:34567
Destination: 172.25.0.40:80
REQUEST:
  Method: GET
  URI: /oauth2callback?code=xyz&state=abc
  Host: 172.25.0.40
  User-Agent: Mozilla/5.0...
RESPONSE:
  Status Code: 302
  Content-Type: text/html
  Location: http://172.25.2.50:8080/
  Set-Cookie: mod_auth_openidc_session=...
```

## Traffic Analysis Features

### Network Flow Monitoring

The sniffer captures traffic between:

1. **External → PEP** (port 80): User requests entering the system
2. **PEP → Dex** (port 5556): OIDC authentication flows
3. **PEP → Flask** (port 8080): Proxied requests to the protected application

### Captured Data

- Complete HTTP requests and responses
- Headers (including cookies, authorization, security headers)
- OIDC/OAuth2 flows (authorization codes, tokens, redirects)
- Error responses and status codes
- Network connection status

### Real-time Monitoring

The system provides real-time monitoring capabilities:

```bash
# Monitor all traffic live
docker logs -f pep-sniffer

# Monitor specific log file
tail -f sniffer/logs/pep_traffic_*.log

# Filter for authentication events
./sniffer/analyze_logs.sh --auth --live
```

## Security Considerations

- The sniffer operates in **read-only mode** and does not modify traffic
- All captured data is stored locally in the `logs/` and `pcap/` directories
- No external network access is required for the sniffer to function
- Sensitive data (passwords, tokens) may be captured - handle logs securely

## Troubleshooting

### Check Sniffer Status

```bash
# Check if sniffer is running
docker ps | grep pep-sniffer

# View sniffer logs
docker logs pep-sniffer

# Check network interfaces
docker exec pep-sniffer ip addr show
```

### Common Issues

1. **No traffic captured**: Ensure PEP is running and receiving traffic
2. **Permission denied**: Check that sniffer has privileged mode enabled
3. **Large log files**: Implement log rotation if needed for long-term monitoring

## Advanced Analysis

### PCAP Analysis

For deeper packet analysis, use the captured PCAP files:

```bash
# Analyze with Wireshark (if available)
wireshark sniffer/pcap/pep_traffic_*.pcap

# Command-line analysis with tshark
tshark -r sniffer/pcap/pep_traffic_*.pcap -Y "http" -T fields -e http.request.uri

# Extract specific protocols
tshark -r sniffer/pcap/pep_traffic_*.pcap -Y "tcp.port == 5556"
```

### Custom Filtering

Modify the capture filters in `docker-compose.yml`:

```yaml
environment:
  CAPTURE_FILTER: "port 80 or port 5556 or port 8080"  # Default
  # CAPTURE_FILTER: "host 172.25.1.20"  # Dex traffic only
  # CAPTURE_FILTER: "tcp and not port 22"  # All TCP except SSH
```

## Files Structure

```
sniffer/
├── Dockerfile              # Sniffer container image
├── start.sh                # Main startup script
├── capture.sh              # Real-time traffic capture
├── analyze.sh              # HTTP traffic analysis
├── analyze_logs.sh         # Log analysis helper
├── README.md               # This file
├── logs/                   # Generated log files
│   ├── pep_traffic_*.log   # Main traffic logs
│   └── http_requests_*.log # HTTP analysis logs
└── pcap/                   # Packet capture files
    └── pep_traffic_*.pcap  # Raw packet data
``` 