FROM debian:bullseye-slim

# Install network analysis tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    netcat-openbsd \
    curl \
    jq \
    iproute2 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/log/sniffer /var/captures /opt/sniffer

# Copy all sniffer scripts
COPY *.sh /opt/sniffer/

# Make scripts executable
RUN chmod +x /opt/sniffer/*.sh

# Set working directory
WORKDIR /opt/sniffer

# Start the sniffer
CMD ["./start_simple.sh"] 