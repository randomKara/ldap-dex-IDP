FROM ghcr.io/dexidp/dex:v2.37.0

# Copy configuration file
COPY config.yaml /etc/dex/config.yaml

# Expose port
EXPOSE 5556

# Start dex with the configuration
CMD ["dex", "serve", "/etc/dex/config.yaml"] 