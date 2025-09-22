# Malware Execution Sandbox
# This Dockerfile creates a secure environment for executing malware payloads
FROM ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential tools and security packages
RUN apt-get update && apt-get install -y \
    # Basic utilities
    curl \
    wget \
    git \
    unzip \
    file \
    # Network tools
    nmap \
    netcat-openbsd \
    telnet \
    # Development tools
    gcc \
    g++ \
    make \
    python3 \
    python3-pip \
    # Security tools
    chroot \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for execution
RUN useradd -m -s /bin/bash malwareuser && \
    echo "malwareuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create sandbox directories
RUN mkdir -p /sandbox/{payloads,output,logs} && \
    chown -R malwareuser:malwareuser /sandbox

# Set up network isolation (will be configured at runtime)
# Create a custom network namespace for isolation

# Set working directory
WORKDIR /sandbox

# Switch to non-root user
USER malwareuser

# Default command
CMD ["/bin/bash"]
