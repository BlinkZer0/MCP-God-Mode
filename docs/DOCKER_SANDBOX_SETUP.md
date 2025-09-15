# Docker Sandbox Setup Guide

## Overview

The WAN Malware Deployer tool uses Docker containers to provide secure, isolated execution environments for malware payloads. This guide explains how to set up Docker for optimal security and performance.

## 🐳 Docker Installation

### Windows
1. **Download Docker Desktop**: Visit https://www.docker.com/products/docker-desktop
2. **Install Docker Desktop**: Run the installer and follow the setup wizard
3. **Enable WSL 2**: Docker Desktop will prompt you to enable WSL 2 for better performance
4. **Restart**: Restart your computer after installation
5. **Verify Installation**: Open PowerShell and run `docker --version`

### Linux (Ubuntu/Debian)
```bash
# Update package index
sudo apt-get update

# Install Docker
sudo apt-get install docker.io

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (optional)
sudo usermod -aG docker $USER

# Verify installation
docker --version
```

### macOS
1. **Download Docker Desktop**: Visit https://www.docker.com/products/docker-desktop
2. **Install Docker Desktop**: Drag to Applications folder
3. **Start Docker Desktop**: Launch from Applications
4. **Verify Installation**: Open Terminal and run `docker --version`

## 🔒 Security Configuration

### Docker Security Settings
The malware sandbox uses the following security configurations:

```yaml
# docker-compose.yml security settings
security_opt:
  - no-new-privileges:true
  - seccomp:unconfined

# Resource limits
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M

# Network isolation
network_mode: "none"

# Read-only filesystem
read_only: true
```

### Additional Security Measures
- **No Network Access**: Containers run with `--network none`
- **Resource Limits**: CPU and memory limits prevent resource exhaustion
- **Read-Only Filesystem**: Prevents file system modifications
- **Non-Root User**: All executions run as non-privileged user
- **Automatic Cleanup**: Containers are automatically removed after execution

## 🚀 Quick Setup

### 1. Verify Docker Installation
```bash
docker --version
docker-compose --version
```

### 2. Build Sandbox Image
```bash
cd dev/dist/tools/security/docker
docker build -t mcp-malware-sandbox:latest .
```

### 3. Test Sandbox
```bash
docker run --rm mcp-malware-sandbox:latest echo "Sandbox is working!"
```

## 📁 Directory Structure

```
malware-sandbox/
├── payloads/          # Downloaded malware payloads
├── output/           # Execution results
├── logs/             # Execution logs
└── docker/
    ├── Dockerfile
    ├── docker-compose.yml
    ├── sandbox-manager.js
    └── fallback-sandbox.js
```

## 🔧 Configuration Options

### Environment Variables
```bash
# Sandbox configuration
export SANDBOX_MODE=true
export EXECUTION_TIMEOUT=300
export MAX_PAYLOAD_SIZE=52428800  # 50MB
```

### Docker Compose Override
Create `docker-compose.override.yml` for custom settings:

```yaml
version: '3.8'
services:
  malware-sandbox:
    environment:
      - EXECUTION_TIMEOUT=600  # 10 minutes
    deploy:
      resources:
        limits:
          memory: 1G  # 1GB memory limit
```

## 🛡️ Fallback Mode

If Docker is not available, the tool automatically falls back to a local sandbox with:

- **Process Isolation**: Limited resource usage
- **File System Isolation**: Temporary execution directories
- **Timeout Protection**: Automatic process termination
- **Resource Limits**: ulimit restrictions

### Fallback Features
- Automatic cleanup of temporary files
- Process resource limits (CPU, memory, files)
- Timeout-based execution termination
- Safe payload copying and execution

## 🔍 Troubleshooting

### Common Issues

#### Docker Not Found
```
Error: Docker is not available
```
**Solution**: Install Docker Desktop or Docker Engine

#### Permission Denied
```
Error: permission denied while trying to connect to Docker daemon
```
**Solution**: 
- Linux: Add user to docker group: `sudo usermod -aG docker $USER`
- Windows/macOS: Ensure Docker Desktop is running

#### Image Build Failed
```
Error: failed to build sandbox image
```
**Solution**: Check internet connection and Docker daemon status

#### Container Execution Failed
```
Error: container execution failed
```
**Solution**: Check resource limits and available disk space

### Debug Mode
Enable debug logging:
```bash
export DEBUG=wan_malware_deployer
export LOG_LEVEL=debug
```

## 📊 Performance Tuning

### Resource Optimization
```yaml
# Optimize for performance
deploy:
  resources:
    limits:
      cpus: '2.0'      # More CPU for faster execution
      memory: 1G       # More memory for complex payloads
```

### Network Configuration
```yaml
# Allow limited network access (if needed)
networks:
  malware-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 🔐 Security Best Practices

### 1. Regular Updates
- Keep Docker updated to latest version
- Regularly update base images
- Monitor security advisories

### 2. Resource Monitoring
- Monitor container resource usage
- Set appropriate limits for your environment
- Log all execution attempts

### 3. Network Security
- Use network isolation by default
- Only enable network access when necessary
- Monitor network traffic

### 4. File System Security
- Use read-only containers
- Implement proper file permissions
- Regular cleanup of temporary files

## 📈 Monitoring and Logging

### Execution Logs
All payload executions are logged with:
- Timestamp
- Payload name
- Target information
- Execution results
- Resource usage

### Log Locations
- **Docker Mode**: `/sandbox/logs/execution.log`
- **Fallback Mode**: `malware-sandbox-fallback/logs/`

### Monitoring Commands
```bash
# View running containers
docker ps

# View container logs
docker logs <container_id>

# Monitor resource usage
docker stats
```

## 🚨 Emergency Procedures

### Stop All Containers
```bash
docker stop $(docker ps -q)
```

### Clean Up Resources
```bash
# Remove all containers
docker rm $(docker ps -aq)

# Remove all images
docker rmi $(docker images -q)

# Clean up volumes
docker volume prune
```

### Reset Sandbox
```bash
# Remove sandbox directory
rm -rf malware-sandbox/

# Rebuild image
docker build -t mcp-malware-sandbox:latest .
```

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Compatibility**: Docker 20.10+, Docker Compose 2.0+
