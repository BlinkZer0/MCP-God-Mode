# Docker Management Tool

## Overview
The **Docker Management Tool** is a comprehensive Docker container and image management utility that provides advanced Docker operations, container management, and image handling capabilities. It offers cross-platform support and enterprise-grade Docker management features.

## Features
- **Container Management**: Advanced Docker container management and control
- **Image Management**: Comprehensive Docker image management and operations
- **Docker Operations**: Full Docker operations and container lifecycle management
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Container Monitoring**: Real-time container monitoring and status tracking
- **Image Operations**: Docker image operations and management

## Usage

### Container Management
```bash
# List containers
{
  "action": "list_containers"
}

# Start container
{
  "action": "start",
  "container_name": "web-server"
}

# Stop container
{
  "action": "stop",
  "container_name": "web-server"
}

# Create container
{
  "action": "create",
  "container_name": "new-container",
  "image_name": "nginx:latest"
}
```

### Image Management
```bash
# List images
{
  "action": "list_images"
}

# Remove image
{
  "action": "remove",
  "image_name": "old-image:latest"
}

# Pull image
{
  "action": "pull",
  "image_name": "ubuntu:20.04"
}
```

### Container Operations
```bash
# Execute command
{
  "action": "exec",
  "container_name": "web-server",
  "command": "ls -la"
}

# View logs
{
  "action": "logs",
  "container_name": "web-server"
}

# Create with ports
{
  "action": "create",
  "container_name": "web-app",
  "image_name": "nginx:latest",
  "ports": ["8080:80", "8443:443"]
}
```

## Parameters

### Container Parameters
- **action**: Docker management action to perform
- **container_name**: Name or ID of the container
- **image_name**: Name of the Docker image
- **command**: Command to execute in container
- **ports**: Port mappings (e.g., ['8080:80'])

### Image Parameters
- **image_tag**: Tag of the Docker image
- **image_repository**: Repository of the Docker image
- **image_version**: Version of the Docker image

### Operation Parameters
- **operation_type**: Type of Docker operation
- **operation_scope**: Scope of Docker operations
- **operation_timeout**: Timeout for Docker operations

## Output Format
```json
{
  "success": true,
  "action": "list_containers",
  "result": {
    "containers": [
      {
        "id": "abc123def456",
        "name": "web-server",
        "image": "nginx:latest",
        "status": "running",
        "ports": ["80:80", "443:443"]
      }
    ],
    "total_containers": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows Docker
- **Linux**: Complete functionality with Linux Docker
- **macOS**: Full feature support with macOS Docker
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: List Containers
```bash
# List containers
{
  "action": "list_containers"
}

# Result
{
  "success": true,
  "result": {
    "containers": [
      {
        "id": "abc123def456",
        "name": "web-server",
        "image": "nginx:latest",
        "status": "running"
      }
    ],
    "total_containers": 1
  }
}
```

### Example 2: Start Container
```bash
# Start container
{
  "action": "start",
  "container_name": "web-server"
}

# Result
{
  "success": true,
  "result": {
    "container_name": "web-server",
    "status": "started",
    "start_time": "2025-09-15T10:30:00Z"
  }
}
```

### Example 3: Execute Command
```bash
# Execute command
{
  "action": "exec",
  "container_name": "web-server",
  "command": "ls -la"
}

# Result
{
  "success": true,
  "result": {
    "container_name": "web-server",
    "command": "ls -la",
    "output": "total 8\ndrwxr-xr-x 1 root root 4096 Sep 15 10:30 .\ndrwxr-xr-x 1 root root 4096 Sep 15 10:30 ..",
    "exit_code": 0
  }
}
```

## Error Handling
- **Container Errors**: Proper handling of container operation failures
- **Image Errors**: Secure handling of image operation failures
- **Docker Errors**: Robust error handling for Docker daemon issues
- **Permission Errors**: Safe handling of Docker permission problems

## Related Tools
- **Container Management**: Container management and orchestration tools
- **Image Management**: Image management and registry tools
- **Docker Operations**: Docker operations and automation tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Docker Management Tool, please refer to the main MCP God Mode documentation or contact the development team.
