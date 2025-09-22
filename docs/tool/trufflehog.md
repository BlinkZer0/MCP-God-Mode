# TruffleHog - Secret Scanner

## Overview

TruffleHog is a comprehensive secret scanning tool that finds, verifies, and analyzes leaked credentials across multiple sources including Git repositories, cloud storage, Docker images, and more. It supports 800+ secret detector types with live credential verification and deep analysis capabilities.

## Features

### Core Capabilities
- **Discovery**: Scan multiple sources (Git, GitHub, S3, Docker, filesystems, etc.)
- **Classification**: Detect 800+ secret types (AWS, Stripe, Cloudflare, etc.)
- **Validation**: Verify if secrets are active/live
- **Analysis**: Deep analysis of credentials and their permissions

### Supported Sources
- Git repositories (local/remote)
- GitHub/GitLab (repos, issues, PRs)
- Docker images
- S3/GCS buckets
- Filesystem (files/directories)
- Jenkins, Postman, Elasticsearch
- CI/CD platforms
- stdin input

### Key Features
- Cross-platform binary support
- JSON/text output formats
- Concurrent scanning
- Custom verification endpoints
- Entropy filtering
- Archive scanning
- Branch/commit-specific scanning

## Usage

### Basic Git Repository Scan
```json
{
  "action": "scan_git",
  "target": "https://github.com/example/repo",
  "results": "verified",
  "outputFormat": "json"
}
```

### Docker Image Scan
```json
{
  "action": "scan_docker",
  "image": "nginx:latest",
  "verification": true,
  "concurrency": 20
}
```

### S3 Bucket Scan
```json
{
  "action": "scan_s3",
  "bucket": "my-bucket",
  "results": "verified",
  "cloudEnvironment": true
}
```

### GitHub Organization Scan
```json
{
  "action": "scan_github",
  "org": "myorg",
  "includeIssues": true,
  "includePRs": true,
  "results": "all"
}
```

### Filesystem Scan
```json
{
  "action": "scan_filesystem",
  "target": "/path/to/code",
  "includePaths": ["*.js", "*.py", "*.json"],
  "excludePaths": ["node_modules/*", "*.log"]
}
```

## Parameters

### Actions
- `scan_git` - Scan Git repositories
- `scan_github` - Scan GitHub repositories/organizations
- `scan_gitlab` - Scan GitLab repositories
- `scan_docker` - Scan Docker images
- `scan_s3` - Scan S3 buckets
- `scan_gcs` - Scan Google Cloud Storage buckets
- `scan_filesystem` - Scan local files/directories
- `scan_jenkins` - Scan Jenkins servers
- `scan_postman` - Scan Postman workspaces
- `scan_elasticsearch` - Scan Elasticsearch clusters
- `scan_stdin` - Scan stdin input
- `analyze_credential` - Analyze specific credentials
- `get_detectors` - List available detectors
- `install_binary` - Install TruffleHog binary
- `check_status` - Check tool status

### Common Options
- `target` - Target to scan (URL, path, etc.)
- `results` - Result types: all, verified, unknown, unverified, filtered_unverified
- `outputFormat` - Output format: text, json, json-legacy, github-actions
- `verification` - Enable credential verification (default: true)
- `concurrency` - Number of concurrent workers
- `includeDetectors` - Detector types to include
- `excludeDetectors` - Detector types to exclude

### Git-Specific Options
- `branch` - Git branch to scan
- `sinceCommit` - Start scanning from this commit
- `maxDepth` - Maximum commit depth to scan
- `bare` - Scan bare repository

### GitHub/GitLab Options
- `org` - Organization to scan
- `repo` - Repository to scan
- `includeIssues` - Include issue comments
- `includePRs` - Include PR comments
- `token` - Authentication token

### Cloud Storage Options
- `bucket` - S3/GCS bucket name
- `projectId` - GCS project ID
- `roleArn` - IAM role ARN for S3
- `cloudEnvironment` - Use cloud environment credentials

### Path Filtering
- `includePaths` - File path patterns to include
- `excludePaths` - File path patterns to exclude
- `excludeGlobs` - Glob patterns to exclude

## Output Format

### JSON Output
```json
{
  "action": "scan_git",
  "target": "https://github.com/example/repo",
  "results": [
    {
      "sourceMetadata": {
        "data": {
          "git": {
            "commit": "abc123",
            "file": "config.js",
            "line": 42
          }
        }
      },
      "detectorName": "AWS",
      "verified": true,
      "raw": "AKIAIOSFODNN7EXAMPLE",
      "extraData": {
        "account": "123456789012",
        "arn": "arn:aws:iam::123456789012:user/example"
      }
    }
  ],
  "summary": {
    "totalResults": 1,
    "verifiedResults": 1,
    "detectorTypes": ["AWS"]
  }
}
```

## Security Considerations

- **Privileged Operation**: Requires elevated privileges for binary installation
- **Network Access**: May access external services for credential verification
- **Sensitive Data**: Handles potentially sensitive credential information
- **Binary Execution**: Downloads and executes TruffleHog binary

## Cross-Platform Support

- **Windows**: x64, ARM64
- **Linux**: x64, ARM64, 386
- **macOS**: x64, ARM64
- **Android**: Limited functionality
- **iOS**: Limited functionality

## Examples

### Comprehensive Repository Scan
```json
{
  "action": "scan_git",
  "target": "https://github.com/myorg/myrepo",
  "branch": "main",
  "sinceCommit": "HEAD~10",
  "results": "verified",
  "verification": true,
  "concurrency": 30,
  "includeDetectors": ["AWS", "GitHub", "Stripe"],
  "outputFormat": "json"
}
```

### CI/CD Integration
```json
{
  "action": "scan_git",
  "target": "file://.",
  "branch": "HEAD",
  "sinceCommit": "main",
  "results": "verified",
  "fail": true,
  "outputFormat": "github-actions"
}
```

### Multi-Image Docker Scan
```json
{
  "action": "scan_docker",
  "images": [
    "nginx:latest",
    "redis:alpine",
    "postgres:13"
  ],
  "verification": true,
  "concurrency": 10,
  "results": "all"
}
```
