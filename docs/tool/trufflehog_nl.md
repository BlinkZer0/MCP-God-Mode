# TruffleHog Natural Language Interface

## Overview

The TruffleHog Natural Language Interface provides an intuitive way to interact with TruffleHog secret scanning through conversational commands. It converts natural language queries into structured TruffleHog parameters, making secret scanning accessible without needing to know the exact API syntax.

## Acknowledgments

**Special thanks to the Truffle Security team** for creating and maintaining [TruffleHog](https://github.com/trufflesecurity/trufflehog) - the powerful secret scanning tool that this natural language interface makes accessible to users who prefer conversational commands over technical APIs.

This natural language interface builds upon TruffleHog's robust foundation, enabling users to leverage its 800+ secret detectors, cross-platform capabilities, and comprehensive analysis features through simple, intuitive commands.

**TruffleHog Repository:** [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)

We encourage users to star, contribute to, and support the TruffleHog project as their continued development benefits the entire security community.

## Features

- **Natural Language Processing**: Parse conversational commands
- **High Confidence Matching**: 90%+ accuracy for common patterns
- **Intelligent Parameter Extraction**: Automatically detect options from context
- **Multiple Output Formats**: Text, JSON, or summary formats
- **Example Generation**: Built-in examples for learning
- **Context Awareness**: Use additional context for better parsing

## Usage

### Basic Commands

#### Git Repository Scanning
```json
{
  "query": "Scan git repository https://github.com/example/repo for secrets"
}
```

#### Docker Image Scanning
```json
{
  "query": "Check docker image nginx:latest for API keys"
}
```

#### S3 Bucket Scanning
```json
{
  "query": "Find secrets in S3 bucket my-bucket with verified results only"
}
```

#### GitHub Organization Scanning
```json
{
  "query": "Scan GitHub organization myorg for AWS credentials including issues"
}
```

### Advanced Commands

#### Branch-Specific Scanning
```json
{
  "query": "Scan git repo https://github.com/example/repo from commit abc123 on branch main"
}
```

#### Performance Options
```json
{
  "query": "Fast scan docker image myapp:latest for verified secrets only"
}
```

#### Deep Analysis
```json
{
  "query": "Deep scan git repo https://github.com/example/repo with JSON output"
}
```

#### Credential Analysis
```json
{
  "query": "Analyze credential AKIAIOSFODNN7EXAMPLE"
}
```

## Supported Patterns

### Scan Types
- **Git**: "scan git repo", "check git repository", "find secrets in git"
- **GitHub**: "scan github org", "check github repo", "github secret scan"
- **GitLab**: "scan gitlab repo", "check gitlab", "gitlab secret scan"
- **Docker**: "scan docker image", "check container image", "docker secret scan"
- **S3**: "scan s3 bucket", "check aws s3", "s3 secret scan"
- **GCS**: "scan gcs bucket", "check google cloud storage", "gcp bucket scan"
- **Filesystem**: "scan directory", "check file", "find secrets in folder"
- **Jenkins**: "scan jenkins server", "check jenkins", "jenkins secret scan"
- **Postman**: "scan postman workspace", "check postman", "postman scan"
- **Elasticsearch**: "scan elasticsearch cluster", "check elastic", "elastic scan"

### Options Detection
- **Result Types**: "verified secrets", "unknown results", "all secrets"
- **Output Format**: "json output", "text format"
- **GitHub/GitLab**: "include issues", "include PRs", "issue comments"
- **Git**: "bare repository", "branch main", "since commit"
- **Performance**: "fast scan", "deep analysis", "concurrent scanning"
- **Verification**: "no verification", "skip verification", "don't verify"

### Detector Types
- **Cloud**: "aws secrets", "azure credentials", "gcp keys"
- **Services**: "github tokens", "slack keys", "stripe secrets"
- **Databases**: "database passwords", "db credentials"
- **General**: "api keys", "ssh keys", "jwt tokens"

## Parameters

### Required
- `query` - Natural language command for TruffleHog secret scanning

### Optional
- `context` - Additional context about the scanning target
- `outputFormat` - Preferred output format (text, json, summary)

## Output Format

### Summary Format (Default)
```
🎯 Command: Scan git repo https://github.com/example/repo for secrets
📋 Parsed as: Detected git scan for target: https://github.com/example/repo
🎲 Confidence: 95%

🔍 TruffleHog Scan Results
📊 Total Secrets Found: 3
✅ Verified Secrets: 2
❓ Unverified Secrets: 1
🏷️ Detector Types: AWS, GitHub
🎯 Target: https://github.com/example/repo

⚠️ Action Required: Review and remediate found secrets immediately!
```

### JSON Format
```json
{
  "action": "scan_git",
  "target": "https://github.com/example/repo",
  "parameters": {
    "action": "scan_git",
    "target": "https://github.com/example/repo",
    "results": "all",
    "outputFormat": "json"
  },
  "confidence": 0.95,
  "explanation": "Detected git scan for target: https://github.com/example/repo"
}
```

## Examples

### Repository Scanning
- "Scan git repository https://github.com/example/repo for secrets"
- "Check git repo /path/to/local/repo for verified secrets only"
- "Find secrets in git repository including issues and PRs"
- "Scan git repo from commit abc123 on branch main"

### Cloud Storage
- "Scan S3 bucket my-bucket for secrets"
- "Check GCS bucket my-gcs-bucket for API keys"
- "Find secrets in S3 bucket with verified results only"

### Container Scanning
- "Scan docker image nginx:latest for secrets"
- "Check docker image myapp:v1.0 for database passwords"
- "Find secrets in container image registry.example.com/myapp:latest"

### Service Scanning
- "Scan Jenkins server https://jenkins.example.com for secrets"
- "Check Postman workspace my-workspace for API keys"
- "Find secrets in Elasticsearch cluster https://elastic.example.com"

### Advanced Options
- "Deep scan git repo https://github.com/example/repo with JSON output"
- "Fast scan docker image myapp:latest for verified secrets only"
- "Scan GitHub org myorg for Stripe keys with concurrent scanning"
- "Check S3 bucket my-bucket for AWS secrets without verification"

## Confidence Scoring

The natural language processor provides confidence scores for parsed commands:

- **90-100%**: High confidence, clear pattern match
- **70-89%**: Good confidence, likely correct interpretation
- **50-69%**: Medium confidence, may need clarification
- **30-49%**: Low confidence, suggest being more specific
- **0-29%**: Very low confidence, provide examples

## Error Handling

### Low Confidence
```
❓ Unable to parse command: "do something with secrets"

🤔 Confidence: 25%

💡 Suggestion: Try being more specific about what you want to scan and where.

📚 Examples:
- "Scan git repo https://github.com/example/repo for secrets"
- "Check docker image nginx:latest for API keys"
- "Find secrets in S3 bucket my-bucket"
```

### Context Suggestions
When confidence is low, the tool provides:
- Specific examples relevant to the query
- Suggestions for improving the command
- Common patterns and formats
- Context hints for better parsing

## Integration

The natural language interface works alongside the main TruffleHog tool:

1. **Parse** natural language command
2. **Extract** parameters and options
3. **Generate** structured TruffleHog parameters
4. **Provide** ready-to-use configuration
5. **Format** results in user-friendly way

This makes TruffleHog accessible to users who prefer conversational interfaces over technical APIs.
