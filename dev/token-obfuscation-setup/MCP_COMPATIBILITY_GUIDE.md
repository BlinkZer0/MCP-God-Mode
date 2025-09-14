# MCP Compatibility Guide for Token Obfuscation

## Overview

The Token Obfuscation Tool now supports multiple AI platforms with Model Context Protocol (MCP) compatibility. This guide explains how to configure and use the tool across different AI platforms.

## Supported Platforms

### 1. Cursor
- **MCP Support**: ✅ Full
- **Auto-Detection**: ✅ Environment variables, config files
- **Configuration**: `cursor.json`
- **Endpoints**: `https://api.cursor.sh`, `https://cursor.sh`

### 2. Claude (Anthropic)
- **MCP Support**: ✅ Full
- **Auto-Detection**: ✅ Environment variables, config files
- **Configuration**: `claude.json`
- **Endpoints**: `https://api.anthropic.com`, `https://claude.ai`

### 3. GPT (OpenAI)
- **MCP Support**: ✅ Full
- **Auto-Detection**: ✅ Environment variables, config files
- **Configuration**: `gpt.json`
- **Endpoints**: `https://api.openai.com`, `https://platform.openai.com`

### 4. Codex (GitHub Copilot)
- **MCP Support**: ✅ Full
- **Auto-Detection**: ✅ Environment variables, config files
- **Configuration**: `codex.json`
- **Endpoints**: `https://api.github.com/copilot`, `https://copilot.github.com`

### 5. Co-Pilot (Microsoft)
- **MCP Support**: ✅ Full
- **Auto-Detection**: ✅ Environment variables, config files
- **Configuration**: `copilot.json`
- **Endpoints**: `https://api.bing.com/copilot`, `https://copilot.microsoft.com`

## Platform Detection

The tool automatically detects the AI platform by checking:

1. **Environment Variables**
   - Platform-specific API keys
   - Proxy settings
   - MCP configuration

2. **Configuration Files**
   - Platform-specific config files
   - MCP server configurations

3. **Process Environment**
   - User agent strings
   - Process arguments
   - MCP indicators

## Usage Examples

### Automatic Platform Detection
```bash
# Detect and configure for the current platform
token_obfuscation detect_platform

# Start proxy with auto-detection
token_obfuscation start_proxy target_platform=auto
```

### Manual Platform Selection
```bash
# Configure for specific platform
token_obfuscation configure target_platform=cursor
token_obfuscation configure target_platform=claude
token_obfuscation configure target_platform=gpt
```

### Natural Language Commands
```bash
# Platform-specific commands
"Start token obfuscation for Claude"
"Configure proxy for GPT platform"
"Detect which AI platform I'm using"
"Generate configuration for Cursor"
```

## MCP Integration

### Environment Variables
Set these environment variables for your platform:

```bash
# Cursor
export CURSOR_API_KEY="your-key"
export CURSOR_PROXY="http://localhost:8080"

# Claude
export ANTHROPIC_API_KEY="your-key"
export ANTHROPIC_PROXY="http://localhost:8080"

# GPT
export OPENAI_API_KEY="your-key"
export OPENAI_PROXY="http://localhost:8080"

# GitHub Copilot
export GITHUB_TOKEN="your-token"
export GITHUB_PROXY="http://localhost:8080"

# Microsoft Copilot
export MICROSOFT_API_KEY="your-key"
export MICROSOFT_PROXY="http://localhost:8080"
```

### Proxy Configuration
All platforms use the same proxy configuration:

```bash
export HTTPS_PROXY="http://localhost:8080"
export HTTP_PROXY="http://localhost:8080"
export NO_PROXY="localhost,127.0.0.1"
```

## Security Features

### Prompt Injection Defense
- Input validation and sanitization
- Request header verification
- Content filtering

### Tool Poisoning Prevention
- Secure tool descriptions
- Parameter validation
- Execution sandboxing

### MCP Security
- Secure communication protocols
- Authentication mechanisms
- Authorization checks

## Troubleshooting

### Platform Not Detected
1. Check environment variables are set
2. Verify config files exist
3. Ensure MCP server is running
4. Use manual platform selection

### Proxy Connection Issues
1. Verify proxy port is available
2. Check firewall settings
3. Confirm platform endpoints are accessible
4. Test with different obfuscation levels

### Token Obfuscation Not Working
1. Check obfuscation level settings
2. Verify streaming is enabled
3. Test with different content types
4. Review error logs

## Advanced Configuration

### Custom Headers
```json
{
  "custom_headers": {
    "x-custom-header": "value",
    "x-obfuscation-mode": "stealth"
  }
}
```

### Platform-Specific Settings
```json
{
  "platformSpecificConfig": {
    "platform": "claude",
    "endpoints": ["https://api.anthropic.com"],
    "api_version": "2023-06-01"
  }
}
```

## Best Practices

1. **Use Auto-Detection**: Let the tool detect your platform automatically
2. **Test Configuration**: Always test with sample content first
3. **Monitor Performance**: Check statistics and health status regularly
4. **Update Regularly**: Keep platform configurations up to date
5. **Secure Keys**: Never expose API keys in logs or configs

## Support

For platform-specific issues:
- Check platform documentation
- Review MCP compatibility matrix
- Test with minimal configuration
- Contact platform support if needed
