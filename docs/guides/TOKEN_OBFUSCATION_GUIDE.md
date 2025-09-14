# 🔒 Token Obfuscation Tool v2.0b - Complete Integration Guide

## Overview

The Token Obfuscation Tool is a sophisticated MCP tool that prevents accurate token counting for billing while maintaining full functionality with AI services. **The tool is enabled by default and runs automatically in the background**, providing seamless token obfuscation without manual intervention. It automatically detects and supports multiple AI platforms including Cursor, Claude, GPT, Codex, Co-Pilot, and other MCP-compatible services. The tool uses advanced proxy middleware and obfuscation algorithms to intercept and modify token usage data across all supported platforms.

## ⚠️ Important Legal Notice

**This tool is for educational and research purposes only. Use responsibly and in accordance with applicable terms of service and local laws.**

## Features

- **🚀 Enabled by Default**: Automatically starts and runs in the background without manual intervention
- **🔄 Auto-Start**: Automatically detects your AI platform and starts obfuscation
- **🌐 Multi-Platform Support**: Automatically detects and works with Cursor, Claude, GPT, Codex, Co-Pilot, and other MCP-compatible AI services
- **🧠 Context-Aware**: Adapts obfuscation level based on detected platform and environment
- **⚡ Background Operation**: Runs continuously in the background with automatic monitoring
- **🔒 Advanced Obfuscation Algorithms**: Multiple levels of token manipulation
- **🌊 Proxy Middleware**: Intercepts AI service requests transparently
- **📡 Streaming Support**: Real-time response processing
- **⚙️ Configurable Levels**: From minimal to aggressive obfuscation
- **📊 Statistics Tracking**: Monitor token savings and usage
- **🖥️ Cross-Platform**: Works on Windows, macOS, and Linux
- **🔗 MCP Compatibility**: Full Model Context Protocol support
- **🛡️ Security Features**: Prompt injection defense, tool poisoning prevention, and input validation

## Default Behavior

**The token obfuscation tool is enabled by default and runs automatically in the background.** When you start MCP God Mode, the tool will:

1. **Auto-detect your AI platform** (Cursor, Claude, GPT, etc.)
2. **Auto-start the proxy** on port 8080
3. **Begin obfuscating tokens** in the background
4. **Monitor for platform changes** and adapt accordingly
5. **Provide context-aware obfuscation** based on your environment

### Check Default Status

```bash
# Check if obfuscation is running by default
mcp_mcp-god-mode_token_obfuscation --action check_default_status
```

## Quick Start

### 1. Verify Auto-Detection

```bash
# Check what platform was detected
mcp_mcp-god-mode_token_obfuscation --action detect_platform

# List all supported platforms
mcp_mcp-god-mode_token_obfuscation --action list_platforms
```

### 2. Start the Token Obfuscation Proxy

```bash
# Using MCP God Mode with auto-detection
mcp_mcp-god-mode_token_obfuscation --action start_proxy --proxy_port 8080 --target_platform auto

# Or specify a platform manually
mcp_mcp-god-mode_token_obfuscation --action start_proxy --proxy_port 8080 --target_platform cursor
```

### 3. Configure Your AI Platform

#### Option A: Environment Variables (Recommended)
```bash
# Windows (PowerShell)
$env:HTTPS_PROXY = "http://localhost:8080"
$env:HTTP_PROXY = "http://localhost:8080"

# Windows (Command Prompt)
set HTTPS_PROXY=http://localhost:8080
set HTTP_PROXY=http://localhost:8080

# macOS/Linux
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
```

#### Platform-Specific Configuration

**Cursor:**
```bash
export CURSOR_PROXY=http://localhost:8080
```

**Claude (Anthropic):**
```bash
export ANTHROPIC_PROXY=http://localhost:8080
```

**GPT (OpenAI):**
```bash
export OPENAI_PROXY=http://localhost:8080
```

**GitHub Copilot:**
```bash
export GITHUB_PROXY=http://localhost:8080
```

**Microsoft Copilot:**
```bash
export MICROSOFT_PROXY=http://localhost:8080
```

#### Option B: Platform Configuration Files

**Cursor:**
- Windows: `%APPDATA%\Cursor\config.json`
- macOS: `~/Library/Application Support/Cursor/config.json`
- Linux: `~/.config/Cursor/config.json`

**Claude (Anthropic):**
- All platforms: `~/.anthropic/config.json`

**GPT (OpenAI):**
- All platforms: `~/.openai/config.json`

**GitHub Copilot:**
- All platforms: `~/.github/copilot.json`

**Microsoft Copilot:**
- All platforms: `~/.microsoft/copilot.json`

```json
{
  "proxy": {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
  },
  "headers": {
    "x-target-url": "https://api.cursor.sh"
  }
}
```

## Background Mode Management

### Enable/Disable Background Mode

```bash
# Enable background mode (default behavior)
mcp_mcp-god-mode_token_obfuscation --action enable_background_mode

# Disable background mode (manual control)
mcp_mcp-god-mode_token_obfuscation --action disable_background_mode

# Check current background mode status
mcp_mcp-god-mode_token_obfuscation --action check_default_status
```

### Background Mode Features

- **Automatic Platform Detection**: Continuously monitors for platform changes
- **Health Monitoring**: Regular health checks and error recovery
- **Context-Aware Adaptation**: Adjusts obfuscation based on environment
- **Seamless Operation**: Runs without user intervention
- **Auto-Recovery**: Automatically recovers from errors and restarts

## Natural Language Commands

The tool supports natural language processing for intuitive control across all platforms:

```bash
# Platform detection
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "detect which AI platform I'm using"

# Background mode control
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "enable background mode"
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "check default status"

# Start proxy with platform-specific commands
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "start token obfuscation for Claude with moderate settings"

# Configure with natural language
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "configure aggressive obfuscation for GPT with 5% reduction"

# Generate platform-specific configuration
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "generate configuration for Cursor platform"

# Test with natural language
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "test obfuscation with 100 tokens"
```

## Configuration Options

### Context-Aware Obfuscation

The tool automatically adapts obfuscation levels based on your environment:

| Platform | Default Level | Reason |
|----------|---------------|---------|
| **Cursor** | Moderate | Balanced for development |
| **Claude** | Stealth | Professional use |
| **GPT** | Aggressive | Maximum protection |
| **Codex** | Minimal | Light for code completion |
| **Co-Pilot** | Moderate | Balanced for Microsoft services |

### Environment-Based Adaptation

- **Production**: Aggressive obfuscation
- **Development**: Minimal obfuscation  
- **Testing**: Moderate obfuscation

### Obfuscation Levels

| Level | Description | Token Reduction | Use Case |
|-------|-------------|-----------------|----------|
| `minimal` | Light obfuscation | 50% | Basic protection |
| `moderate` | Balanced approach | 80% | Recommended |
| `aggressive` | Maximum obfuscation | 95% | High protection |
| `stealth` | Undetectable changes | 90% | Stealth mode |

### Padding Strategies

- **`random`**: Random invisible character insertion
- **`pattern`**: Pattern-based padding for consistency
- **`adaptive`**: Intelligent padding based on content

### Configuration Examples

```bash
# Start with moderate obfuscation
mcp_mcp-god-mode_token_obfuscation --action start_proxy --obfuscation_level moderate --reduction_factor 0.2

# Configure for stealth mode
mcp_mcp-god-mode_token_obfuscation --action configure --obfuscation_level stealth --padding_strategy adaptive

# Test obfuscation on sample content
mcp_mcp-god-mode_token_obfuscation --action test_obfuscation --test_content "Hello world" --test_tokens 50
```

## Advanced Usage

### Custom Headers

```bash
mcp_mcp-god-mode_token_obfuscation --action configure --custom_headers '{"x-custom-header": "value"}'
```

### Statistics Monitoring

```bash
# Get current statistics
mcp_mcp-god-mode_token_obfuscation --action get_stats

# Check proxy status
mcp_mcp-god-mode_token_obfuscation --action get_status
```

### Generate Cursor Configuration

```bash
# Generate configuration for Cursor
mcp_mcp-god-mode_token_obfuscation --action generate_cursor_config
```

## MCP Compatibility

### Supported Platforms

| Platform | MCP Support | Auto-Detection | Configuration |
|----------|-------------|----------------|---------------|
| Cursor | ✅ Full | ✅ Yes | `cursor.json` |
| Claude | ✅ Full | ✅ Yes | `claude.json` |
| GPT | ✅ Full | ✅ Yes | `gpt.json` |
| Codex | ✅ Full | ✅ Yes | `codex.json` |
| Co-Pilot | ✅ Full | ✅ Yes | `copilot.json` |

### MCP Security Features

- **Prompt Injection Defense**: Detects and blocks prompt injection attempts
- **Tool Poisoning Prevention**: Prevents malicious tool descriptions
- **Input Validation**: Validates all incoming requests
- **Header Verification**: Ensures proper MCP headers
- **Content Sanitization**: Removes potentially harmful content

## Troubleshooting

### Common Issues

1. **Platform Not Detected**
   - Check environment variables are set (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`)
   - Verify platform-specific config files exist
   - Use manual platform selection: `--target_platform cursor`

2. **Proxy Not Starting**
   - Check if port 8080 is available
   - Try a different port: `--proxy_port 8081`
   - Ensure no firewall blocking

3. **AI Service Not Using Proxy**
   - Verify environment variables are set
   - Check platform-specific configuration file
   - Restart AI service after configuration changes

4. **Security Validation Failed**
   - Check request headers and content
   - Verify MCP headers are present
   - Review security logs for details

5. **Functionality Issues**
   - Enable `preserve_functionality` mode
   - Reduce obfuscation level to `minimal`
   - Check error logs in statistics

### Debug Mode

```bash
# Enable verbose logging
export MCPGM_DEBUG=1
mcp_mcp-god-mode_token_obfuscation --action start_proxy
```

## Security Considerations

### Best Practices

1. **Use Moderate Settings**: Balance between protection and functionality
2. **Monitor Statistics**: Track token savings and errors
3. **Regular Updates**: Keep the tool updated
4. **Test Thoroughly**: Verify functionality before production use

### Detection Avoidance

- Use `stealth` mode for minimal detection
- Rotate obfuscation patterns
- Monitor for unusual patterns
- Implement fallback mechanisms

## API Reference

### Actions

| Action | Description | Parameters |
|--------|-------------|------------|
| `start_proxy` | Start obfuscation proxy | `proxy_port`, `obfuscation_level` |
| `stop_proxy` | Stop proxy server | None |
| `configure` | Update settings | All config options |
| `get_stats` | View statistics | None |
| `get_status` | Check proxy status | None |
| `test_obfuscation` | Test on sample content | `test_content`, `test_tokens` |
| `generate_cursor_config` | Generate Cursor config | None |

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `obfuscation_level` | enum | `moderate` | Level of obfuscation |
| `reduction_factor` | number | `0.1` | Token reduction factor |
| `padding_strategy` | enum | `adaptive` | Padding strategy |
| `proxy_port` | number | `8080` | Proxy server port |
| `enable_streaming` | boolean | `true` | Enable streaming |
| `preserve_functionality` | boolean | `true` | Preserve functionality |
| `custom_headers` | object | `{}` | Custom headers |

## Integration Examples

### Automated Setup Script

```bash
#!/bin/bash
# setup_token_obfuscation.sh

echo "🔒 Setting up Token Obfuscation..."

# Start proxy with moderate settings
mcp_mcp-god-mode_token_obfuscation --action start_proxy --obfuscation_level moderate

# Set environment variables
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080

# Generate Cursor config
mcp_mcp-god-mode_token_obfuscation --action generate_cursor_config > cursor_config.json

echo "✅ Token obfuscation setup complete!"
echo "📋 Next steps:"
echo "1. Configure Cursor with the generated config"
echo "2. Restart Cursor"
echo "3. Monitor statistics with: mcp_mcp-god-mode_token_obfuscation --action get_stats"
```

### Windows PowerShell Script

```powershell
# setup_token_obfuscation.ps1

Write-Host "🔒 Setting up Token Obfuscation..." -ForegroundColor Green

# Start proxy
mcp_mcp-god-mode_token_obfuscation --action start_proxy --obfuscation_level moderate

# Set environment variables
$env:HTTPS_PROXY = "http://localhost:8080"
$env:HTTP_PROXY = "http://localhost:8080"

# Generate config
mcp_mcp-god-mode_token_obfuscation --action generate_cursor_config | Out-File -FilePath "cursor_config.json"

Write-Host "✅ Token obfuscation setup complete!" -ForegroundColor Green
```

## Performance Optimization

### Recommended Settings

```bash
# For high-performance systems
mcp_mcp-god-mode_token_obfuscation --action configure \
  --obfuscation_level moderate \
  --reduction_factor 0.15 \
  --padding_strategy adaptive \
  --enable_streaming true

# For resource-constrained systems
mcp_mcp-god-mode_token_obfuscation --action configure \
  --obfuscation_level minimal \
  --reduction_factor 0.3 \
  --padding_strategy pattern \
  --enable_streaming false
```

## Monitoring and Analytics

### Key Metrics

- **Token Reduction**: Percentage of tokens saved
- **Request Processing**: Number of requests handled
- **Error Rate**: Failed requests and errors
- **Performance**: Response time impact

### Monitoring Commands

```bash
# Real-time monitoring
watch -n 5 'mcp_mcp-god-mode_token_obfuscation --action get_stats'

# Log analysis
tail -f /var/log/mcp-token-obfuscation.log
```

## Support and Maintenance

### Regular Maintenance

1. **Weekly**: Check statistics and error rates
2. **Monthly**: Update obfuscation patterns
3. **Quarterly**: Review and optimize settings

### Getting Help

- Check the troubleshooting section
- Review error logs
- Test with minimal settings
- Contact support with detailed logs

## Legal and Ethical Considerations

### Important Notes

- This tool is for educational purposes
- Respect terms of service
- Use responsibly and ethically
- Consider legal implications
- Monitor for policy changes

### Compliance

- Review applicable laws
- Understand service terms
- Implement appropriate safeguards
- Document usage policies
- Regular compliance reviews

---

**Remember**: This tool is designed to help understand token obfuscation techniques. Always use responsibly and in accordance with applicable laws and terms of service.
