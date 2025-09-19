# 🗣️ Token Obfuscation Natural Language Interface Guide

## Overview

The Token Obfuscation Tool now includes a comprehensive natural language interface that allows you to control token obfuscation using conversational commands. This makes the tool more accessible and user-friendly.

## 🚨 **CRITICAL SETUP REQUIREMENT**

**⚠️ IMPORTANT: For token obfuscation to work, you MUST configure your AI client to use the proxy.**

### Required Proxy Configuration

**For Cursor:**
1. Open Cursor Settings (Ctrl+,)
2. Search for "proxy"  
3. Set HTTP/HTTPS proxy to: `http://localhost:8080`

**For Other Applications:**
```bash
# Windows
set HTTPS_PROXY=http://localhost:8080
set HTTP_PROXY=http://localhost:8080

# Linux/macOS  
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
```

---

## 🚀 Quick Start

### Basic Natural Language Commands

```bash
# Start the proxy
"start the proxy with moderate obfuscation"

# Check status
"check the status"

# Test obfuscation
"test obfuscation with 100 tokens"

# Stop the proxy
"stop the proxy"

# Show statistics
"show me the statistics"
```

## 📋 Supported Commands

### Proxy Management

| Natural Language Command | Action | Example |
|-------------------------|--------|---------|
| Start/Enable/Launch proxy | `start_proxy` | "start the proxy" |
| Stop/Disable/Shutdown proxy | `stop_proxy` | "stop the proxy" |
| Check/Show status | `get_status` | "check the status" |

### Configuration

| Natural Language Command | Action | Example |
|-------------------------|--------|---------|
| Configure/Setup/Settings | `configure` | "configure the settings" |
| Adjust/Modify settings | `configure` | "adjust the obfuscation level" |

### Monitoring

| Natural Language Command | Action | Example |
|-------------------------|--------|---------|
| Stats/Statistics/Usage | `get_stats` | "show me the statistics" |
| Health check | `get_health_status` | "check the health status" |
| Export logs | `export_logs` | "export the logs" |

### Testing

| Natural Language Command | Action | Example |
|-------------------------|--------|---------|
| Test/Try/Demo | `test_obfuscation` | "test obfuscation" |
| Sample/Example | `test_obfuscation` | "show me a sample" |

### Advanced Operations

| Natural Language Command | Action | Example |
|-------------------------|--------|---------|
| Generate config | `generate_cursor_config` | "generate cursor configuration" |
| Reset circuit breaker | `reset_circuit_breaker` | "reset the circuit breaker" |
| Enable fallback | `enable_fallback` | "enable fallback mode" |
| Disable fallback | `disable_fallback` | "disable fallback mode" |

## 🎯 Parameter Recognition

### Obfuscation Levels

The natural language interface recognizes these terms for obfuscation levels:

- **Minimal**: "minimal", "low"
- **Moderate**: "moderate", "medium" 
- **Aggressive**: "aggressive", "high", "maximum"
- **Stealth**: "stealth"

**Examples:**
```bash
"start the proxy with minimal obfuscation"
"configure for aggressive obfuscation"
"use stealth mode"
```

### Reduction Factors

The interface can extract percentage values:

```bash
"reduce tokens by 90%"
"cut usage by 50 percent"
"set reduction to 5%"
```

### Port Numbers

Port numbers are automatically detected:

```bash
"start the proxy on port 8080"
"use port 9090"
"run on port 3000"
```

### Test Content

Quoted text is extracted for testing:

```bash
'test obfuscation with "Hello world"'
"try with 'This is a test message'"
```

### Token Counts

Token numbers are recognized:

```bash
"test with 100 tokens"
"try 50 tokens"
"sample with 200 tokens"
```

## 🔧 Usage Examples

### Starting the Proxy

```bash
# Basic start
"start the proxy"

# With specific obfuscation level
"start the proxy with moderate obfuscation"

# With custom port
"start the proxy on port 8080"

# With specific reduction
"start the proxy with 90% reduction"
```

### Configuration

```bash
# Change obfuscation level
"configure for aggressive obfuscation"

# Adjust settings
"modify the settings to use stealth mode"

# Update configuration
"change the obfuscation level to minimal"
```

### Testing

```bash
# Basic test
"test obfuscation"

# With specific content
"test obfuscation with 'Hello world'"

# With token count
"test with 100 tokens"

# Combined
"test obfuscation with 'Hello world' using 50 tokens"
```

### Monitoring

```bash
# Check status
"check the status"
"show me the current status"
"is the proxy running?"

# Get statistics
"show me the statistics"
"display the usage metrics"
"get the performance stats"

# Health check
"check the health status"
"run a health check"
"show system health"
```

## 🛠️ Advanced Features

### Circuit Breaker Management

```bash
"reset the circuit breaker"
"clear the circuit breaker"
"fix the circuit breaker"
```

### Fallback Mode

```bash
"enable fallback mode"
"turn on fallback"
"activate fallback"

"disable fallback mode"
"turn off fallback"
"deactivate fallback"
```

### Configuration Generation

```bash
"generate cursor configuration"
"create config file"
"make cursor config"
"setup cursor configuration"
```

## 📊 Confidence Scoring

The natural language interface includes confidence scoring to help you understand how well your command was interpreted:

- **High Confidence (80-100%)**: Command was clearly understood
- **Medium Confidence (50-79%)**: Command was mostly understood
- **Low Confidence (30-49%)**: Command was partially understood
- **Very Low Confidence (<30%)**: Command was unclear

## 🔍 Error Handling

### Unclear Commands

If the system can't understand your command, it will:

1. Show a confidence score
2. Suggest alternative phrasings
3. Provide examples of valid commands

### Ambiguous Parameters

When multiple parameters could apply, the system will:

1. Use the most specific match
2. Apply default values for unclear parameters
3. Show what was detected

## 💡 Best Practices

### Clear Commands

```bash
# Good
"start the proxy with moderate obfuscation on port 8080"

# Better
"start the token obfuscation proxy with moderate obfuscation level on port 8080"
```

### Specific Parameters

```bash
# Good
"test obfuscation"

# Better
"test obfuscation with 'Hello world' using 100 tokens"
```

### Action-First Structure

```bash
# Good
"moderate obfuscation start proxy"

# Better
"start the proxy with moderate obfuscation"
```

## 🚀 Integration with MCP God Mode

The natural language interface integrates seamlessly with your MCP God Mode system:

### Using with MCP Tools

```bash
# Via MCP God Mode
mcp_mcp-god-mode_token_obfuscation --action natural_language_command --natural_language_command "start the proxy with moderate obfuscation"

# Via natural language tool
mcp_mcp-god-mode_token_obfuscation_nl --command "start the proxy with moderate obfuscation"
```

### Batch Operations

```bash
# Multiple commands
"start the proxy and show me the status"
"configure for aggressive obfuscation and test with 100 tokens"
```

## 🔧 Troubleshooting

### Common Issues

1. **Command Not Recognized**
   - Try rephrasing with action words first
   - Use more specific terminology
   - Check the supported commands list

2. **Parameters Not Detected**
   - Use clear separators (quotes for text, numbers for counts)
   - Be explicit about units (%, tokens, port)
   - Use standard terminology

3. **Low Confidence Scores**
   - Simplify the command
   - Use one action per command
   - Check spelling and grammar

### Getting Help

```bash
# Check available commands
"what can I do?"
"show me available commands"
"help me with token obfuscation"

# Get examples
"show me examples"
"give me sample commands"
```

## 📈 Future Enhancements

### Planned Features

- **Voice Commands**: Speech-to-text integration
- **Context Awareness**: Remember previous commands
- **Smart Suggestions**: AI-powered command completion
- **Multi-language Support**: Support for other languages
- **Command History**: Track and replay previous commands

### Advanced NLP

- **Intent Recognition**: Better understanding of user intent
- **Entity Extraction**: Improved parameter detection
- **Contextual Understanding**: Better handling of complex commands
- **Learning**: Adaptive improvement based on usage

---

**The natural language interface makes token obfuscation more accessible and user-friendly. Use conversational commands to control your token obfuscation system with ease!**
