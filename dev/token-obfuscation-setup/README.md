# Token Obfuscation Setup

This directory contains the generated configuration files for token obfuscation.

## Files Generated

- `cursor-config.json` - Cursor configuration file
- `environment.env` - Environment variables
- `start-proxy.bat` - Startup script

## Setup Instructions

### 1. Configure Cursor

Copy the contents of `cursor-config.json` to your Cursor configuration file:

**Windows**: `C:\Users\Randy\AppData\Roaming\Cursor\config.json`

### 2. Set Environment Variables

Run these commands in PowerShell or Command Prompt:

```cmd
set HTTPS_PROXY=http://localhost:8080
set HTTP_PROXY=http://localhost:8080
set NO_PROXY=localhost,127.0.0.1
```

### 3. Start the Proxy

Run the startup script:

```cmd
start-proxy.bat
```

### 4. Test the Setup

1. Start Cursor
2. Make a request that would normally use tokens
3. Check the proxy logs for obfuscation activity

## Configuration

Current settings:
- Proxy Port: 8080
- Obfuscation Level: moderate
- Reduction Factor: 0.1
- Padding Strategy: adaptive

## Troubleshooting

- Ensure port 8080 is not in use
- Check firewall settings
- Verify Cursor configuration is correct
- Monitor proxy logs for errors

## Support

For issues or questions, refer to the main documentation:
`docs/guides/TOKEN_OBFUSCATION_GUIDE.md`
