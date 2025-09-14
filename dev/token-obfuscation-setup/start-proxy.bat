@echo off
echo 🔒 Starting Token Obfuscation Proxy...

REM Set environment variables
set HTTPS_PROXY=http://localhost:8080
set HTTP_PROXY=http://localhost:8080

REM Start the proxy (assuming MCP God Mode is available)
echo Starting proxy on port 8080...
echo Use Ctrl+C to stop the proxy

REM Add your MCP God Mode command here
REM node dev/src/server-modular.js

pause