#!/bin/bash

# Launch Appium server for mobile testing
# Supports both Android and iOS platforms

set -e

echo "🚀 Starting Appium server..."

# Check if Appium is installed
if ! command -v appium &> /dev/null; then
    echo "❌ Appium not found. Installing..."
    npm install -g appium
    appium driver install uiautomator2  # Android
    appium driver install xcuitest      # iOS
fi

# Set default port
APPIUM_PORT=${APPIUM_PORT:-4723}

# Check if port is already in use
if lsof -Pi :$APPIUM_PORT -sTCP:LISTEN -t >/dev/null; then
    echo "⚠️  Port $APPIUM_PORT is already in use. Stopping existing Appium server..."
    pkill -f "appium.*$APPIUM_PORT" || true
    sleep 2
fi

# Start Appium server
echo "📱 Starting Appium server on port $APPIUM_PORT..."
appium --port $APPIUM_PORT --log-level error --session-override

echo "✅ Appium server started successfully!"
echo "🔗 Server URL: http://localhost:$APPIUM_PORT"
echo "📊 Status: http://localhost:$APPIUM_PORT/status"
