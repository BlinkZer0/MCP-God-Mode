#!/bin/bash
# MCP God Mode - Unix/Linux/macOS Installation Script
# Bash script for Unix-like systems

set -e  # Exit on any error

echo "🚀 MCP God Mode - Unix Installation"
echo "==================================="

# Check if Node.js is installed
echo "📋 Checking Node.js installation..."
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node --version)
    echo "✅ Node.js found: $NODE_VERSION"
    
    # Check if version is >= 18
    NODE_MAJOR=$(echo $NODE_VERSION | sed 's/v\([0-9]*\).*/\1/')
    if [ "$NODE_MAJOR" -lt 18 ]; then
        echo "❌ Node.js version 18 or higher is required. Current: $NODE_VERSION"
        echo "Please install Node.js 18+ from https://nodejs.org/"
        exit 1
    fi
else
    echo "❌ Node.js not found. Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

# Check if npm is available
echo "📋 Checking npm..."
if command -v npm >/dev/null 2>&1; then
    NPM_VERSION=$(npm --version)
    echo "✅ npm found: $NPM_VERSION"
else
    echo "❌ npm not found. Please install Node.js with npm."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
if npm install; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Copy environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📋 Creating .env file from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✅ .env file created. Please edit it if needed."
    else
        echo "⚠️ .env.example not found. You may need to create .env manually."
    fi
fi

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Edit .env file if needed (optional)"
echo "2. Run: npm run start:refactored   # Full server (135 tools)"
echo "3. Or:   npm run start:modular     # Modular server (135 tools)"
echo "4. Or:   npm run start:minimal     # Minimal server (15 tools)"
echo "5. Test: npm run smoke             # Health check"
echo ""
echo "📚 Documentation: docs/COMPLETE_SETUP_GUIDE.md"
