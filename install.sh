#!/bin/bash

echo "🚀 MCP God Mode Installation Script"
echo "==================================="
echo

echo "📁 Checking current directory..."
if [ ! -f "start-mcp.js" ]; then
    echo "❌ Error: Please run this script from the MCP God Mode project root"
    echo "   (the folder containing start-mcp.js)"
    exit 1
fi

echo "✅ Found MCP God Mode project"
echo

echo "📦 Installing root dependencies..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install root dependencies"
    exit 1
fi

echo
echo "📦 Installing development dependencies..."
cd dev
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dev dependencies"
    cd ..
    exit 1
fi
cd ..

echo
echo "🔨 Building the project..."
cd dev
npm run build
if [ $? -ne 0 ]; then
    echo "❌ Failed to build project"
    cd ..
    exit 1
fi
cd ..

echo
echo "🔒 Setting execute permissions..."
chmod +x start-mcp.js
chmod +x dev/dist/*.js

echo
echo "🧪 Testing the installation..."
node start-mcp.js --test
if [ $? -ne 0 ]; then
    echo "❌ Installation test failed"
    exit 1
fi

echo
echo "🎉 Installation completed successfully!"
echo
echo "📋 Next steps:"
echo "   1. Copy mcp.json to your MCP client configuration"
echo "   2. Set the working directory to this project folder"
echo "   3. Restart your MCP client"
echo
echo "💡 For detailed setup instructions, see docs/SETUP_GUIDE.md"
echo
