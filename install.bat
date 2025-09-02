@echo off
echo 🚀 MCP God Mode Installation Script
echo ===================================
echo.

echo 📁 Checking current directory...
if not exist "start-mcp.js" (
    echo ❌ Error: Please run this script from the MCP God Mode project root
    echo    (the folder containing start-mcp.js)
    pause
    exit /b 1
)

echo ✅ Found MCP God Mode project
echo.

echo 📦 Installing root dependencies...
call npm install
if %errorlevel% neq 0 (
    echo ❌ Failed to install root dependencies
    pause
    exit /b 1
)

echo.
echo 📦 Installing development dependencies...
cd dev
call npm install
if %errorlevel% neq 0 (
    echo ❌ Failed to install dev dependencies
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo 🔨 Building the project...
cd dev
call npm run build
if %errorlevel% neq 0 (
    echo ❌ Failed to build project
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo 🧪 Testing the installation...
call node start-mcp.js --test
if %errorlevel% neq 0 (
    echo ❌ Installation test failed
    pause
    exit /b 1
)

echo.
echo 🎉 Installation completed successfully!
echo.
echo 📋 Next steps:
echo    1. Copy mcp.json to your MCP client configuration
echo    2. Set the working directory to this project folder
echo    3. Restart your MCP client
echo.
echo 💡 For detailed setup instructions, see docs/SETUP_GUIDE.md
echo.
pause
