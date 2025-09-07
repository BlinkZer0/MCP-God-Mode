@echo off
REM Launch Appium server for mobile testing on Windows
REM Supports both Android and iOS platforms

echo 🚀 Starting Appium server...

REM Check if Appium is installed
where appium >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Appium not found. Installing...
    npm install -g appium
    appium driver install uiautomator2
    appium driver install xcuitest
)

REM Set default port
if not defined APPIUM_PORT set APPIUM_PORT=4723

REM Check if port is already in use
netstat -an | findstr ":%APPIUM_PORT%" | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo ⚠️  Port %APPIUM_PORT% is already in use. Stopping existing Appium server...
    taskkill /f /im node.exe /fi "WINDOWTITLE eq appium*" >nul 2>nul
    timeout /t 2 >nul
)

REM Start Appium server
echo 📱 Starting Appium server on port %APPIUM_PORT%...
appium --port %APPIUM_PORT% --log-level error --session-override

echo ✅ Appium server started successfully!
echo 🔗 Server URL: http://localhost:%APPIUM_PORT%
echo 📊 Status: http://localhost:%APPIUM_PORT%/status
