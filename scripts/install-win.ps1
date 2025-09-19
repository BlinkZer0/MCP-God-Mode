# MCP God Mode - Windows Installation Script
# PowerShell script for Windows installation

Write-Host "🚀 MCP God Mode - Windows Installation" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Check if Node.js is installed
Write-Host "📋 Checking Node.js installation..." -ForegroundColor Yellow
try {
    $nodeVersion = node --version
    Write-Host "✅ Node.js found: $nodeVersion" -ForegroundColor Green
    
    # Check if version is >= 18
    $versionNumber = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
    if ($versionNumber -lt 18) {
        Write-Host "❌ Node.js version 18 or higher is required. Current: $nodeVersion" -ForegroundColor Red
        Write-Host "Please install Node.js 18+ from https://nodejs.org/" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "❌ Node.js not found. Please install Node.js 18+ from https://nodejs.org/" -ForegroundColor Red
    exit 1
}

# Check if npm is available
Write-Host "📋 Checking npm..." -ForegroundColor Yellow
try {
    $npmVersion = npm --version
    Write-Host "✅ npm found: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ npm not found. Please install Node.js with npm." -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
try {
    npm install
    Write-Host "✅ Dependencies installed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Copy environment file if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "📋 Creating .env file from template..." -ForegroundColor Yellow
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "✅ .env file created. Please edit it if needed." -ForegroundColor Green
    } else {
        Write-Host "⚠️ .env.example not found. You may need to create .env manually." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "🎉 Installation completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit .env file if needed (optional)" -ForegroundColor White
Write-Host "2. Run: npm run start:refactored   # Full server (135 tools)" -ForegroundColor White
Write-Host "3. Or:   npm run start:modular     # Modular server (135 tools)" -ForegroundColor White
Write-Host "4. Or:   npm run start:minimal     # Minimal server (15 tools)" -ForegroundColor White
Write-Host "5. Test: npm run smoke             # Health check" -ForegroundColor White
Write-Host ""
Write-Host "📚 Documentation: docs/COMPLETE_SETUP_GUIDE.md" -ForegroundColor Cyan
