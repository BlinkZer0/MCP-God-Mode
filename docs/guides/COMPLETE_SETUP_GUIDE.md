# MCP God Mode - Complete Setup Guide

## 🚀 Quick Start

This guide provides complete setup instructions for MCP God Mode across all supported platforms. Choose your platform below for specific instructions.

## 📋 Prerequisites

### System Requirements
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: Minimum 2GB free space
- **Network**: Internet connection for initial setup
- **Permissions**: Administrative access (recommended)

### Software Requirements
- **Node.js**: 18.0 or higher
- **npm**: Latest version
- **Git**: Latest version
- **Package Manager**: Platform-specific (see below)

## 🚀 MCP Server Installation

### Quick Server Setup
```bash
# Clone the repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode/dev

# Install dependencies
npm install

# Build the project
npm run build
```

### Server Configuration Options

#### 1. **Server-Refactored (Recommended for Production)**
```bash
# Start the full-featured server (174 tools)
npm start
# or
node dist/server-refactored.js
```

#### 2. **Modular Server (Configurable)**
```bash
# Install minimal configuration (~10 tools)
npm run install:minimal
npm run build && node dist/server-modular.js

# Install custom configuration (select categories)
npm run install:modular -- --categories core,network,security
npm run build && node dist/server-modular.js

# Install full configuration (174 tools)
npm run install:full
npm run build && node dist/server-modular.js
```

#### 3. **Server-Minimal (Lightweight)**
```bash
# Start minimal server (15 tools)
npm run start:minimal
# or
node dist/server-minimal.js
```

### Server Architecture Comparison
- **Server-Refactored**: 174 tools, unified interface, production-ready
- **Modular Server**: 174 tools (configurable), flexible deployment options
- **Server-Minimal**: 15 tools, lightweight, resource-constrained environments

## 🪟 Windows Setup

### Method 1: Automated Installer (Recommended)
1. **Download the installer** from the releases page
2. **Run as Administrator** to avoid permission issues
3. **Follow the installation wizard**
4. **Restart your system** if prompted

### Method 2: Manual Installation
```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Clone the repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode

# Install Python dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Install Windows-specific dependencies
python -m pip install pywin32 psutil
```

### Method 3: Chocolatey Installation
```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install MCP God Mode
choco install mcp-god-mode
```

### Windows Configuration
```powershell
# Configure Windows Defender exclusions
Add-MpPreference -ExclusionPath "C:\MCP-God-Mode"

# Enable WSL2 (optional but recommended)
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

## 🐧 Linux Setup

### Ubuntu/Debian (20.04+)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Install development tools
sudo apt install -y build-essential python3-dev libffi-dev libssl-dev

# Clone repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install system packages
sudo apt install -y nmap aircrack-ng wireshark
```

### CentOS/RHEL (8+)
```bash
# Enable EPEL repository
sudo yum install -y epel-release

# Install dependencies
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3 python3-pip git curl wget

# Install additional packages
sudo yum install -y python3-devel libffi-devel openssl-devel

# Clone and setup (same as Ubuntu)
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Arch Linux
```bash
# Install dependencies
sudo pacman -S python python-pip git curl wget base-devel

# Install AUR packages
yay -S nmap aircrack-ng wireshark

# Clone and setup
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Linux Configuration
```bash
# Set up udev rules for USB devices
sudo tee /etc/udev/rules.d/99-mcp-god-mode.rules << EOF
# MCP God Mode USB device rules
SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="2838", MODE="0666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="2832", MODE="0666"
EOF

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Configure firewall (optional)
sudo ufw allow 8080/tcp
sudo ufw allow 8443/tcp
```

## 🍎 macOS Setup

### Method 1: Homebrew Installation (Recommended)
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 git curl wget

# Install additional tools
brew install nmap aircrack-ng wireshark

# Clone repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Method 2: MacPorts Installation
```bash
# Install MacPorts
# Download from https://www.macports.org/install.php

# Install dependencies
sudo port install python39 py39-pip git curl wget

# Install additional tools
sudo port install nmap aircrack-ng wireshark3

# Setup (same as Homebrew)
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode
python3.9 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### macOS Configuration
```bash
# Allow apps from identified developers
sudo spctl --master-disable

# Configure Gatekeeper (if needed)
sudo spctl --add --label 'Approved' /usr/local/bin/python3

# Set up launch agents for background services
mkdir -p ~/Library/LaunchAgents
cp launchd/mcp-god-mode.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/mcp-god-mode.plist
```

## 🤖 Android Setup

### Method 1: Termux Installation (Recommended)
```bash
# Install Termux from F-Droid or Google Play
# Open Termux and update
pkg update && pkg upgrade

# Install dependencies
pkg install python git curl wget

# Install additional tools
pkg install nmap aircrack-ng

# Clone repository
git clone https://github.com/your-username/MCP-God-Mode.git
cd MCP-God-Mode

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Method 2: ADB Installation
```bash
# Enable Developer Options on Android device
# Enable USB Debugging
# Connect device via USB

# Check connection
adb devices

# Install APK (if available)
adb install mcp-god-mode.apk

# Or push files to device
adb push MCP-God-Mode /sdcard/
adb shell
cd /sdcard/MCP-God-Mode
python3 setup.py install
```

### Method 3: Root Installation
```bash
# Requires rooted device
su

# Mount system as writable
mount -o rw,remount /system

# Install to system
cp -r MCP-God-Mode /system/app/
chmod 755 /system/app/MCP-God-Mode

# Set permissions
chown root:root /system/app/MCP-God-Mode
```

### Android Configuration
```bash
# Grant necessary permissions
# Settings > Apps > MCP God Mode > Permissions
# Enable: Storage, Camera, Microphone, Location, etc.

# Configure ADB (if using)
echo 'export PATH=$PATH:/sdcard/termux/usr/bin' >> ~/.bashrc
source ~/.bashrc

# Set up storage access
termux-setup-storage
```

## 🍎 iOS Setup

### Method 1: TestFlight (App Store)
1. **Install TestFlight** from the App Store
2. **Join the beta** for MCP God Mode
3. **Install the app** through TestFlight
4. **Grant permissions** when prompted

### Method 2: Jailbreak Installation
```bash
# Requires jailbroken device
# Install from Cydia/Sileo repositories

# Add repository
# Cydia > Sources > Edit > Add > [repository URL]

# Install package
# Search for "MCP God Mode" and install

# Configure permissions
# Settings > Privacy & Security > [feature] > MCP God Mode
```

### Method 3: Manual Deployment
```bash
# Requires Xcode and developer account
# Clone repository
git clone https://github.com/your-username/MCP-God-Mode.git

# Open in Xcode
open MCP-God-Mode.xcodeproj

# Configure signing and deployment
# Build and deploy to device
```

### iOS Configuration
```bash
# Grant app permissions
# Settings > Privacy & Security > [feature] > MCP God Mode

# Configure background app refresh
# Settings > General > Background App Refresh > MCP God Mode

# Set up file sharing (if needed)
# Settings > General > iPhone Storage > MCP God Mode > Offload App
```

## 🔧 Post-Installation Configuration

### Environment Variables
```bash
# Add to your shell profile (.bashrc, .zshrc, etc.)
export MCP_GOD_MODE_HOME="/path/to/MCP-God-Mode"
export PATH="$PATH:$MCP_GOD_MODE_HOME/bin"
export PYTHONPATH="$PYTHONPATH:$MCP_GOD_MODE_HOME/src"
```

### Configuration Files
```bash
# Create configuration directory
mkdir -p ~/.config/mcp-god-mode

# Copy default configuration
cp config/default.conf ~/.config/mcp-god-mode/config.conf

# Edit configuration
nano ~/.config/mcp-god-mode/config.conf
```

### Service Configuration
```bash
# Linux/macOS systemd/launchd
sudo cp systemd/mcp-god-mode.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable mcp-god-mode
sudo systemctl start mcp-god-mode

# Windows Service
sc create "MCP God Mode" binPath="C:\MCP-God-Mode\bin\mcp-god-mode.exe"
sc start "MCP God Mode"
```

## 🧪 Verification and Testing

### Basic Functionality Test
```bash
# Test core functionality
python3 -c "from mcp_god_mode import MCPGodMode; print('Installation successful!')"

# Test specific tools
python3 -m mcp_god_mode.tools.core.system_info
python3 -m mcp_god_mode.tools.network.network_diagnostics
```

### Tool-Specific Tests
```bash
# Test file operations
python3 -m mcp_god_mode.tools.core.file_ops --test

# Test network tools
python3 -m mcp_god_mode.tools.network.port_scanner --target localhost

# Test security tools
python3 -m mcp_god_mode.tools.security.vulnerability_scanner --target localhost
```

### Performance Testing
```bash
# Benchmark tool performance
python3 -m mcp_god_mode.benchmark --all-tools

# Test memory usage
python3 -m mcp_god_mode.benchmark --memory-test

# Test CPU usage
python3 -m mcp_god_mode.benchmark --cpu-test
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Linux/macOS
sudo chmod +x /path/to/mcp-god-mode
sudo chown $USER:$USER /path/to/mcp-god-mode

# Windows
# Run as Administrator
# Check UAC settings
```

#### Missing Dependencies
```bash
# Python packages
pip install --upgrade -r requirements.txt

# System packages
# See platform-specific installation above
```

#### Network Issues
```bash
# Check firewall settings
# Verify network permissions
# Test connectivity
ping google.com
```

#### Performance Issues
```bash
# Check system resources
htop  # Linux/macOS
taskmgr  # Windows

# Optimize configuration
# Reduce concurrent operations
# Increase timeout values
```

### Platform-Specific Issues

#### Windows Issues
- **PowerShell Execution Policy**: Fix with `Set-ExecutionPolicy`
- **Path Length Limits**: Use short paths or enable long path support
- **Antivirus Interference**: Configure exclusions

#### Linux Issues
- **Missing Libraries**: Install development packages
- **Service Failures**: Check systemd logs
- **Driver Issues**: Update kernel and drivers

#### macOS Issues
- **Gatekeeper Blocking**: Allow apps from identified developers
- **SIP Restrictions**: Disable SIP for system modifications
- **Permission Issues**: Grant appropriate permissions

#### Mobile Issues
- **ADB Connection**: Check USB debugging and authorization
- **Permission Denied**: Request appropriate permissions
- **Storage Space**: Ensure sufficient storage

## 📚 Next Steps

### Documentation
- **[Tool Documentation](tool/)** - Individual tool guides
- **[Parameter Reference](PARAMETER_REFERENCE.md)** - Complete parameter documentation
- **[Examples](examples/)** - Usage examples and tutorials

### Advanced Configuration
- **[Custom Tools](custom-tools/)** - Creating custom tools
- **[API Integration](api/)** - External service integration
- **[Performance Tuning](performance/)** - Optimization guides

### Community
- **[GitHub Issues](https://github.com/your-username/MCP-God-Mode/issues)** - Report bugs
- **[Discussions](https://github.com/your-username/MCP-God-Mode/discussions)** - Ask questions
- **[Contributing](CONTRIBUTING.md)** - Contribute to the project

---

*Last Updated: December 2024*  
*MCP God Mode v2.0 - Complete Setup Guide*