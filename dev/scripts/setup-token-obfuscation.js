#!/usr/bin/env node

/**
 * Token Obfuscation Setup Script
 * Automates the setup of token obfuscation for Cursor
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔒 Token Obfuscation Setup Script');
console.log('=====================================\n');

// Configuration
const config = {
  proxyPort: 8080,
  obfuscationLevel: 'moderate',
  reductionFactor: 0.1,
  paddingStrategy: 'adaptive'
};

// Platform detection
const platform = os.platform();
const isWindows = platform === 'win32';
const isMacOS = platform === 'darwin';
const isLinux = platform === 'linux';

console.log(`📱 Detected platform: ${platform}`);

// Get Cursor config path based on platform
function getCursorConfigPath() {
  const homeDir = os.homedir();
  
  if (isWindows) {
    return path.join(homeDir, 'AppData', 'Roaming', 'Cursor', 'config.json');
  } else if (isMacOS) {
    return path.join(homeDir, 'Library', 'Application Support', 'Cursor', 'config.json');
  } else {
    return path.join(homeDir, '.config', 'Cursor', 'config.json');
  }
}

// Generate Cursor configuration
function generateCursorConfig() {
  return {
    proxy: {
      http: `http://localhost:${config.proxyPort}`,
      https: `http://localhost:${config.proxyPort}`
    },
    headers: {
      'x-target-url': 'https://api.cursor.sh',
      'x-obfuscation-enabled': 'true',
      'x-obfuscation-level': config.obfuscationLevel
    },
    timeout: {
      request: 30000,
      response: 60000
    },
    retry: {
      attempts: 3,
      delay: 1000
    },
    logging: {
      enabled: true,
      level: 'info',
      file: './logs/cursor-proxy.log'
    },
    security: {
      verifySSL: true,
      allowInsecure: false
    },
    performance: {
      connectionPooling: true,
      keepAlive: true,
      compression: true
    }
  };
}

// Generate environment variables
function generateEnvVars() {
  return {
    HTTPS_PROXY: `http://localhost:${config.proxyPort}`,
    HTTP_PROXY: `http://localhost:${config.proxyPort}`,
    NO_PROXY: 'localhost,127.0.0.1'
  };
}

// Generate startup script
function generateStartupScript() {
  if (isWindows) {
    return `@echo off
echo 🔒 Starting Token Obfuscation Proxy...

REM Set environment variables
set HTTPS_PROXY=http://localhost:${config.proxyPort}
set HTTP_PROXY=http://localhost:${config.proxyPort}

REM Start the proxy (assuming MCP God Mode is available)
echo Starting proxy on port ${config.proxyPort}...
echo Use Ctrl+C to stop the proxy

REM Add your MCP God Mode command here
REM node dev/src/server-modular.js

pause`;
  } else {
    return `#!/bin/bash
echo "🔒 Starting Token Obfuscation Proxy..."

# Set environment variables
export HTTPS_PROXY=http://localhost:${config.proxyPort}
export HTTP_PROXY=http://localhost:${config.proxyPort}

# Start the proxy (assuming MCP God Mode is available)
echo "Starting proxy on port ${config.proxyPort}..."
echo "Use Ctrl+C to stop the proxy"

# Add your MCP God Mode command here
# node dev/src/server-modular.js

read -p "Press Enter to continue..."`;
  }
}

// Main setup function
async function setup() {
  try {
    console.log('📋 Configuration:');
    console.log(`   - Proxy Port: ${config.proxyPort}`);
    console.log(`   - Obfuscation Level: ${config.obfuscationLevel}`);
    console.log(`   - Reduction Factor: ${config.reductionFactor}`);
    console.log(`   - Padding Strategy: ${config.paddingStrategy}\n`);

    // Create output directory
    const outputDir = path.join(__dirname, '..', 'token-obfuscation-setup');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Generate Cursor configuration
    const cursorConfig = generateCursorConfig();
    const cursorConfigPath = path.join(outputDir, 'cursor-config.json');
    fs.writeFileSync(cursorConfigPath, JSON.stringify(cursorConfig, null, 2));
    console.log(`✅ Generated Cursor config: ${cursorConfigPath}`);

    // Generate environment variables file
    const envVars = generateEnvVars();
    const envPath = path.join(outputDir, 'environment.env');
    const envContent = Object.entries(envVars)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
    fs.writeFileSync(envPath, envContent);
    console.log(`✅ Generated environment file: ${envPath}`);

    // Generate startup script
    const startupScript = generateStartupScript();
    const scriptExtension = isWindows ? 'bat' : 'sh';
    const scriptPath = path.join(outputDir, `start-proxy.${scriptExtension}`);
    fs.writeFileSync(scriptPath, startupScript);
    
    if (!isWindows) {
      fs.chmodSync(scriptPath, '755');
    }
    console.log(`✅ Generated startup script: ${scriptPath}`);

    // Generate README
    const readmeContent = `# Token Obfuscation Setup

This directory contains the generated configuration files for token obfuscation.

## Files Generated

- \`cursor-config.json\` - Cursor configuration file
- \`environment.env\` - Environment variables
- \`start-proxy.${scriptExtension}\` - Startup script

## Setup Instructions

### 1. Configure Cursor

Copy the contents of \`cursor-config.json\` to your Cursor configuration file:

**${isWindows ? 'Windows' : isMacOS ? 'macOS' : 'Linux'}**: \`${getCursorConfigPath()}\`

### 2. Set Environment Variables

${isWindows ? 
  'Run these commands in PowerShell or Command Prompt:' :
  'Add these to your shell profile (~/.bashrc, ~/.zshrc, etc.):'}

\`\`\`${isWindows ? 'cmd' : 'bash'}
${Object.entries(envVars).map(([key, value]) => `${isWindows ? 'set' : 'export'} ${key}=${value}`).join('\n')}
\`\`\`

### 3. Start the Proxy

Run the startup script:

\`\`\`${isWindows ? 'cmd' : 'bash'}
${isWindows ? 'start-proxy.bat' : './start-proxy.sh'}
\`\`\`

### 4. Test the Setup

1. Start Cursor
2. Make a request that would normally use tokens
3. Check the proxy logs for obfuscation activity

## Configuration

Current settings:
- Proxy Port: ${config.proxyPort}
- Obfuscation Level: ${config.obfuscationLevel}
- Reduction Factor: ${config.reductionFactor}
- Padding Strategy: ${config.paddingStrategy}

## Troubleshooting

- Ensure port ${config.proxyPort} is not in use
- Check firewall settings
- Verify Cursor configuration is correct
- Monitor proxy logs for errors

## Support

For issues or questions, refer to the main documentation:
\`docs/guides/TOKEN_OBFUSCATION_GUIDE.md\`
`;

    const readmePath = path.join(outputDir, 'README.md');
    fs.writeFileSync(readmePath, readmeContent);
    console.log(`✅ Generated README: ${readmePath}`);

    console.log('\n🎉 Setup complete!');
    console.log('\n📋 Next steps:');
    console.log('1. Copy the Cursor configuration to your Cursor config file');
    console.log('2. Set the environment variables');
    console.log('3. Start the proxy using the generated script');
    console.log('4. Restart Cursor');
    console.log('\n📁 All files are in:', outputDir);

  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    process.exit(1);
  }
}

// Run setup
setup();
