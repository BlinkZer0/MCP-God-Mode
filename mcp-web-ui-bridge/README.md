# MCP Web UI Bridge

A Model Context Protocol (MCP) server that enables AI assistants to interact with web-based AI services through browser automation, without requiring API access. Supports desktop and mobile platforms with encrypted session persistence and macro recording capabilities.

## Features

- **Cross-Platform Support**: Windows, macOS, Linux (desktop) + Android, iOS (mobile)
- **Multiple AI Providers**: ChatGPT, Grok, Claude, Hugging Face Chat, plus custom providers
- **Session Persistence**: Encrypted storage of login sessions across restarts
- **Real-time Streaming**: Live text streaming from AI responses
- **Macro Recording**: Capture and replay user actions as portable JSON scripts
- **Provider Wizard**: Interactive setup for custom AI service providers
- **Anti-Bot Friendly**: Human-paced delays and headful browsing by default

## Quick Start

### Installation

```bash
# Clone and install dependencies
git clone <repository-url>
cd mcp-web-ui-bridge
npm install

# Install browser dependencies
npm run playwright:install
```

### Configuration

1. Copy the environment template:
```bash
cp env.example .env
```

2. Edit `.env` to configure your platform and settings:
```env
PLATFORM=desktop
PLAYWRIGHT_HEADLESS=false
ENCRYPTION_KEY=your-secure-passphrase
```

### Running the Server

```bash
# Development mode
npm run dev

# Production build
npm run build
npm start
```

## Usage

### Basic Chat with AI Services

```typescript
// Chat with ChatGPT
{
  "tool": "web_ui_chat",
  "arguments": {
    "provider": "chatgpt",
    "prompt": "Hello, how are you today?",
    "timeoutMs": 60000
  }
}

// Chat with Claude
{
  "tool": "web_ui_chat", 
  "arguments": {
    "provider": "claude",
    "prompt": "Explain quantum computing in simple terms",
    "variables": {
      "model": "claude-3-sonnet"
    }
  }
}
```

### List Available Providers

```typescript
{
  "tool": "providers_list",
  "arguments": {
    "platform": "desktop"
  }
}
```

### Set Up Custom Provider

```typescript
{
  "tool": "provider_wizard",
  "arguments": {
    "startUrl": "https://your-ai-service.com/chat",
    "providerName": "My Custom AI",
    "platform": "desktop"
  }
}
```

### Record and Replay Macros

```typescript
// Record a macro
{
  "tool": "macro_record",
  "arguments": {
    "target": {
      "provider": "chatgpt"
    },
    "scope": "dom",
    "name": "ChatGPT Login Flow"
  }
}

// Run a macro
{
  "tool": "macro_run",
  "arguments": {
    "macroId": "macro_1234567890_abc123",
    "variables": {
      "username": "myuser",
      "password": "mypass"
    },
    "dryRun": false
  }
}
```

## Supported Providers

### Built-in Providers

| Provider | Desktop | Android | iOS | Streaming | File Upload |
|----------|---------|---------|-----|-----------|-------------|
| ChatGPT | ✅ | ✅ | ✅ | ✅ | ✅ |
| Grok (x.ai) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Claude | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hugging Face Chat | ✅ | ✅ | ✅ | ✅ | ❌ |

### Custom Providers

Use the provider wizard to add support for any web-based AI service:

1. Run the provider wizard
2. Navigate to the AI service's chat interface
3. Click on input fields and response areas when prompted
4. Test the configuration
5. Save and use immediately

## Platform Support

### Desktop (Playwright)
- **Windows**: Chrome, Firefox, Edge
- **macOS**: Chrome, Firefox, Safari
- **Linux**: Chrome, Firefox

### Mobile (Appium)
- **Android**: Chrome browser automation
- **iOS**: Safari browser automation (simulator + real device)

## Architecture

```
src/
├── index.ts                 # MCP server entry point
├── drivers/
│   ├── driver-bridge.ts    # Unified driver interface
│   ├── playwright.ts       # Desktop browser automation
│   └── appium.ts          # Mobile browser automation
├── providers/
│   └── registry.ts        # Provider configuration management
├── core/
│   ├── session.ts         # Encrypted session storage
│   ├── streaming.ts       # Real-time text streaming
│   ├── macro.ts          # Macro recording/replay system
│   └── wizard.ts         # Interactive provider setup
└── providers.json         # Provider configurations
```

## Security Features

- **Encrypted Sessions**: All session data encrypted with AES-GCM
- **OS Keychain Integration**: Automatic key management on supported platforms
- **No Credential Storage**: Never stores passwords or API keys
- **Rate Limiting**: Human-paced delays to respect service limits
- **ToS Compliance**: Respects terms of service and anti-bot measures

## Development

### Prerequisites

- Node.js 20+
- Playwright browsers
- Appium server (for mobile testing)
- Android SDK (for Android testing)
- Xcode (for iOS testing)

### Testing

```bash
# Test desktop functionality
PLATFORM=desktop npm test

# Test mobile functionality (requires Appium)
PLATFORM=android npm test
PLATFORM=ios npm test
```

### Mobile Setup

#### Android
```bash
# Start Android emulator
npm run android:emu

# Start Appium server
npm run appium:start
```

#### iOS
```bash
# Start iOS simulator
npm run ios:sim

# Start Appium server
npm run appium:start
```

## Troubleshooting

### Common Issues

1. **Browser not launching**: Ensure Playwright browsers are installed
2. **Mobile testing fails**: Verify Appium server is running and devices are connected
3. **Session not persisting**: Check encryption key configuration
4. **Selectors not working**: Use provider wizard to update selectors

### Debug Mode

```bash
DEBUG=true npm run dev
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure cross-platform compatibility
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with the terms of service of AI providers and applicable laws. The authors are not responsible for any misuse of this software.
