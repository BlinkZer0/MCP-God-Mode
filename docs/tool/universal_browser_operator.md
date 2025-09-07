# Universal Browser Operator (UBO)

## Overview

The Universal Browser Operator (UBO) is a comprehensive browser automation tool that provides advanced web interaction capabilities, AI site integration, and intelligent form handling. It serves as the foundation for web-based operations in the MCP God Mode toolkit.

## Features

### Core Capabilities
- **Multi-Engine Browser Support**: Playwright, Puppeteer, and Chrome DevTools Protocol
- **AI Site Integration**: Direct interaction with ChatGPT, Claude, Gemini, and other AI platforms
- **Advanced Form Handling**: Intelligent form detection, completion, and validation
- **CAPTCHA Defeating**: Multiple methods for solving various CAPTCHA types
- **Cross-Platform Support**: Windows, Linux, macOS, Android, and iOS compatibility

### Browser Engines
- **Playwright** (Primary): Full-featured browser automation
- **Puppeteer** (Fallback): Chrome/Chromium automation
- **Chrome DevTools Protocol** (Fallback): Direct browser control

## Tools

### 1. Web Search Tool (`mcp_mcp-god-mode_web_search`)

Universal web search across multiple search engines and specialized sites.

**Supported Search Engines:**
- Google, DuckDuckGo, Bing, Yahoo
- Reddit, Wikipedia, GitHub, Stack Overflow
- YouTube, Amazon

**Parameters:**
- `query` (string): Search query to execute
- `engine` (enum): Search engine to use
- `max_results` (number): Maximum results to return (1-100, default: 10)
- `include_snippets` (boolean): Include result snippets (default: true)
- `include_metadata` (boolean): Include additional metadata (default: false)
- `timeout` (number): Timeout in milliseconds (5000-120000, default: 30000)
- `headless` (boolean): Run browser in headless mode (default: true)

**Output:**
- `success` (boolean): Operation success status
- `results` (array): Search results with title, URL, snippet, metadata
- `search_engine` (string): Name of search engine used
- `query` (string): Original search query
- `result_count` (number): Number of results returned
- `search_url` (string): Generated search URL

### 2. AI Site Interaction Tool (`mcp_mcp-god-mode_ai_site_interaction`)

Interact with AI platforms using browser automation.

**Supported AI Sites:**
- ChatGPT (chat.openai.com)
- Claude AI (claude.ai)
- Google Gemini (gemini.google.com)
- X/Twitter (x.com)
- Custom sites with user-defined selectors

**Parameters:**
- `site` (enum): AI site to interact with
- `action` (enum): Action to perform (send_message, get_response, new_chat, login, screenshot, wait_for_element)
- `message` (string, optional): Message to send
- `custom_url` (string, optional): Custom URL for custom sites
- `custom_selectors` (object, optional): Custom CSS selectors
- `timeout` (number): Timeout in milliseconds (5000-120000, default: 30000)
- `headless` (boolean): Run browser in headless mode (default: false)

**Output:**
- `success` (boolean): Operation success status
- `result` (string): Action result or response
- `screenshot_path` (string, optional): Path to screenshot if taken
- `site` (string): Name of AI site
- `action` (string): Action performed

### 3. CAPTCHA Defeating Tool (`mcp_mcp-god-mode_captcha_defeating`)

Detect and solve various types of CAPTCHAs.

**Supported CAPTCHA Types:**
- reCAPTCHA v2 and v3
- hCaptcha
- Image CAPTCHAs
- Text CAPTCHAs
- Math CAPTCHAs
- Audio CAPTCHAs

**Parameters:**
- `url` (string): URL containing the CAPTCHA
- `captcha_type` (enum): Type of CAPTCHA (auto, recaptcha, hcaptcha, image, text)
- `method` (enum): Solving method (ocr, screenshot, automated, manual)
- `timeout` (number): Timeout in milliseconds (10000-300000, default: 60000)
- `save_screenshot` (boolean): Save CAPTCHA screenshot (default: true)

**Output:**
- `success` (boolean): Operation success status
- `captcha_type` (string): Detected CAPTCHA type
- `solution` (string): CAPTCHA solution
- `confidence` (number): Solution confidence (0-1)
- `screenshot_path` (string, optional): Path to CAPTCHA screenshot
- `method_used` (string): Method used for solving

### 4. Form Completion Tool (`mcp_mcp-god-mode_form_completion`)

Automatically complete online forms with intelligent field detection.

**Features:**
- Intelligent field mapping
- Form validation
- CAPTCHA handling
- Multi-step form support
- Field type detection

**Parameters:**
- `url` (string): URL of the form
- `form_data` (object): Form data as key-value pairs
- `captcha_handling` (enum): CAPTCHA handling strategy (auto, solve, skip, manual)
- `validation` (boolean): Validate form before submission (default: true)
- `submit_form` (boolean): Submit form after completion (default: false)
- `timeout` (number): Timeout in milliseconds (10000-300000, default: 60000)

**Output:**
- `success` (boolean): Operation success status
- `fields_filled` (number): Number of fields successfully filled
- `captcha_solved` (boolean, optional): Whether CAPTCHA was solved
- `form_submitted` (boolean, optional): Whether form was submitted
- `screenshot_path` (string, optional): Path to completion screenshot
- `validation_errors` (array, optional): List of validation errors

### 5. Browser Control Tool (`mcp_mcp-god-mode_browser_control`)

Advanced browser control with DOM manipulation and page analysis.

**Actions:**
- Navigate to URLs
- Click elements
- Type text
- Take screenshots
- Extract text and HTML
- Wait for elements
- Scroll pages
- Evaluate JavaScript

**Parameters:**
- `action` (enum): Browser action to perform
- `url` (string, optional): URL to navigate to
- `selector` (string, optional): CSS selector for element interaction
- `text` (string, optional): Text to type
- `script` (string, optional): JavaScript to evaluate
- `timeout` (number): Timeout in milliseconds (1000-120000, default: 10000)
- `headless` (boolean): Run browser in headless mode (default: false)

**Output:**
- `success` (boolean): Operation success status
- `result` (string): Action result
- `screenshot_path` (string, optional): Path to screenshot if taken
- `action` (string): Action performed

## Installation Requirements

### Browser Engines
```bash
# Playwright (Recommended)
npm install playwright
npx playwright install

# Puppeteer (Alternative)
npm install puppeteer

# Chrome/Chromium (System requirement)
# Install Chrome or Chromium browser
```

### OCR Support
```bash
# Tesseract OCR (for CAPTCHA solving)
# Ubuntu/Debian
sudo apt-get install tesseract-ocr

# macOS
brew install tesseract

# Windows
# Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

## Usage Examples

### Web Search
```javascript
// Search Google for "artificial intelligence"
const result = await webSearch({
  query: "artificial intelligence",
  engine: "google",
  max_results: 10,
  include_snippets: true
});
```

### AI Site Interaction
```javascript
// Send message to ChatGPT
const result = await aiSiteInteraction({
  site: "chat.openai.com",
  action: "send_message",
  message: "Hello, how are you?",
  headless: false
});
```

### CAPTCHA Solving
```javascript
// Solve image CAPTCHA using OCR
const result = await captchaDefeating({
  url: "https://example.com/form",
  captcha_type: "image",
  method: "ocr",
  save_screenshot: true
});
```

### Form Completion
```javascript
// Complete contact form
const result = await formCompletion({
  url: "https://example.com/contact",
  form_data: {
    name: "John Doe",
    email: "john@example.com",
    message: "Hello, this is a test message."
  },
  captcha_handling: "auto",
  submit_form: true
});
```

## Security Considerations

### CAPTCHA Solving
- Use only for legitimate testing purposes
- Respect website terms of service
- Consider legal implications in your jurisdiction
- Implement rate limiting to avoid abuse

### Form Completion
- Validate all input data
- Use secure connections (HTTPS)
- Implement proper error handling
- Respect website robots.txt and terms of service

### Browser Automation
- Use headless mode for production
- Implement proper timeouts
- Handle browser crashes gracefully
- Clean up browser instances

## Cross-Platform Support

### Windows
- Chrome/Chromium browser required
- Tesseract OCR available via installer
- PowerShell or Command Prompt support

### Linux
- Chrome/Chromium via package manager
- Tesseract OCR via apt/yum
- X11 or Wayland display support

### macOS
- Chrome/Chromium via Homebrew
- Tesseract OCR via Homebrew
- Quartz display support

### Android
- Chrome browser required
- Termux environment recommended
- Limited OCR capabilities

### iOS
- Safari WebKit support
- Limited automation capabilities
- OCR via system APIs

## Troubleshooting

### Common Issues

1. **Browser Engine Not Found**
   - Install Playwright: `npm install playwright && npx playwright install`
   - Install Puppeteer: `npm install puppeteer`
   - Install Chrome/Chromium browser

2. **OCR Not Working**
   - Install Tesseract OCR
   - Verify installation: `tesseract --version`
   - Check image format support

3. **CAPTCHA Solving Fails**
   - Try different solving methods
   - Check CAPTCHA complexity
   - Use manual solving for complex CAPTCHAs

4. **Form Completion Issues**
   - Verify form selectors
   - Check for dynamic content loading
   - Implement proper wait strategies

### Performance Optimization

1. **Use Headless Mode**
   - Faster execution
   - Lower resource usage
   - Better for automation

2. **Implement Timeouts**
   - Prevent hanging operations
   - Handle slow-loading pages
   - Set appropriate limits

3. **Browser Instance Management**
   - Reuse browser instances
   - Clean up properly
   - Monitor memory usage

## Advanced Features

### Custom Site Profiles
Define custom selectors and interaction patterns for specific websites:

```javascript
const customProfile = {
  selectors: {
    input: '#message-input',
    send: '#send-button',
    response: '.response-container'
  },
  waitFor: '#message-input',
  loginRequired: false
};
```

### Multi-Engine Search
Search across multiple engines simultaneously:

```javascript
const results = await multiEngineSearch({
  query: "machine learning",
  engines: ["google", "duckduckgo", "bing"],
  max_results_per_engine: 5
});
```

### Form Pattern Recognition
Automatically detect common form patterns:

```javascript
const patterns = await recognizeFormPatterns({
  url: "https://example.com/register",
  timeout: 30000
});
```

## Integration

The Universal Browser Operator integrates seamlessly with other MCP God Mode tools:

- **Network Tools**: For web scraping and analysis
- **Security Tools**: For penetration testing and vulnerability assessment
- **Media Tools**: For screenshot and image processing
- **Mobile Tools**: For mobile web automation

## Future Enhancements

- **AI Vision Integration**: Advanced image analysis capabilities
- **Voice Recognition**: Audio CAPTCHA solving
- **Machine Learning**: Improved form pattern recognition
- **Cloud Integration**: Distributed browser automation
- **Real-time Monitoring**: Live browser session monitoring

## Support

For issues, feature requests, or contributions:

1. Check the troubleshooting section
2. Review the documentation
3. Test with different browser engines
4. Verify cross-platform compatibility
5. Submit detailed bug reports

The Universal Browser Operator represents the cutting edge of browser automation technology, providing powerful tools for web interaction, AI integration, and intelligent form handling across all major platforms.
