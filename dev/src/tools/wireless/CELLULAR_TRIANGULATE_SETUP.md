# Cellular Triangulation Tool Setup Guide

## Overview

The cellular triangulation tool has been enhanced to support SMS-based triggering via Phone Link (Windows), Messages (macOS), and Twilio (other platforms). This guide covers setup, configuration, and testing across all supported platforms.

## Features

- **SMS Triggering**: Send SMS to remote devices to collect tower data
- **Cross-Platform SMS**: Phone Link (Windows), Messages (macOS), Twilio (fallback)
- **Local Mode**: Direct modem access for local triangulation
- **API Integration**: HTTP endpoints for tower data collection
- **Natural Language**: Parse commands like "Ping +1234567890 for location"

## Platform Support

### Windows
- **SMS Method**: Phone Link (requires paired phone)
- **Local Mode**: Windows Mobile Broadband API
- **Requirements**: Phone Link app, pywin32, paired Android/iOS device

### macOS
- **SMS Method**: Messages (requires iPhone with SMS forwarding)
- **Local Mode**: External modem support
- **Requirements**: iPhone with SMS forwarding enabled

### Linux
- **SMS Method**: Twilio (recommended) or modem-based SMS
- **Local Mode**: mmcli for USB modems
- **Requirements**: mmcli, Twilio account (for SMS)

### Android
- **SMS Method**: Telephony API via Termux
- **Local Mode**: Telephony API with root access
- **Requirements**: Termux, root access, client script

### iOS
- **SMS Method**: Limited without jailbreak
- **Local Mode**: CoreTelephony (jailbreak required)
- **Requirements**: Jailbreak for full functionality

## Installation

### 1. Python Dependencies

```bash
# Core dependencies
pip install requests pyphonecontrol

# Platform-specific dependencies
# Windows
pip install pywin32

# For Twilio SMS (optional)
pip install twilio
```

### 2. Platform Setup

#### Windows (Phone Link)
1. Install Phone Link app from Microsoft Store
2. Install Link to Windows app on your Android/iOS device
3. Pair devices via Phone Link settings
4. Test SMS sending:
   ```powershell
   $phoneLink = New-Object -ComObject PhoneLink.PhoneLink
   $phoneLink.SendSMS('+1234567890', 'Test message')
   ```

#### macOS (Messages)
1. Enable SMS forwarding on iPhone:
   - Settings > Messages > Text Message Forwarding
   - Enable forwarding to your Mac
2. Test SMS sending:
   ```bash
   osascript -e 'tell application "Messages" to send "Test" to buddy "+1234567890" of service "SMS"'
   ```

#### Linux (Twilio)
1. Create Twilio account at https://twilio.com
2. Get Account SID, Auth Token, and phone number
3. Set environment variables:
   ```bash
   export TWILIO_SID="your_account_sid"
   export TWILIO_TOKEN="your_auth_token"
   export TWILIO_NUMBER="your_twilio_number"
   ```

#### Android (Client Script)
1. Install Termux from F-Droid
2. Install Python and dependencies:
   ```bash
   pkg update && pkg upgrade
   pkg install python python-pip
   pip install requests
   ```
3. Grant root access and SMS permissions
4. Deploy client script:
   ```bash
   python cellular_triangulate_client_android.py
   ```

### 3. Server Setup

#### API Endpoints
The cellular triangulation API provides these endpoints:

- `POST /api/cellular/collect` - Receive tower data from client devices
- `GET /api/cellular/status/:token` - Check status of triangulation request
- `GET /api/cellular/towers/:token` - Get tower data for specific token
- `POST /api/cellular/ping` - Send SMS ping to target device
- `GET /api/cellular/tokens` - List active tokens (admin only)
- `GET /api/cellular/health` - Health check

#### Express Integration
```javascript
import express from 'express';
import { setupCellularTriangulateAPI } from './cellular_triangulate_api';

const app = express();
setupCellularTriangulateAPI(app);
```

#### Standalone Server
```javascript
import { createCellularTriangulateAPIApp } from './cellular_triangulate_api';

const app = createCellularTriangulateAPIApp();
app.listen(3000, () => {
  console.log('Cellular Triangulation API running on port 3000');
});
```

## Usage Examples

### 1. Local Triangulation

```python
from cellular_triangulate import CellularTriangulateTool

tool = CellularTriangulateTool()
result = tool.execute(
    modem='wwan0',
    mode='rssi',
    api_key='your_opencellid_key'
)
print(result)
```

### 2. SMS-Based Triangulation

```python
# Windows (Phone Link)
result = tool.ping_phone_number(
    phone_number='+1234567890',
    mode='rssi',
    api_key='your_opencellid_key',
    sms_method='phonelink'
)

# macOS (Messages)
result = tool.ping_phone_number(
    phone_number='+1234567890',
    mode='rssi',
    api_key='your_opencellid_key',
    sms_method='messages'
)

# Linux/Other (Twilio)
result = tool.ping_phone_number(
    phone_number='+1234567890',
    mode='rssi',
    api_key='your_opencellid_key',
    sms_method='twilio',
    twilio_sid='your_sid',
    twilio_token='your_token',
    twilio_number='your_twilio_number'
)
```

### 3. Natural Language Commands

```python
# Parse natural language commands
def handle_nl(command: str) -> dict:
    if 'ping' in command.lower() and '+' in command:
        phone = re.search(r'\+[\d]+', command).group()
        sms_method = 'phonelink' if platform.system().lower() == 'windows' else 'messages' if platform.system().lower() == 'darwin' else 'twilio'
        return {
            'phone_number': phone,
            'mode': 'rssi',
            'api_key': config['opencellid_key'],
            'sms_method': sms_method
        }
    return tool.execute(**params)
```

### 4. API Usage

```bash
# Send SMS ping
curl -X POST http://localhost:3000/api/cellular/ping \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1234567890",
    "mode": "rssi",
    "api_key": "your_opencellid_key",
    "sms_method": "auto"
  }'

# Check status
curl http://localhost:3000/api/cellular/status/abc123def456

# Get tower data
curl http://localhost:3000/api/cellular/towers/abc123def456
```

## Testing

### 1. Local Mode Testing

```bash
# Test local triangulation
python -c "
from cellular_triangulate import CellularTriangulateTool
tool = CellularTriangulateTool()
result = tool.execute(modem='wwan0', mode='rssi')
print(result)
"
```

### 2. SMS Method Testing

```bash
# Test Phone Link (Windows)
python -c "
from cellular_triangulate import CellularTriangulateTool
tool = CellularTriangulateTool()
result = tool.send_sms_phonelink('+1234567890')
print(f'Token: {result}')
"

# Test Messages (macOS)
python -c "
from cellular_triangulate import CellularTriangulateTool
tool = CellularTriangulateTool()
result = tool.send_sms_messages('+1234567890')
print(f'Token: {result}')
"
```

### 3. Client Script Testing

```bash
# On Android device
python cellular_triangulate_client_android.py
# Follow prompts to simulate SMS and test tower data collection
```

### 4. API Testing

```bash
# Test API health
curl http://localhost:3000/api/cellular/health

# Test tower data collection
curl -X POST http://localhost:3000/api/cellular/collect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "test123",
    "towers": [
      {"cid": "12345", "lac": "6789", "mcc": "310", "mnc": "410", "rssi": -70}
    ]
  }'
```

## Configuration

### Environment Variables

```bash
# MCP Server URL (for client communication)
export MCP_SERVER_URL="http://your-mcp-server:3000"

# OpenCellID API Key
export OPENCELLID_API_KEY="your_opencellid_key"

# Twilio Configuration (for Linux/fallback)
export TWILIO_SID="your_account_sid"
export TWILIO_TOKEN="your_auth_token"
export TWILIO_NUMBER="your_twilio_number"

# Admin Key (for API admin endpoints)
export ADMIN_KEY="your_admin_key"
```

### Configuration File

Create `cellular_triangulate_config.json`:

```json
{
  "server_url": "http://localhost:3000",
  "opencellid_api_key": "your_key",
  "twilio": {
    "sid": "your_sid",
    "token": "your_token",
    "number": "your_number"
  },
  "sms_methods": {
    "windows": "phonelink",
    "darwin": "messages",
    "linux": "twilio"
  },
  "timeout": 30,
  "max_towers": 3
}
```

## Troubleshooting

### Common Issues

1. **Phone Link SMS fails**
   - Ensure Phone Link app is installed and devices are paired
   - Check Windows COM permissions
   - Verify PowerShell execution policy

2. **Messages SMS fails**
   - Ensure iPhone SMS forwarding is enabled
   - Check macOS security permissions for AppleScript
   - Verify Messages app is set up correctly

3. **Twilio SMS fails**
   - Verify Twilio credentials are correct
   - Check account balance and phone number verification
   - Ensure proper formatting of phone numbers

4. **Client script issues**
   - Ensure Termux has root access
   - Check mmcli installation and permissions
   - Verify network connectivity to MCP server

5. **API endpoint issues**
   - Check server is running and accessible
   - Verify CORS settings if using web clients
   - Check token expiration (30 minutes default)

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or set environment variable
export CELLULAR_TRIANGULATE_DEBUG=1
```

### Log Files

Check these locations for logs:
- Python: Console output or configured log file
- API: Server console output
- Client: Termux console output

## Security Considerations

1. **SMS Permissions**: Only install client scripts on devices you own
2. **API Security**: Use HTTPS in production, implement proper authentication
3. **Token Management**: Tokens expire after 30 minutes, implement proper cleanup
4. **Data Privacy**: Tower data may contain sensitive location information
5. **Legal Compliance**: Ensure compliance with local regulations regarding cellular data access

## Performance Optimization

1. **Caching**: Cache tower location lookups to reduce API calls
2. **Batch Processing**: Process multiple requests efficiently
3. **Connection Pooling**: Use connection pooling for HTTP requests
4. **Token Cleanup**: Implement automatic cleanup of expired tokens
5. **Rate Limiting**: Implement rate limiting for SMS sending

## Future Enhancements

1. **Database Integration**: Replace in-memory storage with Redis/PostgreSQL
2. **Authentication**: Implement proper user authentication and authorization
3. **Webhooks**: Add webhook support for real-time notifications
4. **Analytics**: Add usage analytics and monitoring
5. **Mobile Apps**: Create native mobile apps for easier deployment
