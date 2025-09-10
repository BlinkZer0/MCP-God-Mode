# Website-Based Cellular Triangulation Setup Guide

This guide explains how to set up the website-based cellular triangulation system that sends SMS messages with URLs for users to click and share their location.

## Overview

The website-based approach provides a user-friendly way to collect location data by:
1. Sending an SMS with a URL to the target device
2. User clicks the URL to open a webpage
3. Webpage requests location permission and collects GPS/tower data
4. Data is sent back to the server for triangulation

## Components

### 1. Python Implementation (`cellular_triangulate.py`)
- **GPS Mode Support**: Added `gps` mode for browser-based location collection
- **Website URLs**: SMS messages now include URLs like `http://your-mcp-server/collect?t=abc123`
- **Enhanced Triangulation**: Handles both tower data and GPS coordinates

### 2. TypeScript Implementation (`cellular_triangulate.ts`)
- **GPS Mode**: Added `gps` mode to input schema
- **GPS Data Parameter**: Added `gps_data` parameter for direct GPS input
- **Natural Language**: Defaults to GPS mode for SMS-based triggering

### 3. Webpage (`collect.html`)
- **Location Collection**: Requests GPS location via browser Geolocation API
- **Tower Data**: Attempts to use experimental Web Telephony API
- **User-Friendly**: Clean interface with privacy notices and error handling
- **Responsive**: Works on mobile and desktop browsers

### 4. API Endpoints (`cellular_triangulate_api.ts`)
- **GET /collect**: Serves the location collection webpage
- **POST /api/cellular/collect**: Receives both tower and GPS data
- **Enhanced Data Handling**: Supports both data types with proper validation

## Setup Instructions

### 1. MCP Server Setup

Add Express static file serving and the cellular triangulation API to your server:

```javascript
import express from 'express';
import { setupCellularTriangulateAPI } from './tools/wireless/cellular_triangulate_api';

const app = express();

// Serve static files (for the webpage)
app.use(express.static('public'));

// Setup cellular triangulation API
setupCellularTriangulateAPI(app);

// Start server
app.listen(3000, () => {
  console.log('MCP Server running on port 3000');
});
```

### 2. SMS Configuration

#### Windows (Phone Link)
```bash
# Install required packages
pip install pywin32

# Ensure Phone Link is set up with a paired phone
# Test SMS sending
powershell -Command "New-Object -ComObject PhoneLink.PhoneLink"
```

#### macOS (Messages)
```bash
# Enable SMS forwarding on iPhone
# Settings > Messages > Text Message Forwarding

# Test SMS sending
osascript -e 'tell application "Messages" to send "Test" to buddy "+1234567890" of service "SMS"'
```

#### Linux/Other (Twilio)
```bash
# Install Twilio
pip install twilio

# Set up Twilio credentials
export TWILIO_SID="your_sid"
export TWILIO_TOKEN="your_token"
export TWILIO_NUMBER="your_twilio_number"
```

### 3. OpenCellID API Key

```bash
# Sign up at opencellid.org
# Get your API key from my.opencellid.org/dashboard
export OPENCELLID_KEY="your_api_key"
```

### 4. Environment Variables

Create a `.env` file:

```env
# MCP Server Configuration
MCP_SERVER_URL=http://localhost:3000
MCPGM_REQUIRE_CONFIRMATION=false

# API Keys
OPENCELLID_KEY=your_opencellid_key
TWILIO_SID=your_twilio_sid
TWILIO_TOKEN=your_twilio_token
TWILIO_NUMBER=your_twilio_number

# Admin Access
ADMIN_KEY=your_admin_key
```

## Usage Examples

### 1. Website-Based SMS Triggering

```python
from cellular_triangulate import CellularTriangulateTool

tool = CellularTriangulateTool()

# Send SMS with URL for GPS location
result = tool.ping_phone_number(
    phone_number='+1234567890',
    mode='gps',  # Use GPS mode for website-based collection
    api_key='your_opencellid_key',
    sms_method='auto'  # Auto-detects platform
)

print(result)
# {'status': 'success', 'location': {'lat': 43.07, 'lon': -89.44, 'error_radius_m': 10}}
```

### 2. Natural Language Commands

```python
# Parse natural language command
params = tool.parse_nl_command("Ping +1234567890 for location")
# Returns: {'phone_number': '+1234567890', 'mode': 'gps', 'sms_method': 'phonelink'}

result = tool.execute(**params)
```

### 3. Direct GPS Data Input

```python
# Process GPS data directly
result = tool.execute(
    gps_data={
        'lat': 43.0731,
        'lon': -89.4012,
        'error_radius_m': 10
    },
    mode='gps'
)
```

## Testing

### 1. Local Testing

```bash
# Test the webpage locally
curl "http://localhost:3000/collect?t=test123"

# Test GPS data collection
curl -X POST "http://localhost:3000/api/cellular/collect?t=test123" \
  -H "Content-Type: application/json" \
  -d '[{"lat": 43.0731, "lon": -89.4012, "error_radius_m": 10}]'
```

### 2. SMS Testing

```python
# Test SMS sending (Windows)
tool = CellularTriangulateTool()
token = tool.send_sms_phonelink('+1234567890')
print(f"Token: {token}")

# Test SMS sending (macOS)
token = tool.send_sms_messages('+1234567890')
print(f"Token: {token}")

# Test SMS sending (Twilio)
token = tool.send_sms_twilio(
    '+1234567890',
    'your_sid',
    'your_token',
    'your_twilio_number'
)
print(f"Token: {token}")
```

### 3. End-to-End Testing

1. Send SMS to target device
2. Click URL on target device
3. Grant location permission
4. Verify data received on server
5. Check triangulation result

## Security Considerations

### 1. Token Security
- Tokens are randomly generated and expire after 30 minutes
- No sensitive data is stored in tokens
- Tokens are single-use for security

### 2. Data Privacy
- Location data is not stored permanently
- Users must explicitly grant location permission
- Clear privacy notices are displayed

### 3. Access Control
- Admin endpoints require authentication
- CORS is configured for cross-origin requests
- Input validation prevents malicious data

## Troubleshooting

### 1. SMS Not Sending

**Windows (Phone Link)**:
- Ensure Phone Link is installed and paired
- Check that pywin32 is installed
- Verify COM object access

**macOS (Messages)**:
- Enable SMS forwarding on iPhone
- Check AppleScript permissions
- Verify Messages app is running

**Twilio**:
- Verify credentials are correct
- Check account balance
- Ensure phone number is verified

### 2. Webpage Not Loading

- Check that the server is running on the correct port
- Verify the HTML file exists in the correct location
- Check browser console for JavaScript errors

### 3. Location Not Collected

- Ensure HTTPS is used (required for Geolocation API)
- Check browser permissions for location access
- Verify the token is valid and not expired

### 4. Data Not Received

- Check server logs for API errors
- Verify the token matches between SMS and webpage
- Ensure the API endpoint is accessible

## Advanced Configuration

### 1. Custom Webpage

You can customize the webpage by modifying `collect.html`:

```html
<!-- Add custom styling -->
<style>
  .custom-button {
    background-color: #your-color;
  }
</style>

<!-- Add custom functionality -->
<script>
  function customLocationHandler(data) {
    // Custom processing
  }
</script>
```

### 2. Custom API Endpoints

Extend the API by adding new endpoints:

```typescript
router.post('/custom-endpoint', async (req: Request, res: Response) => {
  // Custom logic
});
```

### 3. Database Integration

Replace in-memory storage with a database:

```typescript
// Replace Map with database calls
const entry = await db.towerData.findOne({ token });
await db.towerData.insertOne(entry);
```

## Performance Optimization

### 1. Caching
- Cache OpenCellID API responses
- Use Redis for token storage
- Implement request rate limiting

### 2. Monitoring
- Add logging for all API calls
- Monitor token usage and expiration
- Track success/failure rates

### 3. Scaling
- Use load balancers for multiple servers
- Implement horizontal scaling
- Add health checks and monitoring

## Legal Compliance

### 1. Privacy Laws
- Ensure compliance with GDPR, CCPA, etc.
- Implement data retention policies
- Provide clear privacy notices

### 2. Telecommunications
- Check local SMS regulations
- Ensure proper consent for location data
- Follow carrier guidelines

### 3. Data Protection
- Encrypt sensitive data in transit
- Implement secure token generation
- Regular security audits

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review server logs for errors
3. Test individual components separately
4. Verify all dependencies are installed
5. Check network connectivity and firewall settings
