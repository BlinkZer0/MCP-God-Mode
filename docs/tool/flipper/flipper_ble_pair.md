# flipper_ble_pair

Pair with Bluetooth Low Energy device using Flipper Zero.

## Description

Initiates pairing with a Bluetooth Low Energy (BLE) device using the Flipper Zero's Bluetooth interface. This tool establishes a secure connection with BLE devices, allowing for data exchange and device control. Useful for connecting to BLE peripherals and testing BLE security.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `address` | string | Yes | BLE device MAC address (e.g., "AA:BB:CC:DD:EE:FF") |

## Usage Examples

### Pair with BLE Device
```javascript
flipper_ble_pair({
  session_id: "session_123",
  address: "AA:BB:CC:DD:EE:FF"
})
```

### Pair with Discovered Device
```javascript
// First scan for devices
const scanResult = flipper_ble_scan({
  session_id: "session_123",
  duration: 10
})

// Then pair with first discovered device
if (scanResult.data.devices.length > 0) {
  const device = scanResult.data.devices[0]
  flipper_ble_pair({
    session_id: "session_123",
    address: device.address
  })
}
```

### Pair with Specific Device Type
```javascript
flipper_ble_pair({
  session_id: "session_123",
  address: "11:22:33:44:55:66"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "address": "AA:BB:CC:DD:EE:FF",
    "name": "iPhone",
    "paired": true,
    "bonded": true,
    "services": [
      {
        "uuid": "180F",
        "name": "Battery Service",
        "characteristics": ["2A19"]
      },
      {
        "uuid": "180A", 
        "name": "Device Information Service",
        "characteristics": ["2A29", "2A24"]
      }
    ],
    "connection_state": "connected",
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Pairing Process

### Automatic Pairing
1. Device discovery and selection
2. Connection establishment
3. Security negotiation
4. Service discovery
5. Bonding completion

### Manual Pairing
- May require PIN entry
- Device-specific pairing procedures
- Security key exchange
- Service enumeration

## Error Handling

- **Device Not Found**: Returns error if BLE device address is not found
- **Pairing Failed**: Returns error if pairing process fails
- **Security Error**: Returns error if security negotiation fails
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if BLE pairing fails

## Use Cases

### Device Connection
- Connect to BLE peripherals
- Establish device communication
- Test BLE connectivity
- Debug BLE connections

### Security Testing
- Test BLE pairing security
- Analyze BLE authentication
- Test BLE encryption
- Evaluate BLE vulnerabilities

### Development
- Test BLE applications
- Debug BLE protocols
- Develop BLE tools
- Analyze BLE services

## Safety Notes

⚠️ **Security Warning**: BLE pairing establishes a secure connection with devices. Only pair with devices you own or have explicit permission to connect to. Unauthorized pairing may violate laws and regulations.

## Related Tools

- `flipper_ble_scan` - Scan for BLE devices
- `flipper_connect` - Establish device connection
- `flipper_info` - Get device information

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- BLE interface enabled on device
- Target BLE device in range
- BLE pairing permissions granted

## BLE Pairing Tips

### Successful Pairing
- Ensure device is in pairing mode
- Keep devices close during pairing
- Follow device-specific pairing procedures
- Check for pairing requirements (PIN, etc.)

### Troubleshooting
- Verify device address is correct
- Ensure device is discoverable
- Check for interference
- Try pairing from different distances
