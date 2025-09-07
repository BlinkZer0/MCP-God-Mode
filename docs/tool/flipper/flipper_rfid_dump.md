# flipper_rfid_dump

Dump RFID card data to file on Flipper Zero device.

## Description

Reads RFID card data and saves it to a file on the Flipper Zero device's storage. This tool is useful for backing up RFID card data, analyzing card contents, and creating copies of RFID cards for authorized testing purposes.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `filename` | string | No | Optional filename to save dump (default: auto-generated) |

## Usage Examples

### Dump RFID Card with Auto-Generated Filename
```javascript
flipper_rfid_dump({
  session_id: "session_123"
})
```

### Dump RFID Card with Custom Filename
```javascript
flipper_rfid_dump({
  session_id: "session_123",
  filename: "/ext/rfid/access_card.rfid"
})
```

### Dump Multiple RFID Cards
```javascript
// First card
flipper_rfid_dump({
  session_id: "session_123",
  filename: "/ext/rfid/card1.rfid"
})

// Second card
flipper_rfid_dump({
  session_id: "session_123", 
  filename: "/ext/rfid/card2.rfid"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "filename": "/ext/rfid/access_card.rfid",
    "card_type": "EM4100",
    "uid": "1234567890",
    "protocol": "EM4100",
    "frequency": 125000,
    "data": "1234567890",
    "dump_size": 64,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **No Card Detected**: Returns error if no RFID card is present
- **Read Error**: Returns error if card cannot be read
- **File Write Error**: Returns error if file cannot be written to storage
- **Session Invalid**: Returns error if session_id is not found
- **Storage Full**: Returns error if device storage is full

## Supported Card Types

- **EM4100**: 125 kHz proximity cards
- **EM4200**: 125 kHz proximity cards  
- **HID Prox**: 125 kHz proximity cards
- **Indala**: 125 kHz proximity cards
- **ISO11785**: 134.2 kHz animal ID tags
- **Custom**: Various proprietary formats

## Safety Notes

⚠️ **Legal Warning**: Only dump RFID cards that you own or have explicit permission to access. Unauthorized access to RFID cards may violate laws and regulations.

## Related Tools

- `flipper_rfid_read` - Read RFID card without saving
- `flipper_fs_list` - List dumped RFID files
- `flipper_fs_read` - Read dumped RFID file contents
- `flipper_connect` - Establish device connection

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- RFID card present and readable
- Available storage space on device
