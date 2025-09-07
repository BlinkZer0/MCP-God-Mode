# flipper_rfid_read

Read RFID card data from Flipper Zero device.

## Description

Reads RFID card data using the Flipper Zero's RFID reader. This tool provides information about RFID cards including card type, UID, and basic card properties. Useful for RFID card analysis and identification.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |

## Usage Examples

### Read RFID Card
```javascript
flipper_rfid_read({
  session_id: "session_123"
})
```

### Read Multiple RFID Cards
```javascript
// Read first card
const card1 = flipper_rfid_read({
  session_id: "session_123"
})

// Wait for card removal and new card
// Read second card
const card2 = flipper_rfid_read({
  session_id: "session_123"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "card_type": "EM4100",
    "uid": "1234567890",
    "protocol": "EM4100",
    "frequency": 125000,
    "data": "1234567890",
    "checksum": "AB",
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **No Card Detected**: Returns error if no RFID card is present
- **Read Error**: Returns error if card cannot be read
- **Unsupported Card**: Returns error for unsupported RFID card types
- **Session Invalid**: Returns error if session_id is not found
- **Hardware Error**: Returns error if RFID reader fails

## Supported Card Types

- **EM4100**: 125 kHz proximity cards
- **EM4200**: 125 kHz proximity cards
- **HID Prox**: 125 kHz proximity cards
- **Indala**: 125 kHz proximity cards
- **ISO11785**: 134.2 kHz animal ID tags
- **Custom**: Various proprietary formats

## Safety Notes

⚠️ **Legal Warning**: Only read RFID cards that you own or have explicit permission to access. Unauthorized access to RFID cards may violate laws and regulations.

## Related Tools

- `flipper_rfid_dump` - Dump RFID card to file
- `flipper_nfc_read` - Read NFC cards
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
- RFID reader enabled on device
