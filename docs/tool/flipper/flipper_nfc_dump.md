# flipper_nfc_dump

Dump NFC card data to file on Flipper Zero device.

## Description

Reads NFC card data and saves it to a file on the Flipper Zero device's storage. This tool is useful for backing up NFC card data, analyzing card contents, and creating copies of NFC cards for authorized testing purposes.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from flipper_connect |
| `filename` | string | No | Optional filename to save dump (default: auto-generated) |

## Usage Examples

### Dump NFC Card with Auto-Generated Filename
```javascript
flipper_nfc_dump({
  session_id: "session_123"
})
```

### Dump NFC Card with Custom Filename
```javascript
flipper_nfc_dump({
  session_id: "session_123",
  filename: "/ext/nfc/access_card.nfc"
})
```

### Dump Multiple Cards
```javascript
// First card
flipper_nfc_dump({
  session_id: "session_123",
  filename: "/ext/nfc/card1.nfc"
})

// Second card  
flipper_nfc_dump({
  session_id: "session_123",
  filename: "/ext/nfc/card2.nfc"
})
```

## Response Format

```json
{
  "success": true,
  "data": {
    "filename": "/ext/nfc/access_card.nfc",
    "card_type": "Mifare Classic 1K",
    "uid": "04:12:34:56:78",
    "size": 1024,
    "blocks": 16,
    "sectors": 4,
    "dump_size": 1024,
    "timestamp": "2025-01-07T16:33:00Z"
  }
}
```

## Error Handling

- **No Card Detected**: Returns error if no NFC card is present
- **Read Error**: Returns error if card cannot be read
- **File Write Error**: Returns error if file cannot be written to storage
- **Session Invalid**: Returns error if session_id is not found
- **Storage Full**: Returns error if device storage is full

## Supported Card Types

- **Mifare Classic**: 1K, 4K variants
- **Mifare Ultralight**: C, EV1 variants
- **NTAG**: 213, 215, 216 variants
- **ISO14443 Type A**: Various manufacturers
- **ISO14443 Type B**: Various manufacturers

## Safety Notes

⚠️ **Legal Warning**: Only dump NFC cards that you own or have explicit permission to access. Unauthorized access to NFC cards may violate laws and regulations.

## Related Tools

- `flipper_nfc_read` - Read NFC card without saving
- `flipper_fs_list` - List dumped NFC files
- `flipper_fs_read` - Read dumped NFC file contents
- `flipper_connect` - Establish device connection

## Platform Support

- ✅ Windows (USB CDC)
- ✅ macOS (USB CDC)
- ✅ Linux (USB CDC)
- ✅ All platforms (BLE GATT)

## Requirements

- Flipper Zero device connected
- Active session established
- NFC card present and readable
- Available storage space on device
