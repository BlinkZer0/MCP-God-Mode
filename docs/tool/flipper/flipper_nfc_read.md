# Flipper NFC Read

## Overview

Reads and analyzes NFC (Near Field Communication) cards using the Flipper Zero device. This tool can detect, read, and parse various NFC card types including ISO14443A, ISO14443B, and other NFC protocols.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | Yes | Session ID from `flipper_connect` |

## Usage Examples

### Basic NFC Reading
```javascript
// Read NFC card
const nfcData = await flipper_nfc_read({
  session_id: "session_1234567890"
});
```

### Complete NFC Workflow
```javascript
// Connect and read NFC
const session = await flipper_connect({
  device_id: "usb:/dev/tty.usbmodem123"
});

const nfcData = await flipper_nfc_read({
  session_id: session.data.sessionId
});

if (nfcData.success) {
  console.log(`Card Type: ${nfcData.data.cardType}`);
  console.log(`UID: ${nfcData.data.uid}`);
}
```

## Response Format

```json
{
  "success": true,
  "data": {
    "cardType": "ISO14443A",
    "uid": "04:12:34:56:78",
    "atqa": "00:04",
    "sak": "08",
    "protocol": "Mifare Classic",
    "size": "1K",
    "blocks": [
      {
        "block": 0,
        "data": "04:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD",
        "access": "readable"
      },
      {
        "block": 1,
        "data": "FF:FF:FF:FF:FF:FF:FF:07:80:69:FF:FF:FF:FF:FF:FF",
        "access": "readable"
      }
    ],
    "sectors": [
      {
        "sector": 0,
        "blocks": [0, 1, 2, 3],
        "keyA": "FF:FF:FF:FF:FF:FF",
        "keyB": "FF:FF:FF:FF:FF:FF",
        "access": "readable"
      }
    ],
    "metadata": {
      "manufacturer": "NXP",
      "model": "Mifare Classic 1K",
      "readTime": "2024-01-15T10:30:00Z",
      "readDuration": 1.5
    }
  }
}
```

## NFC Card Types

### ISO14443A Cards
- **Mifare Classic**: 1K, 4K variants
- **Mifare Ultralight**: C, EV1 variants
- **NTAG**: 213, 215, 216 variants
- **Topaz**: 512, 1024 variants

### ISO14443B Cards
- **Calypso**: Various sizes
- **Desfire**: EV1, EV2 variants
- **Other**: Custom implementations

### Other Protocols
- **ISO15693**: Long range NFC
- **FeliCa**: Japanese standard
- **Custom**: Proprietary implementations

## Card Information Fields

### Basic Information
- **Card Type**: NFC protocol type (ISO14443A, ISO14443B, etc.)
- **UID**: Unique identifier of the card
- **ATQA**: Answer to Request Type A
- **SAK**: Select Acknowledge
- **Protocol**: Specific card protocol (Mifare Classic, etc.)
- **Size**: Card memory size (1K, 4K, etc.)

### Block Data
- **Blocks**: Individual memory blocks with data
- **Block Number**: Block index (0-based)
- **Data**: Hexadecimal data in the block
- **Access**: Access permissions (readable, writable, protected)

### Sector Information
- **Sectors**: Logical groupings of blocks
- **Sector Number**: Sector index
- **Blocks**: Blocks contained in the sector
- **Keys**: Access keys (Key A, Key B)
- **Access**: Sector access permissions

### Metadata
- **Manufacturer**: Card manufacturer (NXP, etc.)
- **Model**: Specific card model
- **Read Time**: Timestamp of the read operation
- **Read Duration**: Time taken to read the card

## Use Cases

### Access Control Analysis
```javascript
// Analyze access control card
const nfcData = await flipper_nfc_read({ session_id: sessionId });

if (nfcData.data.protocol === "Mifare Classic") {
  console.log("Access control card detected");
  console.log(`UID: ${nfcData.data.uid}`);
  console.log(`Size: ${nfcData.data.size}`);
}
```

### Card Cloning Preparation
```javascript
// Read card for cloning
const nfcData = await flipper_nfc_read({ session_id: sessionId });

if (nfcData.success) {
  // Save card data for later use
  const cardData = {
    uid: nfcData.data.uid,
    blocks: nfcData.data.blocks,
    sectors: nfcData.data.sectors
  };
  
  // Use with flipper_nfc_dump for complete dump
}
```

### Security Assessment
```javascript
// Assess card security
const nfcData = await flipper_nfc_read({ session_id: sessionId });

const securityLevel = nfcData.data.sectors.every(sector => 
  sector.keyA === "FF:FF:FF:FF:FF:FF"
) ? "Low" : "High";

console.log(`Card Security Level: ${securityLevel}`);
```

## Error Handling

### Common Errors
- **No Card Detected**: No NFC card is present near the device
- **Card Not Supported**: Card type is not supported
- **Read Error**: Failed to read card data
- **Authentication Failed**: Cannot authenticate with the card
- **Timeout**: Card read operation timed out

### Troubleshooting
1. **Card Position**: Ensure card is properly positioned near NFC antenna
2. **Card Type**: Verify card type is supported
3. **Distance**: Keep card within 2-3cm of the device
4. **Interference**: Remove metal objects that might interfere
5. **Card Condition**: Check if card is damaged or corrupted

## Physical Requirements

### Card Positioning
- **Distance**: 2-3cm maximum distance from NFC antenna
- **Orientation**: Card should be parallel to device surface
- **Stability**: Hold card steady during read operation
- **Duration**: Keep card in position for 1-3 seconds

### Environmental Factors
- **Interference**: Avoid metal objects and electronic devices
- **Temperature**: Normal operating temperature range
- **Humidity**: Standard indoor humidity levels
- **Lighting**: No special lighting requirements

## Security Considerations

### Data Sensitivity
- **UID Exposure**: Card UIDs are unique identifiers
- **Access Keys**: Keys may be sensitive for security cards
- **Block Data**: Data may contain sensitive information
- **Logging**: Card data is logged for audit purposes

### Legal Compliance
- **Authorization**: Only read cards you own or have permission to read
- **Privacy**: Respect privacy of card owners
- **Regulations**: Comply with local regulations regarding NFC reading
- **Ethical Use**: Use for legitimate security testing purposes only

## Performance Notes

### Read Speed
- **Typical Duration**: 1-5 seconds depending on card type
- **Block Count**: More blocks take longer to read
- **Authentication**: Some cards require authentication which adds time
- **Error Recovery**: Failed reads may require retry attempts

### Success Rate
- **Position Dependent**: Success rate depends on proper card positioning
- **Card Type**: Some card types have higher success rates
- **Device Condition**: Device condition affects read reliability
- **Environmental**: Environmental factors can impact success

## Related Tools

- `flipper_nfc_dump` - Dump complete NFC card data to file
- `flipper_connect` - Establish device connection
- `flipper_info` - Get device information
- `flipper_fs_write` - Save card data to device storage
